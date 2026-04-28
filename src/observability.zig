//! observability.zig — single-file otel seam for audit.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to the appropriate
//! `otel.api.trace` / `otel.instrumentation.http` helper.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller — telemetry must never break audit
//! recording. Spans here COMPLEMENT the persisted audit log; they do
//! not replace it.
//!
//! PII INVARIANT: span attributes carry only `event.kind` (a string
//! identifier composed of `category` + `action`, both bounded above by
//! `MAX_FIELD_LEN = 1024`) and a `audit.durable` boolean indicating
//! whether the record reached durable storage. The audit event PAYLOAD
//! (actor_id, subject_id, source_ip, metadata, …) is NEVER copied into
//! span attributes — those fields can carry usernames, IP addresses,
//! and structured metadata that frequently include PII.
//!
//! NOTE: deviation from template — audit operations don't fit the HTTP
//! `instrumentation.http.startClientSpan` shape (HTTP method/url is
//! lossy for an audit-record write). We expose the generic
//! `startClientSpan` / `startServerSpan` helpers for symmetry with
//! grpc-zig (and to keep the seam template-compatible), AND a
//! domain-specific `startAuditRecordSpan(event_kind)` /
//! `endAuditRecordSpan(span, ok, durable)` pair that constructs a span
//! via `otel.api.trace.Tracer.startSpan` directly with an audit-shaped
//! span name (`"audit.{event_kind}"`) and the `event.kind` semantic
//! convention.

const std = @import("std");
const build_options = @import("build_options");

pub const enabled: bool = build_options.with_otel;

const otel = if (enabled) @import("otel") else struct {};

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// Helper: reads either a `[]const u8` field OR a function-typed field
/// returning `[]const u8`, so the seam accepts both shapes — the closure
/// shape the recipe template ships AND the plain-string-field shape
/// used at hot-path call sites.
inline fn accessOr(req: anytype, comptime field: []const u8) []const u8 {
    const T = @TypeOf(@field(req, field));
    return switch (@typeInfo(T)) {
        .pointer => @field(req, field),
        .@"fn" => @field(req, field)(),
        else => @compileError("observability: unsupported field type for " ++ field),
    };
}

/// Start a span for a generic outbound operation. Kept for template
/// symmetry; audit hot paths use `startAuditRecordSpan` instead.
pub fn startClientSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startClientSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endClientSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endClientSpan(span, .{ .status_code = status });
}

/// Start a span for a generic inbound operation. Kept for template
/// symmetry; audit has no authoritative-server entry point.
pub fn startServerSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startServerSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .route = accessOr(req, "route"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endServerSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endServerSpan(span, status);
}

/// Start a span for an audit-record write.
///
/// Span shape:
///   - name: `"audit.{event_kind}"` (e.g. `"audit.user.login"`,
///     `"audit.auth.password.change"`). Callers typically build
///     `event_kind` from the audit event's `category` + `action`
///     (e.g. `"auth.login"`); the helper does NOT compose those — the
///     caller owns the composition because audit events sometimes
///     carry their kind on a single field.
///   - kind: `.internal` (audit logging is a self-contained library
///     write, not a remote-server call; `.internal` is the
///     OpenTelemetry SpanKind reserved for in-process work that
///     doesn't cross a network boundary).
///   - attributes:
///       * `event.kind = event_kind`
///
/// `event_kind` MUST be a slice whose lifetime outlives the span. The
/// SDK dupes the span name into the span arena, but the `event.kind`
/// attribute is stored by reference at the stringified-value layer;
/// using a stable string keeps the recorder safe from dangling slices.
///
/// PII INVARIANT: callers MUST NOT pass actor_id, subject_id,
/// source_ip, or any metadata field as `event_kind`. The kind is the
/// taxonomy label (`category.action`), not the data.
pub fn startAuditRecordSpan(event_kind: []const u8) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    // Compose the span name on the stack; the SDK dupes the name into
    // the span arena, so a pointer to a stack buffer is safe here.
    // Bound: audit event `category` and `action` are each capped at
    // `events.AuditEvent.MAX_FIELD_LEN = 1024`, so a `category.action`
    // composition fits in 2049 bytes. We size the buffer for
    // `"audit." + 2049` plus headroom.
    var name_buf: [2080]u8 = undefined;
    const span_name = std.fmt.bufPrint(
        name_buf[0..],
        "audit.{s}",
        .{event_kind},
    ) catch "audit.record";
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = .internal }) catch return Span{};
    // Best-effort attribute attachment. Failures (OOM in the attribute
    // set) cannot block audit recording — telemetry is non-fatal.
    span.setStringAttribute("event.kind", event_kind) catch {};
    return span;
}

/// Close an audit-record span, recording success/failure and durability.
///
/// On `ok = true` we set status `.ok`; on `ok = false` we set status
/// `.error_` (no error message — the audit pipeline drops PII-bearing
/// error context on purpose; operators inspect the persisted audit log
/// and the host's structured logs for failure detail). The `durable`
/// flag is recorded as the boolean attribute `audit.durable` to
/// distinguish records that reached the file/syslog sink from those
/// that were buffered or dropped.
///
/// Callers typically pair this with `defer span.end(null)` at the call
/// site so the span is always ended regardless of which path is taken.
/// `setStatus` + `end` are idempotent for status reporting (only the
/// first status write wins; the deferred `end(null)` is a redundant
/// no-op).
pub fn endAuditRecordSpan(span: Span, ok: bool, durable: bool) void {
    if (!enabled) return;
    if (ok) {
        span.setStatus(.ok, "");
    } else {
        // `StatusCode` uses `@"error"` (escaped keyword) for the
        // failure variant — see otel/src/api/trace.zig:35.
        span.setStatus(.@"error", "");
    }
    // The trace API exposes only `setStringAttribute`/`setIntAttribute`
    // helper wrappers; bool attributes go through the lower-level
    // `setAttribute` with an explicit `.bool` `attrs.Value` variant —
    // see otel/src/internal/attributes.zig:15-22 for the union shape.
    span.setAttribute("audit.durable", .{ .bool = durable }) catch {};
    span.end(null);
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer
/// drops the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};
