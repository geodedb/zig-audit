//! Verifies one audit-record span lands in an in-memory recorder when
//! `-Dwith_otel=true`. Skips under the disabled build.
//!
//! NOTE: deviation from template — we exercise the seam directly via
//! the in-memory recorder rather than driving a real `AuditLogger`.
//! The logger path requires a temp file/syslog sink + a config; the
//! seam's behaviour is identical: `startAuditRecordSpan` ->
//! `endAuditRecordSpan` enters and leaves one tracer span carrying the
//! `event.kind` and `audit.durable` attributes.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (with_otel)`
//! and stub the alias to an empty struct when the flag is off — that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const audit = @import("audit");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one audit-record span recorded when otel enabled" {
    if (!audit.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "audit-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "audit-test" });
    audit.observability.global.tracer = &tracer;
    defer audit.observability.global.tracer = null;

    const span = audit.observability.startAuditRecordSpan("user.login");
    audit.observability.endAuditRecordSpan(span, true, true);

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    // Verify span name shape: "audit.{event_kind}".
    const recorded = recorder.spans.items[0];
    try std.testing.expectEqualStrings("audit.user.login", recorded.name);

    // Verify both attributes landed on the span. The in-memory
    // recorder stores attributes as `[]KV` (string-stringified
    // key/value pairs) — see otel/src/exporters/in_memory.zig.
    var found_kind: ?[]const u8 = null;
    var found_durable: ?[]const u8 = null;
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "event.kind")) {
            found_kind = kv.value;
        } else if (std.mem.eql(u8, kv.key, "audit.durable")) {
            found_durable = kv.value;
        }
    }
    const kind_value = found_kind orelse return error.MissingEventKindAttribute;
    try std.testing.expectEqualStrings("user.login", kind_value);
    const durable_value = found_durable orelse return error.MissingAuditDurableAttribute;
    try std.testing.expectEqualStrings("true", durable_value);
}
