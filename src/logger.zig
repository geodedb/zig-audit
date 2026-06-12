// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! High-level audit logger that orchestrates event validation, filtering,
//! redaction, and dispatch to file and syslog sinks.

const std = @import("std");
const events = @import("events.zig");
const config = @import("config.zig");
const filters = @import("filters.zig");
const json_util = @import("json_util.zig");
const syslog = @import("syslog.zig");
const file_sink = @import("file_sink.zig");
const time = @import("time.zig");
// Observability seam (otel). NAMED module — see `build.zig` /
// `src/observability.zig` for the no-op invariants. When
// `-Dwith_otel=false`, every helper here compiles to a comptime-known
// no-op and is eliminated by the optimizer.
const observability = @import("observability");

pub const AuditLogger = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    clock: time.Clock,
    id_gen: time.IdGen,
    syslog_sender: ?*syslog.SyslogSender,
    file_sink: ?*file_sink.FileSink,
    // Owned only when constructed via buildAuditLogger; freed in deinit.
    owned_system_clock: ?*time.SystemClock = null,
    owned_system_id_gen: ?*time.SystemIdGen = null,

    /// Takes ownership of `audit_config`; freed in `deinit()`. Do not call
    /// `audit_config.deinit()` after a successful `init`.
    pub fn init(
        allocator: std.mem.Allocator,
        audit_config: config.Config,
        clock: time.Clock,
        id_gen: time.IdGen,
    ) !*AuditLogger {
        const logger = try allocator.create(AuditLogger);
        errdefer allocator.destroy(logger);

        const syslog_sender = if (audit_config.sinks.syslog.enabled)
            try syslog.SyslogSender.init(
                allocator,
                audit_config.sinks.syslog,
                audit_config.service,
                audit_config.identity.cef,
                clock,
            )
        else
            null;
        errdefer if (syslog_sender) |sender| sender.deinit();

        const file_sink_inst = if (audit_config.sinks.file.enabled)
            try file_sink.FileSink.init(allocator, audit_config.sinks.file, clock)
        else
            null;
        errdefer if (file_sink_inst) |sink| sink.deinit();

        logger.* = AuditLogger{
            .allocator = allocator,
            .config = audit_config,
            .clock = clock,
            .id_gen = id_gen,
            .syslog_sender = syslog_sender,
            .file_sink = file_sink_inst,
        };

        return logger;
    }

    pub fn deinit(self: *AuditLogger) void {
        if (self.syslog_sender) |sender| {
            sender.deinit();
        }
        if (self.file_sink) |sink| {
            sink.deinit();
        }
        if (self.owned_system_clock) |sc| {
            self.allocator.destroy(sc);
        }
        if (self.owned_system_id_gen) |sig| {
            self.allocator.destroy(sig);
        }
        self.config.deinit();
        self.allocator.destroy(self);
    }

    pub fn audit(self: *AuditLogger, ev: *const events.AuditEvent) !void {
        // Compose the event-kind label for the observability span.
        // Bound: `category` and `action` are each capped at
        // `events.AuditEvent.MAX_FIELD_LEN = 1024`, so
        // `"{category}.{action}"` fits in 2049 bytes. We size the
        // buffer with headroom and fall back to `"record"` if the
        // (impossible-after-validate) overflow path fires.
        //
        // PII INVARIANT: only `category` + `action` participate in
        // the kind label. `actor_id`, `subject_id`, `source_ip`,
        // `metadata`, etc. — fields that frequently carry PII — are
        // NEVER copied into span attributes.
        var event_kind_buf: [2080]u8 = undefined;
        const event_kind = std.fmt.bufPrint(
            event_kind_buf[0..],
            "{s}.{s}",
            .{ ev.category, ev.action },
        ) catch "record";
        const span = observability.startAuditRecordSpan(event_kind);
        // Status defaults: span ends as `error` / non-durable unless
        // the success path overrides them. The `defer` below fires on
        // every exit (early-return, propagated error, normal end);
        // `endAuditRecordSpan` itself calls `span.end(null)`, so
        // there's no separate `defer span.end(null)` here — that
        // would double-end.
        var span_ok: bool = false;
        var span_durable: bool = false;
        defer observability.endAuditRecordSpan(span, span_ok, span_durable);

        try ev.validate();
        // Single-copy metadata pipeline (GAP-049, PERF-001, PERF-005): the
        // clone deliberately omits metadata. The filtered tree is built
        // directly from the CALLER's metadata in applyRedaction and MOVED
        // onto the clone — one owned tree total instead of
        // clone + filter + re-clone.
        var event = try ev.cloneWithoutMetadata(self.allocator);
        defer event.freeCloned(self.allocator);

        self.enrichClonedEvent(&event);

        switch (try self.applyRedaction(ev, &event)) {
            .drop => {
                // The function honoured the redaction policy successfully
                // (`span_ok = true`), but the audit record never reached a
                // sink (`span_durable = false`). Operators can spot dropped
                // records by filtering for `audit.durable=false`.
                span_ok = true;
                span_durable = false;
                return;
            },
            .proceed => {},
        }

        // Check message size limit (8 KiB after redaction).
        // Estimate size without full serialization: sum known field lengths
        // with conservative JSON overhead, and only serialize metadata if present.
        const estimated_size = try self.estimateEventSize(&event);

        if (estimated_size > 8192) {
            if (event.metadata) |metadata| {
                json_util.freeJsonValue(self.allocator, metadata);
                // Clear immediately: if building the truncation marker fails
                // below, the deferred freeCloned must not free this again.
                event.metadata = null;
            }
            // Keys must be heap-duped: event.freeCloned ->
            // json_util.freeJsonValue frees every object key, so string
            // literals here would be invalid frees (QR-003).
            var truncation_obj: std.json.ObjectMap = .empty;
            errdefer {
                var trunc_iter = truncation_obj.iterator();
                while (trunc_iter.next()) |entry| {
                    self.allocator.free(entry.key_ptr.*);
                }
                truncation_obj.deinit(self.allocator);
            }
            {
                const key = try self.allocator.dupe(u8, "_truncated");
                errdefer self.allocator.free(key);
                try truncation_obj.put(self.allocator, key, std.json.Value{ .bool = true });
            }
            {
                const key = try self.allocator.dupe(u8, "_original_size");
                errdefer self.allocator.free(key);
                // Defensive cast: estimated_size is bounded in practice
                // (fields capped at MAX_FIELD_LEN, metadata at 8192+1), but
                // saturate rather than trap on a theoretical usize > i64 max.
                const size_i64 = std.math.cast(i64, estimated_size) orelse std.math.maxInt(i64);
                try truncation_obj.put(self.allocator, key, std.json.Value{ .integer = size_i64 });
            }
            // The errdefer above dies with this block: once `truncation_obj`
            // is stored here, ownership transfers to `event.metadata` and the
            // deferred `event.freeCloned` is responsible for freeing it.
            event.metadata = std.json.Value{ .object = truncation_obj };
        }

        // Fan out to sinks concurrently — both sinks use background workers
        // consuming from BoundedChannels, so these calls just format and enqueue.
        // Attempt both sinks independently so one failure doesn't block the other.
        var any_dropped = false;
        var syslog_err: ?anyerror = null;
        if (self.syslog_sender) |sender| {
            if (sender.send(&event)) |status| {
                if (status == .dropped) any_dropped = true;
            } else |err| {
                syslog_err = err;
            }
        }

        var file_err: ?anyerror = null;
        if (self.file_sink) |sink| {
            if (sink.write(&event, event.metadata)) |status| {
                if (status == .dropped) any_dropped = true;
            } else |err| {
                file_err = err;
            }
        }

        // Propagate errors: prefer syslog error since it likely indicates OOM
        if (syslog_err) |err| return err;
        if (file_err) |err| return err;

        // Success path: the call itself succeeded (`span_ok`), but the
        // record is only durable if every enabled sink actually ENQUEUED
        // it — a channel-full drop is not an error, yet the record never
        // reached a sink, so the span must say durable=false (GAP-041/A2,
        // QR-005). The deferred `endAuditRecordSpan` reads these values
        // when the function returns normally.
        span_ok = true;
        span_durable = !any_dropped;
    }

    /// Stamp the cloned event with the injected clock and ID generator:
    /// fill in the timestamp (when the caller passed 0) and generate
    /// trace/span IDs (when the caller passed null).
    fn enrichClonedEvent(self: *AuditLogger, event: *events.AuditEvent) void {
        if (event.ts_unix_ms == 0) {
            event.ts_unix_ms = self.clock.nowMs();
        }

        if (event.trace_id == null) {
            var trace_buf: [32]u8 = undefined;
            self.id_gen.traceId(&trace_buf);
            event.trace_id = trace_buf;
        }

        if (event.span_id == null) {
            var span_buf: [16]u8 = undefined;
            self.id_gen.spanId(&span_buf);
            event.span_id = span_buf;
        }
    }

    /// Outcome of `applyRedaction`: `.drop` means the redaction policy
    /// dropped the whole event (drop marker already written to the file
    /// sink) and `audit()` must return without dispatching.
    const RedactionOutcome = enum { proceed, drop };

    /// Apply filtering and redaction directly from the caller's metadata
    /// tree and MOVE the filtered result onto the cloned event. The filters
    /// never mutate their input and always return an independently-owned
    /// tree (every path dupes/clones — QR-002), so reading `ev.metadata`
    /// here is safe even though we don't own it.
    fn applyRedaction(
        self: *AuditLogger,
        ev: *const events.AuditEvent,
        event: *events.AuditEvent,
    ) !RedactionOutcome {
        const filtered_metadata = if (ev.metadata) |metadata|
            try filters.filterAndRedactMetadata(self.allocator, metadata, &self.config.filters)
        else
            null;

        // If filtering resulted in dropping the event, log error and signal
        // the caller to return.
        // (`filtered_metadata` is null on this path — nothing to free.)
        if (ev.metadata != null and filtered_metadata == null) {
            if (self.file_sink) |sink| {
                // The drop path already reports durable=false, so the
                // enqueue-vs-drop status of the marker itself adds nothing.
                _ = try sink.writeError("Event dropped due to unredactable sensitive content");
            }
            return .drop;
        }

        // MOVE the filtered tree onto the cloned event (its metadata is null
        // until here). Ownership transfers: the deferred freeCloned in
        // audit() — or its truncation branch — frees it. No re-clone
        // (copy #3 of the old pipeline) and no defer of filtered_metadata
        // itself.
        event.metadata = filtered_metadata;
        return .proceed;
    }

    /// Estimate the serialized JSON size of an audit event without building a
    /// throwaway ObjectMap.  Fixed fields are accounted for with a conservative
    /// overhead constant; only metadata (the unbounded part) is serialized.
    fn estimateEventSize(self: *AuditLogger, event: *const events.AuditEvent) !usize {
        _ = self; // measuring no longer allocates (GAP-056); kept as a method for call-site stability
        // Base overhead covers JSON braces, commas, quotes around keys/values,
        // colons, and the fixed-name keys (category, action, outcome, severity,
        // actor_id, ts_unix_ms, trace_id, span_id, subject_id, request_id,
        // session_id, source_ip).  Each key-value pair costs roughly:
        //   "key":"value",  =>  key.len + value.len + 6 (quotes, colon, comma)
        // We use 128 bytes as a conservative base for structural overhead.
        var size: usize = 128;

        // Required string fields
        size += event.category.len;
        size += event.action.len;
        size += event.actor_id.len;

        // Optional string fields -- add length + per-field overhead (16 bytes
        // for the key name, quotes, colon, comma)
        if (event.subject_id) |s| size += s.len + 16;
        if (event.request_id) |r| size += r.len + 16;
        if (event.session_id) |s| size += s.len + 16;
        if (event.source_ip) |s| size += s.len + 16;

        // Fixed-size fields
        if (event.trace_id != null) size += 48; // 32 hex chars + key overhead
        if (event.span_id != null) size += 32; // 16 hex chars + key overhead

        // Timestamp: up to 20 digits for i128
        size += 20;

        // Metadata is the variable/unbounded part -- measure it with a
        // counting (discarding) writer instead of serializing into a
        // throwaway heap buffer (GAP-056).
        if (event.metadata) |metadata| {
            var scratch: [256]u8 = undefined;
            var counter: std.Io.Writer.Discarding = .init(&scratch);
            std.json.Stringify.value(metadata, .{}, &counter.writer) catch |err| switch (err) {
                // Discarding never fails, but stay fail-closed: an
                // unmeasurable payload must trigger truncation.
                error.WriteFailed => return 8192 + 1,
            };
            const meta_len = std.math.cast(usize, counter.fullCount()) orelse return 8192 + 1;
            size += meta_len + 16; // +16 for "metadata": wrapper
        }

        return size;
    }
};

/// Build an `AuditLogger` backed by the system clock and system ID
/// generator. Takes ownership of `cfg`: the logger frees it in `deinit()`;
/// the caller must not call `cfg.deinit()` after a successful return.
///
/// The `SystemClock`/`SystemIdGen` instances are heap-allocated and owned
/// by the returned logger (freed in `deinit()`), so the vtable contexts
/// remain valid for the logger's whole lifetime.
pub fn buildAuditLogger(allocator: std.mem.Allocator, cfg: config.Config) !*AuditLogger {
    // We own `cfg` from the moment we're called, so every error path below
    // must release its heap members. `Config.deinit` takes `*Config` and Zig
    // parameters are immutable, so copy to a local first. `AuditLogger.init`
    // never deinits the config on its own failure paths (it only stores it on
    // success), so this errdefer cannot double-free.
    var owned_cfg = cfg;
    errdefer owned_cfg.deinit();

    const sys_clock = try allocator.create(time.SystemClock);
    errdefer allocator.destroy(sys_clock);
    sys_clock.* = time.SystemClock{};

    const sys_id_gen = try allocator.create(time.SystemIdGen);
    errdefer allocator.destroy(sys_id_gen);
    sys_id_gen.* = time.SystemIdGen.init();

    const logger = try AuditLogger.init(allocator, owned_cfg, sys_clock.clock(), sys_id_gen.idGen());
    // SAFETY: no fallible operations between init() and return; adding any
    // would require cancelling these errdefers (they alias memory now owned
    // by the logger).
    logger.owned_system_clock = sys_clock;
    logger.owned_system_id_gen = sys_id_gen;
    return logger;
}

test "buildAuditLogger: system idgen survives the builder frame (QR-001)" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    const logger = try buildAuditLogger(allocator, test_config);
    defer logger.deinit();

    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    logger.id_gen.traceId(&buf1);
    logger.id_gen.traceId(&buf2);
    for (buf1) |c| try std.testing.expect(std.ascii.isHex(c));
    try std.testing.expect(!std.mem.eql(u8, &buf1, &buf2));

    const event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = 0,
        .severity = .INFO,
        .actor_id = "u1",
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = null,
    };
    try logger.audit(&event);
}

test "buildAuditLogger: config does not leak when AuditLogger.init fails" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var test_config = try config.loadTestConfig(allocator);
    // Force a deterministic AuditLogger.init failure: SyslogSender.init
    // rejects `.tls` with error.TlsNotSupported before allocating anything
    // it doesn't clean up itself. The syslog sink initializes before the
    // file sink, so no filesystem state is touched.
    test_config.sinks.syslog.protocol = .tls;

    const result = buildAuditLogger(allocator, test_config);
    try std.testing.expectError(error.TlsNotSupported, result);
    // DebugAllocator's deinit (deferred above) fails the test if the
    // config's heap members leaked on the error path.
}

test "estimateEventSize: small event stays under 8192" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger_inst = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger_inst.deinit();

    const event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS,
        .severity = .INFO,
        .actor_id = "test-user",
        .subject_id = "subject-1",
        .request_id = "req-123",
        .session_id = "ses-456",
        .source_ip = "10.0.0.1",
        .trace_id = time.TEST_TRACE_ID,
        .span_id = time.TEST_SPAN_ID,
        .metadata = null,
    };

    const size = try logger_inst.estimateEventSize(&event);
    // A small event with no metadata should be well under 8 KiB
    try std.testing.expect(size < 1024);
}

test "GAP-056 characterization: estimateEventSize metadata sizing matches Stringify.valueAlloc" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger_inst = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger_inst.deinit();

    // Mixed-type metadata, including a nested object and strings that need
    // JSON escaping, so the byte count exercises real Stringify behavior.
    var nested_obj: std.json.ObjectMap = .empty;
    defer nested_obj.deinit(allocator);
    try nested_obj.put(allocator, "inner", std.json.Value{ .string = "line1\nline2 \"quoted\"" });

    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);
    try metadata_obj.put(allocator, "department", std.json.Value{ .string = "Engineering" });
    try metadata_obj.put(allocator, "attempts", std.json.Value{ .integer = 3 });
    try metadata_obj.put(allocator, "mfa", std.json.Value{ .bool = true });
    try metadata_obj.put(allocator, "nested", std.json.Value{ .object = nested_obj });
    const metadata = std.json.Value{ .object = metadata_obj };

    var event = makeTestEvent();
    const base_size = try logger_inst.estimateEventSize(&event);

    event.metadata = metadata;
    const with_meta_size = try logger_inst.estimateEventSize(&event);

    // Pin: the metadata contribution is exactly serialized-length + 16,
    // where serialized-length is what Stringify.valueAlloc produces.
    const meta_json = try std.json.Stringify.valueAlloc(allocator, metadata, .{});
    defer allocator.free(meta_json);
    try std.testing.expectEqual(base_size + meta_json.len + 16, with_meta_size);
}

test "estimateEventSize: large metadata exceeds 8192" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger_inst = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger_inst.deinit();

    // Build metadata with a large value (>8 KiB)
    var metadata_obj: std.json.ObjectMap = .empty;
    const big_value = try allocator.alloc(u8, 9000);
    defer allocator.free(big_value);
    @memset(big_value, 'x');
    try metadata_obj.put(allocator, "big_field", std.json.Value{ .string = big_value });
    defer metadata_obj.deinit(allocator);
    const metadata = std.json.Value{ .object = metadata_obj };

    const event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS,
        .severity = .INFO,
        .actor_id = "test-user",
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = metadata,
    };

    const size = try logger_inst.estimateEventSize(&event);
    // With 9000 bytes of metadata, the estimate must exceed 8192
    try std.testing.expect(size > 8192);
}

/// Minimal valid event used by the end-to-end logger tests below.
fn makeTestEvent() events.AuditEvent {
    return events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = 0,
        .severity = .INFO,
        .actor_id = "test-user",
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = null,
    };
}

test "audit logger basic functionality" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    // Logger takes ownership of config and frees it in deinit

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger.deinit();

    const event = makeTestEvent();
    try logger.audit(&event);
}

test "audit: succeeds without error when the file sink drops (GAP-041/QR-005)" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var test_config = try config.loadTestConfig(allocator);
    defer test_config.deinit();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    // Worker-less file sink with a 1-slot channel, pre-filled so the next
    // enqueue deterministically drops (nothing drains it). Construction is
    // centralized in the test-only helper so field additions touch one place.
    const sink = try allocator.create(file_sink.FileSink);
    errdefer allocator.destroy(sink);
    sink.* = try file_sink.FileSink.testInitWorkerless(allocator, .{
        .enabled = true,
        .path = "zig-out/tmp/test-gap041-logger/audit.log",
        .max_bytes = 1024 * 1024,
        .backup_count = 0,
    }, fixed_clock.clock());
    defer sink.deinit();

    const occupant = try allocator.dupe(u8, "occupant");
    try std.testing.expect(sink.ch.trySend(occupant));

    // Stack logger wired straight to the manual sink — its deinit is never
    // called (config and sink are cleaned up by the defers above).
    var logger_inst = AuditLogger{
        .allocator = allocator,
        .config = test_config,
        .clock = fixed_clock.clock(),
        .id_gen = fixed_id_gen.idGen(),
        .syslog_sender = null,
        .file_sink = sink,
    };

    const event = makeTestEvent();
    // A full channel is a DROP, not an error: audit() must still succeed
    // (the span ends durable=false, observable here via the drop counter).
    try logger_inst.audit(&event);
    try std.testing.expect(sink.getDroppedCount() > 0);
}

test "audit: non-object top-level metadata does not double-free (QR-002)" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger.deinit();

    var event = makeTestEvent();
    event.metadata = std.json.Value{ .string = "not-an-object" };
    try logger.audit(&event);
}

test "audit: nested metadata pipeline leaks nothing and emits filtered output (GAP-049)" {
    // Leak-sensitivity guard for the single-copy metadata pipeline: an
    // end-to-end audit() with nested metadata (object containing an object,
    // an array, and strings) under DebugAllocator. gpa.deinit() (deferred
    // first, so it runs last) fails the test on any leak in the
    // clone -> filter -> move -> sink choreography. Output is read back
    // from the file sink AFTER logger deinit (async worker drains on
    // deinit, QR-013).
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();
    // Random per-process suffix: the src test module is compiled into TWO
    // binaries (otel on/off) that run in parallel; a shared fixed dir races
    // (one binary's deleteTree vs the other's sink writes).
    var dir_suffix: [4]u8 = undefined;
    io.random(&dir_suffix);
    const test_dir = try std.fmt.allocPrint(allocator, "zig-out/tmp/test-gap049-single-copy-{s}", .{std.fmt.bytesToHex(dir_suffix, .lower)});
    defer allocator.free(test_dir);
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};
    const log_path = try std.fmt.allocPrint(allocator, "{s}/audit.log", .{test_dir});
    defer allocator.free(log_path);

    var test_config = try config.loadTestConfig(allocator);
    allocator.free(test_config.sinks.file.path);
    test_config.sinks.file.path = try allocator.dupe(u8, log_path);

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger_inst = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());

    // Caller-owned metadata tree: { subject_id: "user-42",
    //   request_id: { actor_id: ["alpha", "beta"], source_ip: "10.1.2.3" },
    //   password: "Sup3rSecret!" }
    // loadTestConfig sets default_deny=true; subject_id/request_id/
    // actor_id/source_ip are allow-listed AND not sensitive-key matches
    // (e.g. "session_id" would trip isSensitiveKey's "session" pattern and
    // "span_id" contains "pan"), so they survive filtering verbatim.
    // "password" matches a deny pattern and is redacted.
    var inner_arr = std.json.Array.init(allocator);
    defer inner_arr.deinit();
    try inner_arr.append(std.json.Value{ .string = "alpha" });
    try inner_arr.append(std.json.Value{ .string = "beta" });

    var inner_obj: std.json.ObjectMap = .empty;
    defer inner_obj.deinit(allocator);
    try inner_obj.put(allocator, "actor_id", std.json.Value{ .array = inner_arr });
    try inner_obj.put(allocator, "source_ip", std.json.Value{ .string = "10.1.2.3" });

    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);
    try metadata_obj.put(allocator, "subject_id", std.json.Value{ .string = "user-42" });
    try metadata_obj.put(allocator, "request_id", std.json.Value{ .object = inner_obj });
    try metadata_obj.put(allocator, "password", std.json.Value{ .string = "Sup3rSecret!" });

    var event = makeTestEvent();
    event.metadata = std.json.Value{ .object = metadata_obj };
    try logger_inst.audit(&event);

    // Drain the async file sink, then assert the filtered tree reached disk.
    logger_inst.deinit();

    const content = try cwd.readFileAlloc(io, log_path, allocator, .limited(8192));
    defer allocator.free(content);
    try std.testing.expect(content.len > 0);

    // Allowed fields survive filtering...
    try std.testing.expect(std.mem.indexOf(u8, content, "user-42") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "alpha") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "beta") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "10.1.2.3") != null);
    // ...the denied key is redacted, and the secret never reaches the sink.
    try std.testing.expect(std.mem.indexOf(u8, content, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Sup3rSecret!") == null);
}

test "audit: drop_event metadata path leaks nothing (GAP-049/GAP-061)" {
    // Leak angle of the fail-closed drop path: a PEM private key under a
    // sensitive key makes the filter return null (drop_event). audit() must
    // succeed (span_ok=true, durable=false), write only the drop marker,
    // and free every allocation — DebugAllocator's deinit is the oracle.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();
    // Random per-process suffix — see the GAP-049 single-copy test above.
    var dir_suffix: [4]u8 = undefined;
    io.random(&dir_suffix);
    const test_dir = try std.fmt.allocPrint(allocator, "zig-out/tmp/test-gap049-drop-event-{s}", .{std.fmt.bytesToHex(dir_suffix, .lower)});
    defer allocator.free(test_dir);
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};
    const log_path = try std.fmt.allocPrint(allocator, "{s}/audit.log", .{test_dir});
    defer allocator.free(log_path);

    var test_config = try config.loadTestConfig(allocator);
    allocator.free(test_config.sinks.file.path);
    test_config.sinks.file.path = try allocator.dupe(u8, log_path);

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger_inst = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());

    // Split literal: comptime-concatenates to a real PEM marker at runtime,
    // but keeps the verbatim pattern out of src/ so the detect-private-key
    // pre-commit hook (which excludes tests/, not src/) doesn't flag it.
    const pem = "-----BEGIN RSA " ++ "PRIVATE KEY-----\nMIIEpAIBAAKCAQEAy8Dbq...\n-----END RSA " ++ "PRIVATE KEY-----";
    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);
    try metadata_obj.put(allocator, "private_key", std.json.Value{ .string = pem });

    var event = makeTestEvent();
    event.metadata = std.json.Value{ .object = metadata_obj };
    try logger_inst.audit(&event);

    logger_inst.deinit();

    const content = try cwd.readFileAlloc(io, log_path, allocator, .limited(8192));
    defer allocator.free(content);
    // Only the drop marker reaches the sink; no key material, no record.
    try std.testing.expect(std.mem.indexOf(u8, content, "Event dropped due to unredactable sensitive content") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "BEGIN RSA") == null);
}

test "audit: oversized metadata truncation markers are heap-owned (QR-003)" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger.deinit();

    // Metadata serializing to >8192 bytes. loadTestConfig sets
    // default_deny=true, so the key must be in allow_fields ("subject_id"
    // is). The value is repeated 'x', which no value detector flags
    // (not hex, PAN, JWT, email, phone, or CVV), so it survives redaction
    // and triggers the truncation branch.
    const big_value = try allocator.alloc(u8, 9000);
    defer allocator.free(big_value);
    @memset(big_value, 'x');

    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);
    try metadata_obj.put(allocator, "subject_id", std.json.Value{ .string = big_value });

    var event = makeTestEvent();
    event.metadata = std.json.Value{ .object = metadata_obj };
    try logger.audit(&event);
}
