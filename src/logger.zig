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
        var event = try ev.clone(self.allocator);
        defer event.freeCloned(self.allocator);

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

        // Apply filtering and redaction
        const filtered_metadata = if (event.metadata) |metadata|
            try filters.filterAndRedactMetadata(self.allocator, metadata, &self.config.filters)
        else
            null;

        defer if (filtered_metadata) |fm| {
            json_util.freeJsonValue(self.allocator, fm);
        };

        // If filtering resulted in dropping the event, log error and return.
        // The function honoured the redaction policy successfully
        // (`span_ok = true`), but the audit record never reached a
        // sink (`span_durable = false`). Operators can spot dropped
        // records by filtering for `audit.durable=false`.
        if (event.metadata != null and filtered_metadata == null) {
            if (self.file_sink) |sink| {
                try sink.writeError("Event dropped due to unredactable sensitive content");
            }
            span_ok = true;
            span_durable = false;
            return;
        }

        // Update event with filtered metadata
        if (event.metadata) |original_metadata| {
            json_util.freeJsonValue(self.allocator, original_metadata);
        }
        if (filtered_metadata) |fm| {
            event.metadata = try json_util.cloneJsonValue(self.allocator, fm);
        } else {
            event.metadata = null;
        }

        // Check message size limit (8 KiB after redaction).
        // Estimate size without full serialization: sum known field lengths
        // with conservative JSON overhead, and only serialize metadata if present.
        const estimated_size = try self.estimateEventSize(&event);

        if (estimated_size > 8192) {
            if (event.metadata) |metadata| {
                json_util.freeJsonValue(self.allocator, metadata);
            }
            var truncation_obj: std.json.ObjectMap = .empty;
            try truncation_obj.put(self.allocator, "_truncated", std.json.Value{ .bool = true });
            try truncation_obj.put(self.allocator, "_original_size", std.json.Value{ .integer = @intCast(estimated_size) });
            event.metadata = std.json.Value{ .object = truncation_obj };
        }

        // Fan out to sinks concurrently — both sinks use background workers
        // consuming from BoundedChannels, so these calls just format and enqueue.
        // Attempt both sinks independently so one failure doesn't block the other.
        var syslog_err: ?anyerror = null;
        if (self.syslog_sender) |sender| {
            sender.send(&event) catch |err| {
                syslog_err = err;
            };
        }

        var file_err: ?anyerror = null;
        if (self.file_sink) |sink| {
            sink.write(&event, event.metadata) catch |err| {
                file_err = err;
            };
        }

        // Propagate errors: prefer syslog error since it likely indicates OOM
        if (syslog_err) |err| return err;
        if (file_err) |err| return err;

        // Success path: both sinks accepted the record (or were
        // disabled), so the record is considered durable. The
        // deferred `endAuditRecordSpan` reads these values when the
        // function returns normally.
        span_ok = true;
        span_durable = true;
    }

    /// Estimate the serialized JSON size of an audit event without building a
    /// throwaway ObjectMap.  Fixed fields are accounted for with a conservative
    /// overhead constant; only metadata (the unbounded part) is serialized.
    fn estimateEventSize(self: *AuditLogger, event: *const events.AuditEvent) !usize {
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

        // Metadata is the variable/unbounded part -- serialize only this
        if (event.metadata) |metadata| {
            const meta_json = std.json.Stringify.valueAlloc(self.allocator, metadata, .{}) catch |err| switch (err) {
                error.OutOfMemory => return 8192 + 1, // trigger truncation on OOM
            };
            defer self.allocator.free(meta_json);
            size += meta_json.len + 16; // +16 for "metadata": wrapper
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
    const sys_clock = try allocator.create(time.SystemClock);
    errdefer allocator.destroy(sys_clock);
    sys_clock.* = time.SystemClock{};

    const sys_id_gen = try allocator.create(time.SystemIdGen);
    errdefer allocator.destroy(sys_id_gen);
    sys_id_gen.* = time.SystemIdGen.init();

    const logger = try AuditLogger.init(allocator, cfg, sys_clock.clock(), sys_id_gen.idGen());
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

test "estimateEventSize: small event stays under 8192" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID, time.TEST_REQUEST_ID);

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

test "estimateEventSize: large metadata exceeds 8192" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID, time.TEST_REQUEST_ID);

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

test "audit logger basic functionality" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    // Logger takes ownership of config and frees it in deinit

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID, time.TEST_REQUEST_ID);

    const logger = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger.deinit();

    const event = events.AuditEvent{
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

    try logger.audit(&event);
}
