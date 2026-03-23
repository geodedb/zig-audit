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

pub const AuditLogger = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    clock: time.Clock,
    id_gen: time.IdGen,
    syslog_sender: ?*syslog.SyslogSender,
    file_sink: ?*file_sink.FileSink,

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
        self.config.deinit();
        self.allocator.destroy(self);
    }

    pub fn audit(self: *AuditLogger, ev: *const events.AuditEvent) !void {
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

        // If filtering resulted in dropping the event, log error and return
        if (event.metadata != null and filtered_metadata == null) {
            if (self.file_sink) |sink| {
                try sink.writeError("Event dropped due to unredactable sensitive content");
            }
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
            var truncation_obj = std.json.ObjectMap.init(self.allocator);
            try truncation_obj.put("_truncated", std.json.Value{ .bool = true });
            try truncation_obj.put("_original_size", std.json.Value{ .integer = @intCast(estimated_size) });
            event.metadata = std.json.Value{ .object = truncation_obj };
        }

        // Send to sinks
        if (self.syslog_sender) |sender| {
            try sender.send(&event);
        }

        if (self.file_sink) |sink| {
            try sink.write(&event, event.metadata);
        }
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

pub fn buildAuditLogger(allocator: std.mem.Allocator, cfg: *const config.Config) !*AuditLogger {
    var sys_clock = time.SystemClock{};
    var sys_id_gen = time.SystemIdGen.init();

    return AuditLogger.init(allocator, cfg.*, sys_clock.clock(), sys_id_gen.idGen());
}

test "estimateEventSize: small event stays under 8192" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID, time.TEST_REQUEST_ID);

    const logger_inst = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger_inst.deinit();

    // Build metadata with a large value (>8 KiB)
    var metadata_obj = std.json.ObjectMap.init(allocator);
    const big_value = try allocator.alloc(u8, 9000);
    defer allocator.free(big_value);
    @memset(big_value, 'x');
    try metadata_obj.put("big_field", std.json.Value{ .string = big_value });
    defer metadata_obj.deinit();
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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
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
