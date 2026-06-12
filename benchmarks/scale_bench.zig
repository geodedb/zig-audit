// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Incremental scale benchmark for the audit library.
//!
//! Runs the same battery of operations at progressively larger event volumes
//! and emits structured JSON to stdout for tracking over time.
//! A human-readable summary table is printed to stderr via std.debug.print.
//!
//! Run via: zig build scale-bench
//! Save:   zig build scale-bench 2>/dev/null > results.json

const std = @import("std");
const builtin = @import("builtin");
const audit = @import("audit");

const AuditEvent = audit.AuditEvent;
const AuditLogger = audit.AuditLogger;
const BoundedChannel = audit.BoundedChannel;
const config = audit.config;
const events = audit.events;
const filters = audit.filters;
const cef = audit.cef;
const time = audit.time;
const json_util = audit.json_util;

const print = std.debug.print;

inline fn nowNs() u64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    const ts = std.Io.Clock.Timestamp.now(io_inst, .awake);
    return @intCast(ts.raw.toNanoseconds());
}

inline fn timeSec() i64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io_inst, .real).raw.toSeconds();
}

// ---------------------------------------------------------------------------
// Scale tier definitions — event counts at each level
// ---------------------------------------------------------------------------

const Tier = struct {
    name: []const u8,
    event_count: usize,
    metadata_fields: usize, // number of metadata fields per event
};

const tiers = [_]Tier{
    .{ .name = "100", .event_count = 100, .metadata_fields = 5 },
    .{ .name = "1K", .event_count = 1_000, .metadata_fields = 5 },
    .{ .name = "10K", .event_count = 10_000, .metadata_fields = 5 },
    .{ .name = "50K", .event_count = 50_000, .metadata_fields = 5 },
    .{ .name = "100K", .event_count = 100_000, .metadata_fields = 5 },
    .{ .name = "500K", .event_count = 500_000, .metadata_fields = 5 },
};

// ---------------------------------------------------------------------------
// Per-tier results
// ---------------------------------------------------------------------------

const TierResult = struct {
    name: []const u8,
    event_count: u64,
    // Throughput metrics (higher is better)
    logger_ops_sec: f64,
    channel_ops_sec: f64,
    // Multi-producer channel throughput (PR-013): P producers splitting the
    // tier's event count into one draining consumer.
    channel_mp1_ops_sec: f64 = 0,
    channel_mp2_ops_sec: f64 = 0,
    channel_mp4_ops_sec: f64 = 0,
    channel_mp8_ops_sec: f64 = 0,
    // Latency metrics (lower is better)
    validate_ns: f64,
    clone_ns: f64,
    cef_format_ns: f64,
    filter_redact_ns: f64,
    file_sink_ns: f64,
    // Aggregate
    mixed_ops_sec: f64,
    skipped: bool = false,
    skip_reason: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn makeEvent() AuditEvent {
    return AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = 1735689600000,
        .severity = .INFO,
        .actor_id = "user-12345",
        .subject_id = "resource-67890",
        .request_id = "req-abcdef-123456",
        .session_id = "sess-fedcba-654321",
        .source_ip = "192.168.1.100",
        .trace_id = time.TEST_TRACE_ID,
        .span_id = time.TEST_SPAN_ID,
        .metadata = null,
    };
}

fn makeMetadata(allocator: std.mem.Allocator, field_count: usize) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    const fields = [_]struct { key: []const u8, val: []const u8 }{
        .{ .key = "username", .val = "john.doe@example.com" },
        .{ .key = "department", .val = "Engineering" },
        .{ .key = "action_detail", .val = "Password change via self-service portal" },
        .{ .key = "client_version", .val = "2.4.1" },
        .{ .key = "mfa_method", .val = "totp" },
        .{ .key = "browser", .val = "Chrome/120.0" },
        .{ .key = "os_name", .val = "Linux 6.1" },
        .{ .key = "geo_country", .val = "US" },
        .{ .key = "geo_city", .val = "San Francisco" },
        .{ .key = "risk_score", .val = "low" },
    };

    const n = @min(field_count, fields.len);
    for (fields[0..n]) |f| {
        try obj.put(allocator, f.key, std.json.Value{ .string = f.val });
    }
    return std.json.Value{ .object = obj };
}

/// Maximum wall-clock time for a single tier (10 minutes).
const TIER_TIMEOUT_NS: u64 = 10 * 60 * std.time.ns_per_s;

// ---------------------------------------------------------------------------
// Individual benchmark functions
// ---------------------------------------------------------------------------

fn benchValidate(iterations: usize) f64 {
    const event = makeEvent();
    const timer_start: u64 = nowNs();

    for (0..iterations) |_| {
        event.validate() catch {};
    }

    const ns_f: f64 = @floatFromInt(nowNs() - timer_start);
    const count_f: f64 = @floatFromInt(iterations);
    return ns_f / count_f;
}

fn benchClone(allocator: std.mem.Allocator, iterations: usize) f64 {
    const event = makeEvent();
    const timer_start: u64 = nowNs();

    for (0..iterations) |_| {
        var cloned = event.clone(allocator) catch continue;
        cloned.freeCloned(allocator);
    }

    const ns_f: f64 = @floatFromInt(nowNs() - timer_start);
    const count_f: f64 = @floatFromInt(iterations);
    return ns_f / count_f;
}

fn benchCefFormat(allocator: std.mem.Allocator, iterations: usize) f64 {
    const event = makeEvent();
    const identity = config.CefIdentityConfig{
        .vendor = "DEVNW",
        .product = "AUDIT",
        .version = "0.1.0",
    };
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const timer_start: u64 = nowNs();

    for (0..iterations) |_| {
        const msg = cef.formatCef(allocator, &event, &identity, clock) catch continue;
        allocator.free(msg);
    }

    const ns_f: f64 = @floatFromInt(nowNs() - timer_start);
    const count_f: f64 = @floatFromInt(iterations);
    return ns_f / count_f;
}

fn benchFilterRedact(allocator: std.mem.Allocator, iterations: usize, field_count: usize) f64 {
    const metadata = makeMetadata(allocator, field_count) catch return 0;
    defer {
        var m = metadata;
        if (m == .object) m.object.deinit(allocator);
    }

    var filters_cfg = config.FiltersConfig{
        .default_deny = true,
        .allow_fields = @constCast(&[_][]const u8{ "username", "department", "action_detail", "client_version", "mfa_method" }),
        .deny_key_patterns = @constCast(&[_][]const u8{ "password", "secret" }),
        .pii_mode = .mask,
        .pci_mode = true,
    };

    const timer_start: u64 = nowNs();

    for (0..iterations) |_| {
        const result = filters.filterAndRedactMetadata(allocator, metadata, &filters_cfg) catch continue;
        if (result) |r| {
            json_util.freeJsonValue(allocator, r);
        }
    }

    const ns_f: f64 = @floatFromInt(nowNs() - timer_start);
    const count_f: f64 = @floatFromInt(iterations);
    return ns_f / count_f;
}

fn benchFileSink(allocator: std.mem.Allocator, iterations: usize) f64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();
    const test_dir = "zig-out/tmp/scale-bench-file";
    cwd.createDirPath(io, test_dir) catch return 0;
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/bench.log",
        .max_bytes = 1073741824, // 1GB — no rotation during bench
        .backup_count = 0,
        .sync_mode = .none,
    };

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const sink = audit.file_sink.FileSink.init(allocator, file_config, fixed_clock.clock()) catch return 0;

    const event = makeEvent();

    const timer_start: u64 = nowNs();

    for (0..iterations) |_| {
        _ = sink.write(&event, null) catch .dropped;
    }

    const elapsed = nowNs() - timer_start;
    sink.deinit(); // drains

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(iterations);
    return ns_f / count_f;
}

fn benchChannel(allocator: std.mem.Allocator, iterations: usize) f64 {
    var ch = BoundedChannel(u64).init(allocator, 4096) catch return 0;
    defer ch.deinit();

    const timer_start: u64 = nowNs();

    // Multi-threaded: producer sends, consumer receives (blocking)
    const producer = std.Thread.spawn(.{}, struct {
        fn run(channel: *BoundedChannel(u64), n: usize) void {
            for (0..n) |i| {
                while (!channel.trySend(i)) {
                    std.Thread.yield() catch {};
                }
            }
            channel.close();
        }
    }.run, .{ &ch, iterations }) catch return 0;

    var received: usize = 0;
    while (ch.receive()) |_| {
        received += 1;
    }
    producer.join();

    const ns_f: f64 = @floatFromInt(nowNs() - timer_start);
    const count_f: f64 = @floatFromInt(received);
    if (count_f == 0) return 0;
    return count_f / (ns_f / 1_000_000_000.0);
}

/// Multi-producer channel throughput (PR-013): `producer_count` threads
/// split a fixed `total` number of sends (remainder distributed to the
/// first producers) into one consumer that drains exactly `total` items.
/// Producers use trySend with yield-on-full so the send count is exact;
/// no close() is needed because the consumer stops at the known total.
fn benchChannelMultiProducer(allocator: std.mem.Allocator, total: usize, producer_count: usize) f64 {
    var ch = BoundedChannel(u64).init(allocator, 4096) catch return 0;
    defer ch.deinit();

    const Producer = struct {
        fn run(channel: *BoundedChannel(u64), n: usize) void {
            for (0..n) |i| {
                while (!channel.trySend(i)) {
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    var threads: [8]std.Thread = undefined;
    std.debug.assert(producer_count <= threads.len);
    const base = total / producer_count;
    const rem = total % producer_count;

    const timer_start: u64 = nowNs();

    var spawned: usize = 0;
    var expected: usize = 0;
    for (0..producer_count) |p| {
        const n = base + @intFromBool(p < rem);
        threads[p] = std.Thread.spawn(.{}, Producer.run, .{ &ch, n }) catch break;
        spawned += 1;
        expected += n;
    }

    // Single consumer: drain exactly the number of items the spawned
    // producers will send, then stop (deterministic, no close needed).
    var received: usize = 0;
    while (received < expected) {
        _ = ch.receive() orelse break;
        received += 1;
    }
    const elapsed = nowNs() - timer_start;

    for (threads[0..spawned]) |t| t.join();

    if (received == 0) return 0;
    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(received);
    if (ns_f == 0) return 0;
    return count_f / (ns_f / 1_000_000_000.0);
}

fn benchLogger(allocator: std.mem.Allocator, iterations: usize) f64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();
    const test_dir = "zig-out/tmp/scale-bench-logger";
    cwd.createDirPath(io, test_dir) catch return 0;
    defer cwd.deleteTree(io, test_dir) catch {};

    const test_config = config.Config{
        .version = 1,
        .service = config.ServiceConfig{ .name = "bench", .host = "bench-host", .pid = 1 },
        .identity = config.IdentityConfig{
            .cef = config.CefIdentityConfig{ .vendor = "V", .product = "P", .version = "1" },
        },
        .sinks = config.SinksConfig{
            .file = config.FileSinkConfig{
                .enabled = true,
                .path = test_dir ++ "/bench.log",
                .max_bytes = 1073741824,
                .backup_count = 0,
                .sync_mode = .none,
            },
            .syslog = config.SyslogSinkConfig{
                .enabled = false,
                .protocol = .udp,
                .host = "{{BENCH}}",
                .port = 514,
                .rfc5424 = config.SyslogRfc5424Config{ .facility = .local0 },
            },
        },
        .filters = config.FiltersConfig{
            .default_deny = false,
            .allow_fields = @constCast(&[_][]const u8{}),
            .deny_key_patterns = @constCast(&[_][]const u8{}),
            .pii_mode = .off,
            .pci_mode = false,
        },
        .allocator = allocator,
    };

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const logger_inst = AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen()) catch return 0;

    const event = makeEvent();

    const timer_start: u64 = nowNs();

    for (0..iterations) |_| {
        logger_inst.audit(&event) catch {};
    }

    const elapsed = nowNs() - timer_start;
    logger_inst.deinit();

    const count_f: f64 = @floatFromInt(iterations);
    const ns_f: f64 = @floatFromInt(elapsed);
    if (ns_f == 0) return 0;
    return count_f / (ns_f / 1_000_000_000.0);
}

fn benchMixed(allocator: std.mem.Allocator, iterations: usize, field_count: usize) f64 {
    // Mixed workload: 40% validate, 20% clone, 20% CEF format, 20% filter
    const event = makeEvent();
    const identity = config.CefIdentityConfig{ .vendor = "V", .product = "P", .version = "1" };
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();
    const metadata = makeMetadata(allocator, field_count) catch return 0;
    defer {
        var m = metadata;
        if (m == .object) m.object.deinit(allocator);
    }
    var filters_cfg = config.FiltersConfig{
        .default_deny = true,
        .allow_fields = @constCast(&[_][]const u8{ "username", "department" }),
        .deny_key_patterns = @constCast(&[_][]const u8{"password"}),
        .pii_mode = .mask,
        .pci_mode = false,
    };

    var rng = std.Random.DefaultPrng.init(42);
    const random = rng.random();

    const timer_start: u64 = nowNs();

    for (0..iterations) |_| {
        const roll = random.intRangeAtMost(u32, 0, 99);
        if (roll < 40) {
            event.validate() catch {};
        } else if (roll < 60) {
            var cloned = event.clone(allocator) catch continue;
            cloned.freeCloned(allocator);
        } else if (roll < 80) {
            const msg = cef.formatCef(allocator, &event, &identity, clock) catch continue;
            allocator.free(msg);
        } else {
            const result = filters.filterAndRedactMetadata(allocator, metadata, &filters_cfg) catch continue;
            if (result) |r| {
                json_util.freeJsonValue(allocator, r);
            }
        }
    }

    const count_f: f64 = @floatFromInt(iterations);
    const ns_f: f64 = @floatFromInt(nowNs() - timer_start);
    if (ns_f == 0) return 0;
    return count_f / (ns_f / 1_000_000_000.0);
}

// ---------------------------------------------------------------------------
// Run a single tier
// ---------------------------------------------------------------------------

fn runTier(allocator: std.mem.Allocator, tier: Tier) TierResult {
    const tier_start: u64 = nowNs();

    const iters = tier.event_count;

    print("    validate...\n", .{});
    const validate_ns = benchValidate(iters);
    if (checkTimeout(tier_start, tier)) |r| return r;

    print("    clone...\n", .{});
    const clone_ns = benchClone(allocator, iters);
    if (checkTimeout(tier_start, tier)) |r| return r;

    print("    CEF format...\n", .{});
    const cef_format_ns = benchCefFormat(allocator, iters);
    if (checkTimeout(tier_start, tier)) |r| return r;

    print("    filter+redact...\n", .{});
    const filter_redact_ns = benchFilterRedact(allocator, iters, tier.metadata_fields);
    if (checkTimeout(tier_start, tier)) |r| return r;

    print("    file sink...\n", .{});
    const file_sink_ns = benchFileSink(allocator, iters);
    if (checkTimeout(tier_start, tier)) |r| return r;

    print("    channel...\n", .{});
    const channel_ops_sec = benchChannel(allocator, iters);
    if (checkTimeout(tier_start, tier)) |r| return r;

    print("    channel multi-producer...\n", .{});
    const mp_producer_counts = [_]usize{ 1, 2, 4, 8 };
    var mp_ops: [mp_producer_counts.len]f64 = @splat(0);
    for (mp_producer_counts, 0..) |p, idx| {
        mp_ops[idx] = benchChannelMultiProducer(allocator, iters, p);
        if (checkTimeout(tier_start, tier)) |r| return r;
    }

    print("    logger...\n", .{});
    const logger_ops_sec = benchLogger(allocator, iters);
    if (checkTimeout(tier_start, tier)) |r| return r;

    print("    mixed...\n", .{});
    const mixed_ops_sec = benchMixed(allocator, iters, tier.metadata_fields);

    return TierResult{
        .name = tier.name,
        .event_count = @intCast(tier.event_count),
        .logger_ops_sec = logger_ops_sec,
        .channel_ops_sec = channel_ops_sec,
        .channel_mp1_ops_sec = mp_ops[0],
        .channel_mp2_ops_sec = mp_ops[1],
        .channel_mp4_ops_sec = mp_ops[2],
        .channel_mp8_ops_sec = mp_ops[3],
        .validate_ns = validate_ns,
        .clone_ns = clone_ns,
        .cef_format_ns = cef_format_ns,
        .filter_redact_ns = filter_redact_ns,
        .file_sink_ns = file_sink_ns,
        .mixed_ops_sec = mixed_ops_sec,
    };
}

fn checkTimeout(tier_start: u64, tier: Tier) ?TierResult {
    const elapsed = nowNs() - tier_start;
    if (elapsed > TIER_TIMEOUT_NS) {
        return skipResult(tier, "timeout (>10min)");
    }
    return null;
}

fn skipResult(tier: Tier, reason: []const u8) TierResult {
    return TierResult{
        .name = tier.name,
        .event_count = @intCast(tier.event_count),
        .logger_ops_sec = 0,
        .channel_ops_sec = 0,
        .validate_ns = 0,
        .clone_ns = 0,
        .cef_format_ns = 0,
        .filter_redact_ns = 0,
        .file_sink_ns = 0,
        .mixed_ops_sec = 0,
        .skipped = true,
        .skip_reason = reason,
    };
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

const StdoutWriter = struct {
    file: std.Io.File,
    io: std.Io,
    buf: [8192]u8 = undefined,
    writer: ?std.Io.File.Writer = null,

    fn open(self: *StdoutWriter) void {
        self.writer = self.file.writer(self.io, &self.buf);
    }

    fn writeAll(self: *StdoutWriter, data: []const u8) !void {
        try self.writer.?.interface.writeAll(data);
    }

    fn writeFmt(self: *StdoutWriter, comptime fmt: []const u8, args: anytype) !void {
        try self.writer.?.interface.print(fmt, args);
    }

    fn flush(self: *StdoutWriter) !void {
        try self.writer.?.interface.flush();
    }
};

fn writeJsonOutput(out: *StdoutWriter, results: []const TierResult) !void {
    try out.writeAll("{\n");
    try out.writeAll("  \"version\": 1,\n");

    // Timestamp
    const ts = timeSec();
    const epoch_secs: u64 = @intCast(ts);
    const es = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
    const day_secs = es.getDaySeconds();
    const year_day = es.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    try out.writeFmt("  \"timestamp\": \"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z\",\n", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    });

    try out.writeAll("  \"git_commit\": \"unknown\",\n");
    try out.writeFmt("  \"system\": {{ \"os\": \"{s}\", \"arch\": \"{s}\" }},\n", .{
        @tagName(builtin.os.tag),
        @tagName(builtin.cpu.arch),
    });

    try out.writeAll("  \"tiers\": [\n");
    for (results, 0..) |r, i| {
        try out.writeAll("    {\n");
        try out.writeFmt("      \"name\": \"{s}\",\n", .{r.name});
        try out.writeFmt("      \"event_count\": {d},\n", .{r.event_count});
        if (r.skipped) {
            try out.writeAll("      \"skipped\": true,\n");
            if (r.skip_reason) |reason| {
                try out.writeFmt("      \"skip_reason\": \"{s}\",\n", .{reason});
            }
        }
        try out.writeFmt("      \"logger_ops_sec\": {d:.0},\n", .{r.logger_ops_sec});
        try out.writeFmt("      \"channel_ops_sec\": {d:.0},\n", .{r.channel_ops_sec});
        try out.writeFmt("      \"channel_mp1_ops_sec\": {d:.0},\n", .{r.channel_mp1_ops_sec});
        try out.writeFmt("      \"channel_mp2_ops_sec\": {d:.0},\n", .{r.channel_mp2_ops_sec});
        try out.writeFmt("      \"channel_mp4_ops_sec\": {d:.0},\n", .{r.channel_mp4_ops_sec});
        try out.writeFmt("      \"channel_mp8_ops_sec\": {d:.0},\n", .{r.channel_mp8_ops_sec});
        try out.writeFmt("      \"validate_ns\": {d:.1},\n", .{r.validate_ns});
        try out.writeFmt("      \"clone_ns\": {d:.1},\n", .{r.clone_ns});
        try out.writeFmt("      \"cef_format_ns\": {d:.1},\n", .{r.cef_format_ns});
        try out.writeFmt("      \"filter_redact_ns\": {d:.1},\n", .{r.filter_redact_ns});
        try out.writeFmt("      \"file_sink_ns\": {d:.1},\n", .{r.file_sink_ns});
        try out.writeFmt("      \"mixed_ops_sec\": {d:.0}\n", .{r.mixed_ops_sec});
        if (i < results.len - 1) {
            try out.writeAll("    },\n");
        } else {
            try out.writeAll("    }\n");
        }
    }
    try out.writeAll("  ]\n");
    try out.writeAll("}\n");
    try out.flush();
}

// ---------------------------------------------------------------------------
// Human-readable summary
// ---------------------------------------------------------------------------

fn writeSummary(results: []const TierResult) void {
    print("\n", .{});
    print("{s}\n", .{"=" ** 120});
    print("  audit library incremental scale benchmark\n", .{});
    print("{s}\n\n", .{"=" ** 120});

    print("  {s:<6} {s:>8} {s:>12} {s:>12} {s:>10} {s:>10} {s:>10} {s:>12} {s:>10} {s:>12}\n", .{
        "Tier", "Events", "Logger/s", "Channel/s", "Valid(ns)", "Clone(ns)", "CEF(ns)", "Filter(ns)", "File(ns)", "Mixed/s",
    });
    print("  {s:<6} {s:>8} {s:>12} {s:>12} {s:>10} {s:>10} {s:>10} {s:>12} {s:>10} {s:>12}\n", .{
        "-" ** 6, "-" ** 8, "-" ** 12, "-" ** 12, "-" ** 10, "-" ** 10, "-" ** 10, "-" ** 12, "-" ** 10, "-" ** 12,
    });

    for (results) |r| {
        if (r.skipped) {
            print("  {s:<6} {d:>8} SKIPPED ({s})\n", .{
                r.name, r.event_count, r.skip_reason orelse "unknown",
            });
        } else {
            print("  {s:<6} {d:>8} {d:>12.0} {d:>12.0} {d:>10.1} {d:>10.1} {d:>10.1} {d:>12.1} {d:>10.1} {d:>12.0}\n", .{
                r.name,
                r.event_count,
                r.logger_ops_sec,
                r.channel_ops_sec,
                r.validate_ns,
                r.clone_ns,
                r.cef_format_ns,
                r.filter_redact_ns,
                r.file_sink_ns,
                r.mixed_ops_sec,
            });
        }
    }

    print("\n{s}\n\n", .{"=" ** 120});
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;

    // Parse optional max-tier argument
    var args = init.minimal.args.iterate();
    _ = args.next();

    var max_tier_count: usize = tiers.len;
    if (args.next()) |arg| {
        for (tiers, 0..) |t, i| {
            if (std.mem.eql(u8, arg, t.name)) {
                max_tier_count = i + 1;
                break;
            }
        }
    }

    var results: [tiers.len]TierResult = undefined;
    var completed: usize = 0;

    for (tiers[0..max_tier_count], 0..) |tier, i| {
        print("  Running tier {s} ({d} events)...\n", .{ tier.name, tier.event_count });
        results[i] = runTier(allocator, tier);
        completed = i + 1;

        if (results[i].skipped) {
            print("  Tier {s} skipped: {s}\n", .{ tier.name, results[i].skip_reason orelse "unknown" });
        } else {
            print("  Tier {s} complete.\n", .{tier.name});
        }
    }

    writeSummary(results[0..completed]);

    const stdout_io = std.Io.Threaded.global_single_threaded.io();
    var out = StdoutWriter{ .file = std.Io.File.stdout(), .io = stdout_io };
    out.open();
    try writeJsonOutput(&out, results[0..completed]);
}
