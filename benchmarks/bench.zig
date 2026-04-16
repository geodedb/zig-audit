// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Performance benchmark harness for the audit library.
//!
//! Benchmarks: event creation, validation, cloning, CEF formatting,
//! metadata filtering/redaction, JSON serialization, file sink throughput,
//! syslog enqueue throughput, and channel throughput.
//!
//! Run via: zig build bench
//!      or: make bench

const std = @import("std");
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

inline fn nowNs() u64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    const ts = std.Io.Clock.Timestamp.now(io_inst, .awake);
    return @intCast(ts.raw.toNanoseconds());
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const EVENT_COUNT: usize = 10_000;
const FILTER_COUNT: usize = 5_000;
const CEF_COUNT: usize = 5_000;
const CHANNEL_COUNT: usize = 100_000;
const LOGGER_COUNT: usize = 5_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BenchResult = struct {
    name: []const u8,
    count: usize,
    total_ns: u64,

    fn ops_per_sec(self: BenchResult) f64 {
        if (self.total_ns == 0) return 0;
        const count_f: f64 = @floatFromInt(self.count);
        const ns_f: f64 = @floatFromInt(self.total_ns);
        return count_f / (ns_f / 1_000_000_000.0);
    }

    fn avg_ns(self: BenchResult) f64 {
        if (self.count == 0) return 0;
        const ns_f: f64 = @floatFromInt(self.total_ns);
        const count_f: f64 = @floatFromInt(self.count);
        return ns_f / count_f;
    }
};

const print = std.debug.print;

fn printHeader() void {
    print("\n{s}\n", .{"=" ** 78});
    print("  audit library benchmark suite\n", .{});
    print("{s}\n\n", .{"=" ** 78});
    print("  {s:<30} {s:>10} {s:>14} {s:>12} {s:>10}\n", .{
        "Benchmark", "Count", "Total (ms)", "Avg (ns)", "ops/sec",
    });
    print("  {s:<30} {s:>10} {s:>14} {s:>12} {s:>10}\n", .{
        "-" ** 30, "-" ** 10, "-" ** 14, "-" ** 12, "-" ** 10,
    });
}

fn printResult(r: BenchResult) void {
    const total_ms = @as(f64, @floatFromInt(r.total_ns)) / 1_000_000.0;
    print("  {s:<30} {d:>10} {d:>14.2} {d:>12.1} {d:>10.0}\n", .{
        r.name,
        r.count,
        total_ms,
        r.avg_ns(),
        r.ops_per_sec(),
    });
}

fn printFooter() void {
    print("\n{s}\n\n", .{"=" ** 78});
}

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

fn makeEventWithMetadata(allocator: std.mem.Allocator) !AuditEvent {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "username", std.json.Value{ .string = "john.doe@example.com" });
    try obj.put(allocator, "department", std.json.Value{ .string = "Engineering" });
    try obj.put(allocator, "action_detail", std.json.Value{ .string = "Password change via self-service portal" });
    try obj.put(allocator, "client_version", std.json.Value{ .string = "2.4.1" });
    try obj.put(allocator, "mfa_method", std.json.Value{ .string = "totp" });

    var event = makeEvent();
    event.metadata = std.json.Value{ .object = obj };
    return event;
}

var allow_fields_storage = [_][]const u8{
    "username", "department", "action_detail", "client_version", "mfa_method",
};
var deny_patterns_storage = [_][]const u8{ "password", "secret", "token" };

fn makeFiltersConfig() config.FiltersConfig {
    return config.FiltersConfig{
        .default_deny = true,
        .allow_fields = &allow_fields_storage,
        .deny_key_patterns = &deny_patterns_storage,
        .pii_mode = .mask,
        .pci_mode = true,
    };
}

// ---------------------------------------------------------------------------
// Individual benchmarks
// ---------------------------------------------------------------------------

fn benchEventValidation() BenchResult {
    const event = makeEvent();
    const timer_start: u64 = nowNs();

    for (0..EVENT_COUNT) |_| {
        event.validate() catch {};
    }

    return BenchResult{ .name = "event validation", .count = EVENT_COUNT, .total_ns = nowNs() - timer_start };
}

fn benchEventClone(allocator: std.mem.Allocator) BenchResult {
    const event = makeEvent();
    const timer_start: u64 = nowNs();

    for (0..EVENT_COUNT) |_| {
        var cloned = event.clone(allocator) catch continue;
        cloned.freeCloned(allocator);
    }

    return BenchResult{ .name = "event clone", .count = EVENT_COUNT, .total_ns = nowNs() - timer_start };
}

fn benchCefFormat(allocator: std.mem.Allocator) BenchResult {
    const event = makeEvent();
    const identity = config.CefIdentityConfig{
        .vendor = "DEVNW",
        .product = "AUDIT",
        .version = "0.1.0",
    };
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const timer_start: u64 = nowNs();

    for (0..CEF_COUNT) |_| {
        const msg = cef.formatCef(allocator, &event, &identity, clock) catch continue;
        allocator.free(msg);
    }

    return BenchResult{ .name = "CEF format", .count = CEF_COUNT, .total_ns = nowNs() - timer_start };
}

fn benchMetadataFilter(allocator: std.mem.Allocator) BenchResult {
    // Build metadata with sensitive fields
    var obj: std.json.ObjectMap = .empty;
    obj.put(allocator, "username", std.json.Value{ .string = "john.doe@example.com" }) catch {};
    obj.put(allocator, "password", std.json.Value{ .string = "secret123" }) catch {};
    obj.put(allocator, "credit_card", std.json.Value{ .string = "4111111111111111" }) catch {};
    obj.put(allocator, "department", std.json.Value{ .string = "Engineering" }) catch {};
    obj.put(allocator, "phone", std.json.Value{ .string = "+1-555-123-4567" }) catch {};
    defer obj.deinit(allocator);

    const metadata = std.json.Value{ .object = obj };
    var filters_cfg = makeFiltersConfig();

    const timer_start: u64 = nowNs();

    for (0..FILTER_COUNT) |_| {
        const result = filters.filterAndRedactMetadata(allocator, metadata, &filters_cfg) catch continue;
        if (result) |r| {
            json_util.freeJsonValue(allocator, r);
        }
    }

    return BenchResult{ .name = "metadata filter+redact", .count = FILTER_COUNT, .total_ns = nowNs() - timer_start };
}

fn benchSensitiveKeyDetect() BenchResult {
    const keys = [_][]const u8{
        "password",     "api_key",         "authorization",
        "credit_card",  "ssn",             "email",
        "phone_number", "private_key_pem", "session_token",
        "safe_field",
    };
    const total = EVENT_COUNT * keys.len;

    const timer_start: u64 = nowNs();

    for (0..EVENT_COUNT) |_| {
        for (keys) |key| {
            _ = filters.isSensitiveKey(std.heap.page_allocator, key);
        }
    }

    return BenchResult{ .name = "sensitive key detect", .count = total, .total_ns = nowNs() - timer_start };
}

fn benchChannelThroughput(allocator: std.mem.Allocator) BenchResult {
    var ch = BoundedChannel(u64).init(allocator, 1024) catch return BenchResult{ .name = "channel throughput", .count = 0, .total_ns = 0 };
    defer ch.deinit();

    const timer_start: u64 = nowNs();

    // Single-threaded: send/receive pairs to measure raw channel overhead
    for (0..CHANNEL_COUNT) |i| {
        _ = ch.trySend(i);
        _ = ch.tryReceive();
    }

    return BenchResult{ .name = "channel throughput", .count = CHANNEL_COUNT, .total_ns = nowNs() - timer_start };
}

fn benchChannelMT(allocator: std.mem.Allocator) BenchResult {
    var ch = BoundedChannel(u64).init(allocator, 4096) catch return BenchResult{ .name = "channel MT throughput", .count = 0, .total_ns = 0 };
    defer ch.deinit();

    const count = CHANNEL_COUNT;
    const timer_start: u64 = nowNs();

    // Producer thread
    const producer = std.Thread.spawn(.{}, struct {
        fn run(channel: *BoundedChannel(u64), n: usize) void {
            for (0..n) |i| {
                while (!channel.trySend(i)) {
                    std.Thread.yield() catch {};
                }
            }
            channel.close();
        }
    }.run, .{ &ch, count }) catch return BenchResult{ .name = "channel MT throughput", .count = 0, .total_ns = 0 };

    // Consumer: blocking receive
    var received: usize = 0;
    while (ch.receive()) |_| {
        received += 1;
    }

    producer.join();
    return BenchResult{ .name = "channel MT throughput", .count = received, .total_ns = nowNs() - timer_start };
}

fn benchLoggerAudit(allocator: std.mem.Allocator) BenchResult {
    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();
    const test_dir = "zig-out/tmp/bench-logger";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    const test_config = config.Config{
        .version = 1,
        .service = config.ServiceConfig{
            .name = "bench-svc",
            .host = "bench-host",
            .pid = 9999,
        },
        .identity = config.IdentityConfig{
            .cef = config.CefIdentityConfig{
                .vendor = "DEVNW",
                .product = "AUDIT",
                .version = "0.1.0",
            },
        },
        .sinks = config.SinksConfig{
            .file = config.FileSinkConfig{
                .enabled = true,
                .path = test_dir ++ "/bench.log",
                .max_bytes = 104857600, // 100MB
                .backup_count = 0,
                .sync_mode = .none,
            },
            .syslog = config.SyslogSinkConfig{
                .enabled = false,
                .protocol = .udp,
                .host = "{{BENCH_HOST}}",
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
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID, time.TEST_REQUEST_ID);

    const logger_inst = AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen()) catch
        return BenchResult{ .name = "logger audit()", .count = 0, .total_ns = 0 };

    const event = makeEvent();

    const timer_start: u64 = nowNs();

    for (0..LOGGER_COUNT) |_| {
        logger_inst.audit(&event) catch {};
    }

    const elapsed = nowNs() - timer_start;
    logger_inst.deinit();

    return BenchResult{ .name = "logger audit()", .count = LOGGER_COUNT, .total_ns = elapsed };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    printHeader();

    printResult(benchEventValidation());
    printResult(benchEventClone(allocator));
    printResult(benchCefFormat(allocator));
    printResult(benchMetadataFilter(allocator));
    printResult(benchSensitiveKeyDetect());
    printResult(benchChannelThroughput(allocator));
    printResult(benchChannelMT(allocator));
    printResult(benchLoggerAudit(allocator));

    printFooter();
}
