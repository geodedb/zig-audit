// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic usage example for the audit library.
//!
//! Demonstrates:
//!   1. Loading a test configuration
//!   2. Creating an AuditLogger with deterministic clock/ID helpers
//!   3. Emitting a sample audit event
//!   4. Reading back the file sink output to show what was written
//!   5. Formatting a timestamp with the shared formatRfc3339 helper

const std = @import("std");
const audit = @import("audit");

/// Helper to write to stdout on Zig 0.16+ where std.io.getStdOut is removed.
fn printStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const file: std.Io.File = std.Io.File.stdout();
    const io = std.Io.Threaded.global_single_threaded.io();
    var w = file.writer(io, &buf);
    w.interface.print(fmt, args) catch return;
    w.interface.flush() catch return;
}

pub fn main() !void {
    printStdout("audit library -- basic example\n", .{});
    printStdout("==============================\n\n", .{});

    // -- 1. Allocator setup -------------------------------------------------
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // -- 2. Load a test configuration ---------------------------------------
    //    In production you would call audit.config.loadConfig(allocator, path)
    //    to read a JSON config file.  loadTestConfig gives us sensible defaults
    //    without requiring a file on disk.
    var cfg = try audit.config.loadTestConfig(allocator);

    //    Disable syslog for this example (no real syslog server available).
    //
    //    To enable syslog in production, configure the syslog sink in your
    //    JSON config file (or set these fields programmatically):
    //
    //      cfg.sinks.syslog.enabled  = true;
    //      cfg.sinks.syslog.protocol = .udp;   // .udp, .tcp, or .tls
    //      cfg.sinks.syslog.host     = "10.0.0.50";  // prefer IP over hostname
    //      cfg.sinks.syslog.port     = 514;
    //      cfg.sinks.syslog.rfc5424.facility = .local4;
    //
    //    Or via JSON config:
    //
    //      "sinks": {
    //        "syslog": {
    //          "enabled": true,
    //          "protocol": "udp",
    //          "host": "10.0.0.50",
    //          "port": 514,
    //          "rfc5424": { "facility": "local4" }
    //        }
    //      }
    //
    //    See README.md "Security Considerations" for notes on using IP
    //    addresses vs hostnames in high-security environments.
    cfg.sinks.syslog.enabled = false;

    //    Point the file sink at a temporary path so the example is self-contained.
    allocator.free(cfg.sinks.file.path);
    cfg.sinks.file.path = try allocator.dupe(u8, "zig-out/tmp/example-audit.log");

    printStdout("[config] service   = {s}\n", .{cfg.service.name});
    printStdout("[config] file sink = {s}\n", .{cfg.sinks.file.path});
    printStdout("[config] syslog    = disabled (no server for example)\n\n", .{});

    // -- 3. Create deterministic clock and ID generator ----------------------
    //    FixedClock and FixedIdGen produce repeatable output, which is useful
    //    for testing and for this example.  In production, use SystemClock
    //    and SystemIdGen (or let buildAuditLogger create them for you).
    var fixed_clock = audit.time.FixedClock.init(audit.time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = audit.time.FixedIdGen.init(
        audit.time.TEST_TRACE_ID,
        audit.time.TEST_SPAN_ID,
        audit.time.TEST_REQUEST_ID,
    );

    // -- 4. Build the AuditLogger -------------------------------------------
    //    The logger takes ownership of cfg and will free it on deinit.
    const logger = try audit.AuditLogger.init(
        allocator,
        cfg,
        fixed_clock.clock(),
        fixed_id_gen.idGen(),
    );
    defer logger.deinit();

    printStdout("[logger] created successfully\n", .{});

    // -- 5. Emit a sample audit event ---------------------------------------
    const event = audit.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = 0, // 0 means "use the injected clock"
        .severity = .INFO,
        .actor_id = "jane.doe",
        .subject_id = "jane.doe",
        .request_id = "req-abc123",
        .session_id = "ses-999",
        .source_ip = "203.0.113.5",
        .trace_id = audit.time.TEST_TRACE_ID,
        .span_id = audit.time.TEST_SPAN_ID,
        .metadata = null,
    };

    try logger.audit(&event);
    printStdout("[logger] emitted auth.login event\n", .{});

    // -- 6. Read back the file sink output ----------------------------------
    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();
    const content = try cwd.readFileAlloc(io, "zig-out/tmp/example-audit.log", allocator, .limited(8192));
    defer allocator.free(content);

    printStdout("\n[file sink output]\n{s}\n", .{content});

    // -- 7. Demonstrate the shared formatRfc3339 helper ---------------------
    var ts_buf: [64]u8 = undefined;
    const formatted = audit.time.formatRfc3339(audit.time.TEST_TIMESTAMP_MS, &ts_buf);
    printStdout("\n[formatRfc3339] {d} -> {s}\n", .{ audit.time.TEST_TIMESTAMP_MS, formatted });

    printStdout("\nExample completed successfully.\n", .{});
}
