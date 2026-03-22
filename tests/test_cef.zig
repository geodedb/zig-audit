// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const testing = std.testing;
const audit = @import("audit");
const events = audit.events;
const config = audit.config;
const cef = audit.cef;
const time = audit.time;

test "CEF formatting basic structure" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const identity = config.CefIdentityConfig{
        .vendor = "DEVNW",
        .product = "AUDIT",
        .version = "0.1.0",
    };

    var event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS,
        .severity = .INFO,
        .actor_id = "jane.doe",
        .subject_id = null,
        .request_id = "req-abc123",
        .session_id = "ses-999",
        .source_ip = "203.0.113.5",
        .trace_id = time.TEST_TRACE_ID,
        .span_id = time.TEST_SPAN_ID,
        .metadata = null,
    };

    const cef_msg = try cef.formatCef(allocator, &event, &identity, clock);
    defer allocator.free(cef_msg);

    try testing.expect(std.mem.startsWith(u8, cef_msg, "CEF:0|DEVNW|AUDIT|0.1.0|auth.login|User login|5|"));
    try testing.expect(std.mem.indexOf(u8, cef_msg, "act=login") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "outcome=success") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "suser=jane.doe") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "src=203.0.113.5") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "requestId=req-abc123") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "traceId=11111111111111111111111111111111") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "spanId=2222222222222222") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "cs1Label=actorId cs1=jane.doe") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "cs2Label=sessionId cs2=ses-999") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "deviceExternalId=req-abc123") != null);
}

test "CEF severity mapping" {
    try testing.expect(events.Severity.DEBUG.toCefSeverity() == 2);
    try testing.expect(events.Severity.INFO.toCefSeverity() == 5);
    try testing.expect(events.Severity.WARN.toCefSeverity() == 8);
    try testing.expect(events.Severity.ERROR.toCefSeverity() == 10);
}

test "CEF with metadata extensions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const identity = config.CefIdentityConfig{
        .vendor = "DEVNW",
        .product = "AUDIT",
        .version = "0.1.0",
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    try metadata_obj.put("db.operation", std.json.Value{ .string = "UPDATE" });
    try metadata_obj.put("db.table", std.json.Value{ .string = "users" });
    try metadata_obj.put("db.rowCount", std.json.Value{ .integer = 1 });
    try metadata_obj.put("duration_ms", std.json.Value{ .integer = 42 });

    const metadata = std.json.Value{ .object = metadata_obj };

    var event = events.AuditEvent{
        .category = "db",
        .action = "update",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS,
        .severity = .INFO,
        .actor_id = "admin",
        .subject_id = "usr-123",
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = metadata,
    };

    const cef_msg = try cef.formatCef(allocator, &event, &identity, clock);
    defer allocator.free(cef_msg);

    try testing.expect(std.mem.indexOf(u8, cef_msg, "cs3Label=dbOperation cs3=UPDATE") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "cs4Label=dbTable cs4=users") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "cn1Label=rowCount cn1=1") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "cn2Label=durationMs cn2=42") != null);
}

test "CEF event name mapping" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const identity = config.CefIdentityConfig{
        .vendor = "DEVNW",
        .product = "AUDIT",
        .version = "0.1.0",
    };

    const test_cases = [_]struct { category: []const u8, action: []const u8, expected_name: []const u8 }{
        .{ .category = "auth", .action = "login", .expected_name = "User login" },
        .{ .category = "auth", .action = "logout", .expected_name = "User logout" },
        .{ .category = "auth", .action = "password.change", .expected_name = "Password change" },
        .{ .category = "db", .action = "select", .expected_name = "DB select" },
        .{ .category = "db", .action = "update", .expected_name = "DB update" },
        .{ .category = "unknown", .action = "something", .expected_name = "Audit event" },
    };

    for (test_cases) |test_case| {
        var event = events.AuditEvent{
            .category = test_case.category,
            .action = test_case.action,
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
            .metadata = null,
        };

        const cef_msg = try cef.formatCef(allocator, &event, &identity, clock);
        defer allocator.free(cef_msg);

        const expected_pattern = try std.fmt.allocPrint(allocator, "|{s}|{d}|", .{ test_case.expected_name, event.severity.toCefSeverity() });
        defer allocator.free(expected_pattern);

        try testing.expect(std.mem.indexOf(u8, cef_msg, expected_pattern) != null);
    }
}
