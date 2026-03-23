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

test "CEF header escaping: pipe and backslash are escaped" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    // Vendor and product contain | and \ which must be escaped in CEF headers
    const identity = config.CefIdentityConfig{
        .vendor = "DEV|NW",
        .product = "AU\\DIT",
        .version = "1.0",
    };

    var event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS,
        .severity = .INFO,
        .actor_id = "user1",
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

    // Pipe in vendor must be escaped as \|
    try testing.expect(std.mem.startsWith(u8, cef_msg, "CEF:0|DEV\\|NW|AU\\\\DIT|1.0|"));
}

test "CEF header escaping: equals is NOT escaped in headers" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Per CEF spec, = is only escaped in extension values, not in headers
    const r = try cef.escapeCefString(allocator, "name=value", true);
    defer allocator.free(r);
    try testing.expectEqualStrings("name=value", r);
}

test "CEF extension value escaping: equals, newlines, carriage returns" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // = is escaped in extension values
    const r1 = try cef.escapeCefString(allocator, "key=val", false);
    defer allocator.free(r1);
    try testing.expectEqualStrings("key\\=val", r1);

    // \n is escaped
    const r2 = try cef.escapeCefString(allocator, "line1\nline2", false);
    defer allocator.free(r2);
    try testing.expectEqualStrings("line1\\nline2", r2);

    // \r is escaped
    const r3 = try cef.escapeCefString(allocator, "line1\rline2", false);
    defer allocator.free(r3);
    try testing.expectEqualStrings("line1\\rline2", r3);

    // Backslash is escaped
    const r4 = try cef.escapeCefString(allocator, "path\\file", false);
    defer allocator.free(r4);
    try testing.expectEqualStrings("path\\\\file", r4);

    // Pipe is NOT escaped in extension values
    const r5 = try cef.escapeCefString(allocator, "a|b", false);
    defer allocator.free(r5);
    try testing.expectEqualStrings("a|b", r5);
}

test "CEF formatCef with adversarial input produces valid CEF" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    // Identity with special characters
    const identity = config.CefIdentityConfig{
        .vendor = "Evil|Vendor\\Corp",
        .product = "Mal\nicious",
        .version = "1.0=beta",
    };

    // Event with special characters in fields
    var event = events.AuditEvent{
        .category = "auth",
        .action = "login\\attempt",
        .outcome = .failure,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS,
        .severity = .WARN,
        .actor_id = "user=admin\nroot",
        .subject_id = "target|user",
        .request_id = "req\\123=abc",
        .session_id = "ses\r\n456",
        .source_ip = "10.0.0.1",
        .trace_id = null,
        .span_id = null,
        .metadata = null,
    };

    const cef_msg = try cef.formatCef(allocator, &event, &identity, clock);
    defer allocator.free(cef_msg);

    // The message should start with CEF:0|
    try testing.expect(std.mem.startsWith(u8, cef_msg, "CEF:0|"));

    // Header pipes must be escaped: vendor "Evil|Vendor\\Corp" -> "Evil\|Vendor\\\\Corp"
    try testing.expect(std.mem.indexOf(u8, cef_msg, "Evil\\|Vendor\\\\Corp") != null);

    // Extension values: backslash in action is escaped
    try testing.expect(std.mem.indexOf(u8, cef_msg, "act=login\\\\attempt") != null);

    // Extension values: = in actor_id is escaped, \n is escaped
    try testing.expect(std.mem.indexOf(u8, cef_msg, "suser=user\\=admin\\nroot") != null);

    // Extension values: \r and \n in session_id are escaped
    try testing.expect(std.mem.indexOf(u8, cef_msg, "cs2Label=sessionId cs2=ses\\r\\n456") != null);

    // Validate the CEF header structure by walking through the first 7 unescaped
    // pipes. After the 7th pipe we are in the extension section (where pipes may
    // appear unescaped in values -- that is allowed by the CEF spec).
    var pipe_count: usize = 0;
    var i: usize = 0;
    while (i < cef_msg.len) : (i += 1) {
        if (cef_msg[i] == '|') {
            var bs_count: usize = 0;
            var j = i;
            while (j > 0 and cef_msg[j - 1] == '\\') {
                bs_count += 1;
                j -= 1;
            }
            if (bs_count % 2 == 0) {
                pipe_count += 1;
                if (pipe_count == 7) break; // 7th pipe starts the extension
            }
        }
    }
    // We must have found exactly 7 unescaped pipes for the header
    try testing.expectEqual(@as(usize, 7), pipe_count);

    // The character after the 7th pipe should be the start of the extension (rt=...)
    try testing.expect(i + 1 < cef_msg.len);
    try testing.expect(std.mem.startsWith(u8, cef_msg[i + 1 ..], "rt="));

    // Verify severity field is "8" (WARN) right before the 7th pipe
    try testing.expectEqual(@as(u8, '8'), cef_msg[i - 1]);
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
