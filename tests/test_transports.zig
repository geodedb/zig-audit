// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const testing = std.testing;
const audit = @import("audit");
const events = audit.events;
const config = audit.config;
const syslog = audit.syslog;
const file_sink = audit.file_sink;
const time = audit.time;

test "syslog RFC5424 formatting" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const service_config = config.ServiceConfig{
        .name = "authsvc",
        .host = "app-host",
        .pid = 1234,
    };

    const identity_config = config.CefIdentityConfig{
        .vendor = "DEVNW",
        .product = "AUDIT",
        .version = "0.1.0",
    };

    const syslog_config = config.SyslogSinkConfig{
        .enabled = true,
        .protocol = .udp,
        .host = "{{SYSLOG_HOST}}",
        .port = 514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local4,
        },
    };

    var mock_sender = try syslog.MockSyslogSender.init(allocator);
    defer mock_sender.deinit();

    const event = events.AuditEvent{
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

    try mock_sender.send(&event, &identity_config, &service_config, &syslog_config, clock);

    const messages = mock_sender.getMessages();
    try testing.expect(messages.len == 1);

    const expected_line = "<166>1 2025-01-01T00:00:00.000Z app-host authsvc 1234 AUDIT - CEF:0|DEVNW|AUDIT|0.1.0|auth.login|User login|5|rt=2025-01-01T00:00:00.000Z act=login outcome=success suser=jane.doe src=203.0.113.5 requestId=req-abc123 traceId=11111111111111111111111111111111 spanId=2222222222222222 cs1Label=actorId cs1=jane.doe cs2Label=sessionId cs2=ses-999 deviceExternalId=req-abc123";

    try testing.expectEqualStrings(expected_line, messages[0]);
}

test "syslog severity and facility calculation" {
    const facility = config.SyslogFacility.local4;
    const severity = events.Severity.INFO;

    try testing.expect(facility.toInt() == 20);
    try testing.expect(severity.toSyslogSeverity() == 6);

    const pri = facility.toInt() * 8 + severity.toSyslogSeverity();
    try testing.expect(pri == 166);
}

test "file sink JSON formatting" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const test_dir = "zig-out/tmp/test-file-sink";
    std.fs.cwd().makePath(test_dir) catch {};
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/test.log",
        .max_bytes = 1024 * 1024,
        .backup_count = 3,
    };

    const sink = try file_sink.FileSink.init(allocator, file_config, clock);
    defer sink.deinit();

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();
    try metadata_obj.put("user_action", std.json.Value{ .string = "profile_update" });
    try metadata_obj.put("request_size", std.json.Value{ .integer = 1024 });
    const metadata = std.json.Value{ .object = metadata_obj };

    const event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS,
        .severity = .INFO,
        .actor_id = "test-user",
        .subject_id = "test-subject",
        .request_id = "req-test-001",
        .session_id = "ses-test-001",
        .source_ip = "192.168.1.1",
        .trace_id = time.TEST_TRACE_ID,
        .span_id = time.TEST_SPAN_ID,
        .metadata = metadata,
    };

    try sink.write(&event, metadata);

    const file = try std.fs.cwd().openFile(file_config.path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 8192);
    defer allocator.free(content);

    const line = std.mem.trim(u8, content, " \n\r\t");
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();

    const json_obj = parsed.value.object;

    try testing.expect(json_obj.contains("ts"));
    try testing.expect(json_obj.contains("category"));
    try testing.expect(json_obj.contains("action"));
    try testing.expect(json_obj.contains("outcome"));
    try testing.expect(json_obj.contains("severity"));
    try testing.expect(json_obj.contains("actor_id"));

    try testing.expectEqualStrings("auth", json_obj.get("category").?.string);
    try testing.expectEqualStrings("login", json_obj.get("action").?.string);
    try testing.expectEqualStrings("success", json_obj.get("outcome").?.string);
    try testing.expectEqualStrings("test-user", json_obj.get("actor_id").?.string);

    try testing.expect(json_obj.contains("user_action"));
    try testing.expectEqualStrings("profile_update", json_obj.get("user_action").?.string);
    try testing.expect(json_obj.get("request_size").?.integer == 1024);
}

test "file rotation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const test_dir = "zig-out/tmp/test-rotation";
    std.fs.cwd().makePath(test_dir) catch {};
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/rotate.log",
        .max_bytes = 512,
        .backup_count = 2,
    };

    const sink = try file_sink.FileSink.init(allocator, file_config, clock);

    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        const event = events.AuditEvent{
            .category = "test",
            .action = "rotation_test",
            .outcome = .success,
            .ts_unix_ms = time.TEST_TIMESTAMP_MS,
            .severity = .INFO,
            .actor_id = "rotation-test-user",
            .subject_id = null,
            .request_id = null,
            .session_id = null,
            .source_ip = null,
            .trace_id = null,
            .span_id = null,
            .metadata = null,
        };

        try sink.write(&event, null);
    }

    // deinit drains all queued writes to disk before closing
    sink.deinit();

    const file_exists = blk: {
        std.fs.cwd().access(test_dir ++ "/rotate.log", .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(file_exists);
    const backup_exists = blk: {
        std.fs.cwd().access(test_dir ++ "/rotate.log.1", .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(backup_exists);
}

test "syslog protocol enum parsing" {
    try testing.expect(try config.SyslogProtocol.fromString("udp") == .udp);
    try testing.expect(try config.SyslogProtocol.fromString("tcp") == .tcp);
    try testing.expect(try config.SyslogProtocol.fromString("tls") == .tls);

    try testing.expectError(error.InvalidProtocol, config.SyslogProtocol.fromString("invalid"));
}

test "syslog facility enum parsing and mapping" {
    try testing.expect(try config.SyslogFacility.fromString("local0") == .local0);
    try testing.expect(try config.SyslogFacility.fromString("local4") == .local4);
    try testing.expect(try config.SyslogFacility.fromString("local7") == .local7);

    try testing.expectError(error.InvalidFacility, config.SyslogFacility.fromString("invalid"));

    try testing.expect(config.SyslogFacility.local0.toInt() == 16);
    try testing.expect(config.SyslogFacility.local1.toInt() == 17);
    try testing.expect(config.SyslogFacility.local4.toInt() == 20);
    try testing.expect(config.SyslogFacility.local7.toInt() == 23);
}

test "event outcome enum string conversion" {
    try testing.expectEqualStrings("success", events.Outcome.success.toString());
    try testing.expectEqualStrings("failure", events.Outcome.failure.toString());
    try testing.expectEqualStrings("deny", events.Outcome.deny.toString());
    try testing.expectEqualStrings("error", events.Outcome.@"error".toString());
}
