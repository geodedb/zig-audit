// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests for audit
//!
//! These tests verify end-to-end functionality and cross-module interactions.
//! Ported from Geode's test_audit_integration.zig (excluding DB adapter tests).

const std = @import("std");
const testing = std.testing;
const lib = @import("audit");
const events = lib.events;
const config = lib.config;
const logger = lib.logger;
const syslog = lib.syslog;
const time = lib.time;

test "integration: library initializes successfully" {
    // lib.version is single-sourced from build.zig.zon (GAP-074); assert it
    // is a well-formed semver instead of pinning a value that would drift
    // on every release.
    _ = try std.SemanticVersion.parse(lib.version);
}

test "integration: auth login success with exact syslog output" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const test_config = try config.loadTestConfig(allocator);
    // Logger takes ownership of config

    const audit_logger = try logger.AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer audit_logger.deinit();

    var mock_sender = try syslog.MockSyslogSender.init(allocator);
    defer mock_sender.deinit();

    const event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = 0,
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

    try mock_sender.send(&event, &test_config.identity.cef, &test_config.service, &test_config.sinks.syslog, fixed_clock.clock());

    const messages = mock_sender.getMessages();
    try testing.expect(messages.len == 1);

    // The CEF device-version field comes from loadTestConfig, which uses
    // lib.version (single-sourced from build.zig.zon) — interpolate it so
    // the assertion does not drift on version bumps.
    const expected_syslog_line = std.fmt.comptimePrint(
        "<166>1 2025-01-01T00:00:00.000Z app-host authsvc 1234 AUDIT - CEF:0|DEVNW|AUDIT|{s}|auth.login|User login|5|rt=2025-01-01T00:00:00.000Z act=login outcome=success suser=jane.doe src=203.0.113.5 requestId=req-abc123 traceId=11111111111111111111111111111111 spanId=2222222222222222 cs1Label=actorId cs1=jane.doe cs2Label=sessionId cs2=ses-999 deviceExternalId=req-abc123",
        .{lib.version},
    );

    try testing.expectEqualStrings(expected_syslog_line, messages[0]);
}

test "integration: sensitive data redaction" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();

    // Unique dir: other test binaries also write loadTestConfig's default
    // path in parallel; an isolated dir keeps the read-back deterministic.
    const test_dir = "zig-out/tmp/test-redaction";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};
    const log_path = test_dir ++ "/audit.log";

    var test_config = try config.loadTestConfig(allocator);
    allocator.free(test_config.sinks.file.path);
    test_config.sinks.file.path = try allocator.dupe(u8, log_path);

    const audit_logger = try logger.AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());

    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);

    try metadata_obj.put(allocator, "password", std.json.Value{ .string = "Sup3rSecret!" });
    try metadata_obj.put(allocator, "card", std.json.Value{ .string = "4111 1111 1111 1111" });
    try metadata_obj.put(allocator, "jwt", std.json.Value{ .string = "eyJhbGciOi...aaa.bbb" });

    const metadata = std.json.Value{ .object = metadata_obj };

    const event = events.AuditEvent{
        .category = "auth",
        .action = "password.change",
        .outcome = .success,
        .ts_unix_ms = 0,
        .severity = .INFO,
        .actor_id = "jane.doe",
        .subject_id = "jane.doe",
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = metadata,
    };

    try audit_logger.audit(&event);

    // The file sink is async (worker thread): content is only guaranteed on
    // disk after deinit drains the queue. Read AFTER deinit, and fail loudly
    // if nothing was written (QR-013) — the old soft guards silently passed
    // on an empty/missing file.
    audit_logger.deinit();

    const content = try cwd.readFileAlloc(io, log_path, allocator, .limited(8192));
    defer allocator.free(content);
    try testing.expect(content.len > 0);

    // Secrets must not appear in the output
    try testing.expect(std.mem.indexOf(u8, content, "Sup3rSecret!") == null);
    try testing.expect(std.mem.indexOf(u8, content, "4111 1111 1111 1111") == null);

    // Redaction tokens must appear: password (sensitive key), card
    // (detected PAN), jwt (sensitive key; value is not a parseable JWT)
    try testing.expect(std.mem.indexOf(u8, content, "[REDACTED]") != null);
    try testing.expect(std.mem.indexOf(u8, content, "[REDACTED_PAN]") != null);
    try testing.expect(std.mem.indexOf(u8, content, "[REDACTED_JWT]") != null);
}

test "integration: file rotation functionality" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/it-rotation";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    var test_config = try config.loadTestConfig(allocator);

    allocator.free(test_config.sinks.file.path);
    test_config.sinks.file.path = try allocator.dupe(u8, test_dir ++ "/audit.log");
    test_config.sinks.file.max_bytes = 512;
    test_config.sinks.file.backup_count = 2;

    const audit_logger = try logger.AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());

    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        const event = events.AuditEvent{
            .category = "test",
            .action = "rotation",
            .outcome = .success,
            .ts_unix_ms = 0,
            .severity = .INFO,
            .actor_id = "test-user-with-long-name-to-increase-size",
            .subject_id = "another-long-subject-id-for-size",
            .request_id = "very-long-request-id-to-make-lines-bigger",
            .session_id = "session-id-also-quite-long",
            .source_ip = "192.168.1.100",
            .trace_id = time.TEST_TRACE_ID,
            .span_id = time.TEST_SPAN_ID,
            .metadata = null,
        };

        try audit_logger.audit(&event);
    }

    // deinit drains all queued async writes before closing
    audit_logger.deinit();

    const audit_log = test_dir ++ "/audit.log";
    const backup1 = test_dir ++ "/audit.log.1";
    const backup3 = test_dir ++ "/audit.log.3";

    const audit_log_exists = blk: {
        cwd.access(io, audit_log, .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(audit_log_exists);
    const backup1_exists = blk: {
        cwd.access(io, backup1, .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(backup1_exists);
    const backup3_exists = blk: {
        cwd.access(io, backup3, .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(!backup3_exists);
}

test "integration: default deny filtering" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();

    // Unique dir: see "sensitive data redaction" above.
    const test_dir = "zig-out/tmp/test-default-deny";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};
    const log_path = test_dir ++ "/audit.log";

    var test_config = try config.loadTestConfig(allocator);
    allocator.free(test_config.sinks.file.path);
    test_config.sinks.file.path = try allocator.dupe(u8, log_path);

    const audit_logger = try logger.AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());

    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);

    try metadata_obj.put(allocator, "nickname", std.json.Value{ .string = "jay" });
    try metadata_obj.put(allocator, "notes", std.json.Value{ .string = "loves pizza" });
    try metadata_obj.put(allocator, "actor_id", std.json.Value{ .string = "jane.doe" });

    const metadata = std.json.Value{ .object = metadata_obj };

    const event = events.AuditEvent{
        .category = "auth",
        .action = "profile.view",
        .outcome = .success,
        .ts_unix_ms = 0,
        .severity = .DEBUG,
        .actor_id = "jane.doe",
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = metadata,
    };

    try audit_logger.audit(&event);

    // Async file sink: read AFTER deinit drains, and fail loudly if nothing
    // was written (QR-013).
    audit_logger.deinit();

    const content = try cwd.readFileAlloc(io, log_path, allocator, .limited(8192));
    defer allocator.free(content);
    try testing.expect(content.len > 0);

    // GAP-008: Fields not in allow_fields are now redacted (not dropped)
    // under default_deny. The key "nickname" will appear but with a
    // redacted value. The original value "loves pizza" must not leak.
    try testing.expect(std.mem.indexOf(u8, content, "loves pizza") == null);
    try testing.expect(std.mem.indexOf(u8, content, "jay") == null);
    // actor_id is in allow_fields and should appear with its value
    try testing.expect(std.mem.indexOf(u8, content, "jane.doe") != null);
}

test "integration: fail closed behavior" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID);

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-fail-closed";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    var test_config = try config.loadTestConfig(allocator);

    allocator.free(test_config.sinks.file.path);
    test_config.sinks.file.path = try allocator.dupe(u8, test_dir ++ "/audit.log");

    const audit_logger = try logger.AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());

    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);

    try metadata_obj.put(allocator, "private_key", std.json.Value{ .string = "raw_key_bytes_without_pem_markers_12345" });

    const metadata = std.json.Value{ .object = metadata_obj };

    const event = events.AuditEvent{
        .category = "auth",
        .action = "key.import",
        .outcome = .success,
        .ts_unix_ms = 0,
        .severity = .INFO,
        .actor_id = "admin",
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = metadata,
    };

    try audit_logger.audit(&event);

    // Async file sink: read AFTER deinit drains, and fail loudly if nothing
    // was written (QR-013).
    audit_logger.deinit();

    const content = try cwd.readFileAlloc(io, test_dir ++ "/audit.log", allocator, .limited(8192));
    defer allocator.free(content);
    try testing.expect(content.len > 0);

    // The private_key field should be redacted (value is not a valid PEM key,
    // so it gets redacted rather than causing the event to be dropped)
    try testing.expect(std.mem.indexOf(u8, content, "raw_key_bytes") == null);
    try testing.expect(std.mem.indexOf(u8, content, "[REDACTED_PK]") != null);
}
