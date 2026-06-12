// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! CEF v0 (Common Event Format) message formatting.
//! Encodes audit events into the ArcSight CEF wire format with proper header
//! and extension escaping.

const std = @import("std");
const events = @import("events.zig");
const config = @import("config.zig");
const time = @import("time.zig");

pub fn formatCef(
    allocator: std.mem.Allocator,
    event: *const events.AuditEvent,
    identity: *const config.CefIdentityConfig,
    clock: time.Clock,
) ![]const u8 {
    // CEF:0|vendor|product|version|signature_id|name|severity|extension
    const signature_id = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ event.category, event.action });
    defer allocator.free(signature_id);

    const name = getEventName(event.category, event.action);
    const severity = event.severity.toCefSeverity();

    var extension = try std.ArrayList(u8).initCapacity(allocator, 256);
    defer extension.deinit(allocator);

    // Timestamp
    var ts_buf: [64]u8 = undefined;
    const ts_str = clock.nowRfc3339(&ts_buf);
    try extension.print(allocator, "rt={s}", .{ts_str});

    // Core fields
    const escaped_action = try escapeValue(allocator, event.action);
    defer allocator.free(escaped_action);
    try extension.print(allocator, " act={s}", .{escaped_action});
    try extension.print(allocator, " outcome={s}", .{event.outcome.toString()});

    if (event.actor_id.len > 0) {
        const escaped_actor = try escapeValue(allocator, event.actor_id);
        defer allocator.free(escaped_actor);
        try extension.print(allocator, " suser={s}", .{escaped_actor});
    }

    if (event.subject_id) |subject_id| {
        const escaped_subject = try escapeValue(allocator, subject_id);
        defer allocator.free(escaped_subject);
        try extension.print(allocator, " duser={s}", .{escaped_subject});
    }

    if (event.source_ip) |source_ip| {
        const escaped_ip = try escapeValue(allocator, source_ip);
        defer allocator.free(escaped_ip);
        try extension.print(allocator, " src={s}", .{escaped_ip});
    }

    if (event.request_id) |request_id| {
        const escaped_req = try escapeValue(allocator, request_id);
        defer allocator.free(escaped_req);
        try extension.print(allocator, " requestId={s}", .{escaped_req});
    }

    if (event.trace_id) |trace_id| {
        try extension.print(allocator, " traceId={s}", .{@as([]const u8, &trace_id)});
    }

    if (event.span_id) |span_id| {
        try extension.print(allocator, " spanId={s}", .{@as([]const u8, &span_id)});
    }

    // Custom signature fields
    const escaped_cs1 = try escapeValue(allocator, event.actor_id);
    defer allocator.free(escaped_cs1);
    try extension.print(allocator, " cs1Label=actorId cs1={s}", .{escaped_cs1});

    if (event.session_id) |session_id| {
        const escaped_session = try escapeValue(allocator, session_id);
        defer allocator.free(escaped_session);
        try extension.print(allocator, " cs2Label=sessionId cs2={s}", .{escaped_session});
    }

    if (event.request_id) |request_id| {
        const escaped_dev = try escapeValue(allocator, request_id);
        defer allocator.free(escaped_dev);
        try extension.print(allocator, " deviceExternalId={s}", .{escaped_dev});
    }

    // Add metadata fields if present
    if (event.metadata) |metadata| {
        try addMetadataExtensions(allocator, &extension, metadata);
    }

    // Escape header fields
    const escaped_vendor = try escapeHeader(allocator, identity.vendor);
    defer allocator.free(escaped_vendor);
    const escaped_product = try escapeHeader(allocator, identity.product);
    defer allocator.free(escaped_product);
    const escaped_version = try escapeHeader(allocator, identity.version);
    defer allocator.free(escaped_version);
    const escaped_sig_id = try escapeHeader(allocator, signature_id);
    defer allocator.free(escaped_sig_id);
    const escaped_name = try escapeHeader(allocator, name);
    defer allocator.free(escaped_name);

    return std.fmt.allocPrint(allocator, "CEF:0|{s}|{s}|{s}|{s}|{s}|{d}|{s}", .{
        escaped_vendor,
        escaped_product,
        escaped_version,
        escaped_sig_id,
        escaped_name,
        severity,
        extension.items,
    });
}

fn getEventName(category: []const u8, action: []const u8) []const u8 {
    if (std.mem.eql(u8, category, "auth")) {
        if (std.mem.eql(u8, action, "login")) return "User login";
        if (std.mem.eql(u8, action, "logout")) return "User logout";
        if (std.mem.eql(u8, action, "password.change")) return "Password change";
        if (std.mem.eql(u8, action, "mfa.challenge")) return "MFA challenge";
        return "Authentication event";
    }

    if (std.mem.eql(u8, category, "db")) {
        if (std.mem.eql(u8, action, "select")) return "DB select";
        if (std.mem.eql(u8, action, "insert")) return "DB insert";
        if (std.mem.eql(u8, action, "update")) return "DB update";
        if (std.mem.eql(u8, action, "delete")) return "DB delete";
        return "Database operation";
    }

    return "Audit event";
}

fn addMetadataExtensions(allocator: std.mem.Allocator, extension: *std.ArrayList(u8), metadata: std.json.Value) !void {
    if (metadata != .object) return;

    const obj = metadata.object;
    var iter = obj.iterator();

    while (iter.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;

        if (std.mem.eql(u8, key, "db.operation")) {
            if (value == .string) {
                const escaped = try escapeValue(allocator, value.string);
                defer allocator.free(escaped);
                try extension.print(allocator, " cs3Label=dbOperation cs3={s}", .{escaped});
            }
        } else if (std.mem.eql(u8, key, "db.table")) {
            if (value == .string) {
                const escaped = try escapeValue(allocator, value.string);
                defer allocator.free(escaped);
                try extension.print(allocator, " cs4Label=dbTable cs4={s}", .{escaped});
            }
        } else if (std.mem.eql(u8, key, "db.rowCount")) {
            if (value == .integer) {
                try extension.print(allocator, " cn1Label=rowCount cn1={d}", .{value.integer});
            }
        } else if (std.mem.eql(u8, key, "duration_ms")) {
            if (value == .integer) {
                try extension.print(allocator, " cn2Label=durationMs cn2={d}", .{value.integer});
            }
        } else {
            try addGenericExtension(allocator, extension, key, value);
        }
    }
}

fn addGenericExtension(allocator: std.mem.Allocator, extension: *std.ArrayList(u8), key: []const u8, value: std.json.Value) !void {
    switch (value) {
        .string => |s| {
            const escaped_key = try escapeKey(allocator, key);
            defer allocator.free(escaped_key);
            const escaped_val = try escapeValue(allocator, s);
            defer allocator.free(escaped_val);
            try extension.print(allocator, " {s}={s}", .{ escaped_key, escaped_val });
        },
        .integer => |i| {
            const escaped_key = try escapeKey(allocator, key);
            defer allocator.free(escaped_key);
            try extension.print(allocator, " {s}={d}", .{ escaped_key, i });
        },
        .bool => |b| {
            const escaped_key = try escapeKey(allocator, key);
            defer allocator.free(escaped_key);
            try extension.print(allocator, " {s}={s}", .{ escaped_key, if (b) "true" else "false" });
        },
        else => {},
    }
}

/// Escape a CEF header field value. Headers escape `\` and `|`.
fn escapeHeader(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    return escapeCefString(allocator, s, true);
}

/// Escape a CEF extension value. Extension values escape `\`, `=`, `\n`, and `\r`.
fn escapeValue(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    return escapeCefString(allocator, s, false);
}

/// Escape a CEF extension key. Same rules as extension values.
fn escapeKey(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    return escapeCefString(allocator, s, false);
}

/// Core CEF string escaping function.
///
/// When `is_header` is true (header fields): escapes `\` to `\\` and `|` to `\|`.
/// Newlines are replaced with spaces. `=` is NOT escaped in headers.
///
/// When `is_header` is false (extension values/keys): escapes `\` to `\\`,
/// `=` to `\=`, `\n` to `\\n`, `\r` to `\\r`. `|` is NOT escaped in extensions.
///
/// All other C0 control bytes (0x00-0x1F) and DEL (0x7F) are neutralized to
/// `\xNN` hex escapes in both modes (GAP-042/A3) so no raw control byte can
/// reach a log sink and forge or corrupt records.
pub fn escapeCefString(allocator: std.mem.Allocator, input: []const u8, is_header: bool) ![]const u8 {
    var result = try std.ArrayList(u8).initCapacity(allocator, input.len + 16);
    errdefer result.deinit(allocator);

    for (input) |c| {
        switch (c) {
            '\\' => try result.appendSlice(allocator, "\\\\"),
            '|' => if (is_header) try result.appendSlice(allocator, "\\|") else try result.append(allocator, c),
            '=' => if (is_header) try result.append(allocator, c) else try result.appendSlice(allocator, "\\="),
            '\n' => if (!is_header) try result.appendSlice(allocator, "\\n") else try result.append(allocator, ' '),
            '\r' => if (!is_header) try result.appendSlice(allocator, "\\r") else try result.append(allocator, ' '),
            0x00...0x09, 0x0B, 0x0C, 0x0E...0x1F, 0x7F => {
                var hex_buf: [4]u8 = undefined;
                const hex = std.fmt.bufPrint(&hex_buf, "\\x{x:0>2}", .{c}) catch unreachable;
                try result.appendSlice(allocator, hex);
            },
            else => try result.append(allocator, c),
        }
    }

    return result.toOwnedSlice(allocator);
}

test "CEF formatting" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    // Identity passed explicitly — no build_options import needed
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

    const cef_msg = try formatCef(allocator, &event, &identity, clock);
    defer allocator.free(cef_msg);

    try testing.expect(std.mem.startsWith(u8, cef_msg, "CEF:0|DEVNW|AUDIT|0.1.0|auth.login|User login|5|"));
    try testing.expect(std.mem.indexOf(u8, cef_msg, "act=login") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "outcome=success") != null);
    try testing.expect(std.mem.indexOf(u8, cef_msg, "suser=jane.doe") != null);
}

test "escapeCefString: header escapes backslash and pipe" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Backslash is escaped
    const r1 = try escapeCefString(allocator, "vendor\\name", true);
    defer allocator.free(r1);
    try testing.expectEqualStrings("vendor\\\\name", r1);

    // Pipe is escaped in headers
    const r2 = try escapeCefString(allocator, "product|v2", true);
    defer allocator.free(r2);
    try testing.expectEqualStrings("product\\|v2", r2);

    // Equals is NOT escaped in headers (CEF spec: only in extensions)
    const r3 = try escapeCefString(allocator, "key=val", true);
    defer allocator.free(r3);
    try testing.expectEqualStrings("key=val", r3);

    // Newlines are replaced with spaces in headers
    const r4 = try escapeCefString(allocator, "line1\nline2\rline3", true);
    defer allocator.free(r4);
    try testing.expectEqualStrings("line1 line2 line3", r4);
}

test "escapeCefString: extension value escapes backslash, equals, and newlines" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Backslash is escaped
    const r1 = try escapeCefString(allocator, "path\\to\\file", false);
    defer allocator.free(r1);
    try testing.expectEqualStrings("path\\\\to\\\\file", r1);

    // Equals is escaped in extensions
    const r2 = try escapeCefString(allocator, "a=b", false);
    defer allocator.free(r2);
    try testing.expectEqualStrings("a\\=b", r2);

    // Newline is escaped in extensions
    const r3 = try escapeCefString(allocator, "line1\nline2", false);
    defer allocator.free(r3);
    try testing.expectEqualStrings("line1\\nline2", r3);

    // Carriage return is escaped in extensions
    const r4 = try escapeCefString(allocator, "line1\rline2", false);
    defer allocator.free(r4);
    try testing.expectEqualStrings("line1\\rline2", r4);

    // Pipe is NOT escaped in extensions
    const r5 = try escapeCefString(allocator, "val|ue", false);
    defer allocator.free(r5);
    try testing.expectEqualStrings("val|ue", r5);
}

test "escapeCefString: no special characters returns input unchanged" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const r1 = try escapeCefString(allocator, "simple text", true);
    defer allocator.free(r1);
    try testing.expectEqualStrings("simple text", r1);

    const r2 = try escapeCefString(allocator, "simple text", false);
    defer allocator.free(r2);
    try testing.expectEqualStrings("simple text", r2);

    // Empty string
    const r3 = try escapeCefString(allocator, "", true);
    defer allocator.free(r3);
    try testing.expectEqualStrings("", r3);
}
