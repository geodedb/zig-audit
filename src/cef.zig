// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

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
    try extension.writer(allocator).print("rt={s}", .{ts_str});

    // Core fields
    try extension.writer(allocator).print(" act={s}", .{escapeValue(event.action)});
    try extension.writer(allocator).print(" outcome={s}", .{event.outcome.toString()});

    if (event.actor_id.len > 0) {
        try extension.writer(allocator).print(" suser={s}", .{escapeValue(event.actor_id)});
    }

    if (event.subject_id) |subject_id| {
        try extension.writer(allocator).print(" duser={s}", .{escapeValue(subject_id)});
    }

    if (event.source_ip) |source_ip| {
        try extension.writer(allocator).print(" src={s}", .{escapeValue(source_ip)});
    }

    if (event.request_id) |request_id| {
        try extension.writer(allocator).print(" requestId={s}", .{escapeValue(request_id)});
    }

    if (event.trace_id) |trace_id| {
        try extension.writer(allocator).print(" traceId={s}", .{@as([]const u8, &trace_id)});
    }

    if (event.span_id) |span_id| {
        try extension.writer(allocator).print(" spanId={s}", .{@as([]const u8, &span_id)});
    }

    // Custom signature fields
    try extension.writer(allocator).print(" cs1Label=actorId cs1={s}", .{escapeValue(event.actor_id)});

    if (event.session_id) |session_id| {
        try extension.writer(allocator).print(" cs2Label=sessionId cs2={s}", .{escapeValue(session_id)});
    }

    if (event.request_id) |request_id| {
        try extension.writer(allocator).print(" deviceExternalId={s}", .{escapeValue(request_id)});
    }

    // Add metadata fields if present
    if (event.metadata) |metadata| {
        try addMetadataExtensions(allocator, &extension, metadata);
    }

    return std.fmt.allocPrint(allocator, "CEF:0|{s}|{s}|{s}|{s}|{s}|{d}|{s}", .{
        escapeHeader(identity.vendor),
        escapeHeader(identity.product),
        escapeHeader(identity.version),
        escapeHeader(signature_id),
        escapeHeader(name),
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
                try extension.writer(allocator).print(" cs3Label=dbOperation cs3={s}", .{escapeValue(value.string)});
            }
        } else if (std.mem.eql(u8, key, "db.table")) {
            if (value == .string) {
                try extension.writer(allocator).print(" cs4Label=dbTable cs4={s}", .{escapeValue(value.string)});
            }
        } else if (std.mem.eql(u8, key, "db.rowCount")) {
            if (value == .integer) {
                try extension.writer(allocator).print(" cn1Label=rowCount cn1={d}", .{value.integer});
            }
        } else if (std.mem.eql(u8, key, "duration_ms")) {
            if (value == .integer) {
                try extension.writer(allocator).print(" cn2Label=durationMs cn2={d}", .{value.integer});
            }
        } else {
            try addGenericExtension(allocator, extension, key, value);
        }
    }
}

fn addGenericExtension(allocator: std.mem.Allocator, extension: *std.ArrayList(u8), key: []const u8, value: std.json.Value) !void {
    switch (value) {
        .string => |s| {
            try extension.writer(allocator).print(" {s}={s}", .{ escapeKey(key), escapeValue(s) });
        },
        .integer => |i| {
            try extension.writer(allocator).print(" {s}={d}", .{ escapeKey(key), i });
        },
        .bool => |b| {
            try extension.writer(allocator).print(" {s}={s}", .{ escapeKey(key), if (b) "true" else "false" });
        },
        else => {},
    }
}

fn escapeHeader(s: []const u8) []const u8 {
    return s;
}

fn escapeValue(s: []const u8) []const u8 {
    return s;
}

fn escapeKey(s: []const u8) []const u8 {
    return s;
}

pub fn escapeCefString(allocator: std.mem.Allocator, input: []const u8, is_header: bool) ![]const u8 {
    var result = try std.ArrayList(u8).initCapacity(allocator, input.len + 16);
    errdefer result.deinit(allocator);

    for (input) |c| {
        switch (c) {
            '\\' => try result.appendSlice(allocator, "\\\\"),
            '|' => if (is_header) try result.appendSlice(allocator, "\\|") else try result.append(allocator, c),
            '=' => if (is_header) try result.appendSlice(allocator, "\\=") else try result.appendSlice(allocator, "\\="),
            '\n' => if (!is_header) try result.appendSlice(allocator, "\\n") else try result.append(allocator, ' '),
            '\r' => if (!is_header) try result.appendSlice(allocator, "\\r") else try result.append(allocator, ' '),
            else => try result.append(allocator, c),
        }
    }

    return result.toOwnedSlice(allocator);
}

test "CEF formatting" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
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
