// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub const Severity = enum {
    DEBUG,
    INFO,
    WARN,
    ERROR,

    pub fn toSyslogSeverity(self: Severity) u8 {
        return switch (self) {
            .DEBUG => 7,
            .INFO => 6,
            .WARN => 4,
            .ERROR => 3,
        };
    }

    pub fn toCefSeverity(self: Severity) u8 {
        return switch (self) {
            .DEBUG => 2,
            .INFO => 5,
            .WARN => 8,
            .ERROR => 10,
        };
    }
};

pub const Outcome = enum {
    success,
    failure,
    deny,
    @"error",

    pub fn toString(self: Outcome) []const u8 {
        return switch (self) {
            .success => "success",
            .failure => "failure",
            .deny => "deny",
            .@"error" => "error",
        };
    }
};

pub const AuditEvent = struct {
    category: []const u8, // "auth" | "db"
    action: []const u8, // e.g., "login", "password.change", "db.update"
    outcome: Outcome,
    ts_unix_ms: i128, // UTC epoch ms; if 0, use injected clock
    severity: Severity,
    actor_id: []const u8,
    subject_id: ?[]const u8,
    request_id: ?[]const u8,
    session_id: ?[]const u8,
    source_ip: ?[]const u8,
    trace_id: ?[32]u8, // 32 hex (lowercase)
    span_id: ?[16]u8, // 16 hex (lowercase)
    metadata: ?std.json.Value, // arbitrary object; filtered/redacted

    pub fn init(allocator: std.mem.Allocator) AuditEvent {
        _ = allocator;
        return AuditEvent{
            .category = "",
            .action = "",
            .outcome = .success,
            .ts_unix_ms = 0,
            .severity = .INFO,
            .actor_id = "",
            .subject_id = null,
            .request_id = null,
            .session_id = null,
            .source_ip = null,
            .trace_id = null,
            .span_id = null,
            .metadata = null,
        };
    }

    pub fn deinit(self: *AuditEvent, allocator: std.mem.Allocator) void {
        if (self.metadata) |metadata| {
            freeJsonValue(allocator, metadata);
        }
    }

    fn freeJsonValue(allocator: std.mem.Allocator, value: std.json.Value) void {
        var val = value;
        switch (val) {
            .number_string => |ns| allocator.free(ns),
            .string => |s| allocator.free(s),
            .array => |*arr| {
                for (arr.items) |item| {
                    freeJsonValue(allocator, item);
                }
                arr.deinit();
            },
            .object => |*obj| {
                var iter = obj.iterator();
                while (iter.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    freeJsonValue(allocator, entry.value_ptr.*);
                }
                obj.deinit();
            },
            else => {},
        }
    }

    pub fn clone(self: *const AuditEvent, allocator: std.mem.Allocator) !AuditEvent {
        var cloned = AuditEvent{
            .category = try allocator.dupe(u8, self.category),
            .action = try allocator.dupe(u8, self.action),
            .outcome = self.outcome,
            .ts_unix_ms = self.ts_unix_ms,
            .severity = self.severity,
            .actor_id = try allocator.dupe(u8, self.actor_id),
            .subject_id = if (self.subject_id) |sid| try allocator.dupe(u8, sid) else null,
            .request_id = if (self.request_id) |rid| try allocator.dupe(u8, rid) else null,
            .session_id = if (self.session_id) |sid| try allocator.dupe(u8, sid) else null,
            .source_ip = if (self.source_ip) |sip| try allocator.dupe(u8, sip) else null,
            .trace_id = self.trace_id,
            .span_id = self.span_id,
            .metadata = null,
        };

        if (self.metadata) |metadata| {
            // Deep clone JSON value via round-trip serialization
            const json_str = try std.json.Stringify.valueAlloc(allocator, metadata, .{});
            defer allocator.free(json_str);
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
            defer parsed.deinit();
            // Clone the parsed value so it outlives the parsed container
            cloned.metadata = try cloneJsonValue(allocator, parsed.value);
        }

        return cloned;
    }

    fn cloneJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
        return switch (value) {
            .null => .null,
            .bool => |b| std.json.Value{ .bool = b },
            .integer => |i| std.json.Value{ .integer = i },
            .float => |f| std.json.Value{ .float = f },
            .number_string => |ns| std.json.Value{ .number_string = try allocator.dupe(u8, ns) },
            .string => |s| std.json.Value{ .string = try allocator.dupe(u8, s) },
            .array => |arr| blk: {
                var cloned_array = std.json.Array.init(allocator);
                for (arr.items) |item| {
                    try cloned_array.append(try cloneJsonValue(allocator, item));
                }
                break :blk std.json.Value{ .array = cloned_array };
            },
            .object => |obj| blk: {
                var cloned_map = std.json.ObjectMap.init(allocator);
                var iter = obj.iterator();
                while (iter.next()) |entry| {
                    const cloned_key = try allocator.dupe(u8, entry.key_ptr.*);
                    const cloned_value = try cloneJsonValue(allocator, entry.value_ptr.*);
                    try cloned_map.put(cloned_key, cloned_value);
                }
                break :blk std.json.Value{ .object = cloned_map };
            },
        };
    }

    pub fn freeCloned(self: *AuditEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.category);
        allocator.free(self.action);
        allocator.free(self.actor_id);
        if (self.subject_id) |sid| allocator.free(sid);
        if (self.request_id) |rid| allocator.free(rid);
        if (self.session_id) |sid| allocator.free(sid);
        if (self.source_ip) |sip| allocator.free(sip);
        if (self.metadata) |metadata| {
            freeJsonValue(allocator, metadata);
        }
    }
};
