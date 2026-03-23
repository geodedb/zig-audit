// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Rotating file sink for JSON-formatted audit log output.
//! Supports configurable max size and backup count for log rotation.

const std = @import("std");
const builtin = @import("builtin");
const events = @import("events.zig");
const config = @import("config.zig");
const json_util = @import("json_util.zig");
const time = @import("time.zig");
const log = std.log.scoped(.audit);

pub const FileSink = struct {
    allocator: std.mem.Allocator,
    config: config.FileSinkConfig,
    clock: time.Clock,
    current_file: ?std.fs.File,
    current_size: u64,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, file_config: config.FileSinkConfig, clock: time.Clock) !*FileSink {
        const sink = try allocator.create(FileSink);
        sink.* = FileSink{
            .allocator = allocator,
            .config = file_config,
            .clock = clock,
            .current_file = null,
            .current_size = 0,
            .mutex = std.Thread.Mutex{},
        };

        if (file_config.enabled) {
            try sink.openCurrentFile();
        }

        return sink;
    }

    pub fn deinit(self: *FileSink) void {
        if (self.current_file) |file| {
            file.close();
        }
        self.allocator.destroy(self);
    }

    pub fn write(self: *FileSink, event: *const events.AuditEvent, filtered_metadata: ?std.json.Value) !void {
        if (!self.config.enabled) return;

        const json_line = try self.formatJsonLine(event, filtered_metadata);
        defer self.allocator.free(json_line);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.checkRotation(json_line.len);

        if (self.current_file) |file| {
            try file.writeAll(json_line);
            try file.writeAll("\n");
            try file.sync();
            self.current_size += json_line.len + 1;
        }
    }

    pub fn writeError(self: *FileSink, error_msg: []const u8) !void {
        if (!self.config.enabled) return;

        var ts_buf: [64]u8 = undefined;
        const timestamp = self.clock.nowRfc3339(&ts_buf);

        var obj = std.json.ObjectMap.init(self.allocator);
        defer obj.deinit();
        try obj.put("ts", std.json.Value{ .string = timestamp });
        try obj.put("level", std.json.Value{ .string = "ERROR" });
        try obj.put("msg", std.json.Value{ .string = error_msg });
        const error_obj = try std.json.Stringify.valueAlloc(self.allocator, std.json.Value{ .object = obj }, .{});
        defer self.allocator.free(error_obj);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.checkRotation(error_obj.len);

        if (self.current_file) |file| {
            try file.writeAll(error_obj);
            try file.writeAll("\n");
            try file.sync();
            self.current_size += error_obj.len + 1;
        }
    }

    /// Insert a string field into a JSON object, duplicating both the key and value.
    /// This reduces repetition in formatJsonLine where every field follows the
    /// same `try obj.put(try dupe(key), .{ .string = try dupe(value) })` pattern.
    fn putField(self: *FileSink, obj: *std.json.ObjectMap, key: []const u8, value: []const u8) !void {
        try obj.put(
            try self.allocator.dupe(u8, key),
            std.json.Value{ .string = try self.allocator.dupe(u8, value) },
        );
    }

    fn formatJsonLine(self: *FileSink, event: *const events.AuditEvent, filtered_metadata: ?std.json.Value) ![]const u8 {
        var json_obj = std.json.ObjectMap.init(self.allocator);
        defer {
            var iter = json_obj.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(self.allocator, entry.value_ptr.*);
            }
            json_obj.deinit();
        }

        var ts_buf: [64]u8 = undefined;
        const timestamp = self.clock.nowRfc3339(&ts_buf);
        try self.putField(&json_obj, "ts", timestamp);

        try self.putField(&json_obj, "category", event.category);
        try self.putField(&json_obj, "action", event.action);
        try self.putField(&json_obj, "outcome", event.outcome.toString());
        try self.putField(&json_obj, "severity", @tagName(event.severity));
        try self.putField(&json_obj, "actor_id", event.actor_id);

        if (event.subject_id) |subject_id| {
            try self.putField(&json_obj, "subject_id", subject_id);
        }

        if (event.request_id) |request_id| {
            try self.putField(&json_obj, "request_id", request_id);
        }

        if (event.session_id) |session_id| {
            try self.putField(&json_obj, "session_id", session_id);
        }

        if (event.source_ip) |source_ip| {
            try self.putField(&json_obj, "source_ip", source_ip);
        }

        if (event.trace_id) |trace_id| {
            try self.putField(&json_obj, "trace_id", &trace_id);
        }

        if (event.span_id) |span_id| {
            try self.putField(&json_obj, "span_id", &span_id);
        }

        if (filtered_metadata) |metadata| {
            if (metadata == .object) {
                var iter = metadata.object.iterator();
                while (iter.next()) |entry| {
                    // Free any existing entry with the same key to avoid leaks
                    if (json_obj.fetchSwapRemove(entry.key_ptr.*)) |removed| {
                        self.allocator.free(removed.key);
                        json_util.freeJsonValue(self.allocator, removed.value);
                    }
                    const key = try self.allocator.dupe(u8, entry.key_ptr.*);
                    const value = try json_util.cloneJsonValue(self.allocator, entry.value_ptr.*);
                    try json_obj.put(key, value);
                }
            }
        }

        const json_value = std.json.Value{ .object = json_obj };
        return std.json.Stringify.valueAlloc(self.allocator, json_value, .{});
    }

    fn checkRotation(self: *FileSink, additional_size: usize) !void {
        if (self.current_size + additional_size > self.config.max_bytes) {
            try self.rotateFile();
        }
    }

    fn rotateFile(self: *FileSink) !void {
        if (self.current_file) |file| {
            file.close();
            self.current_file = null;
        }

        var i: u32 = self.config.backup_count;
        while (i > 1) : (i -= 1) {
            const old_backup_path = try std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ self.config.path, i - 1 });
            defer self.allocator.free(old_backup_path);

            const new_backup_path = try std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ self.config.path, i });
            defer self.allocator.free(new_backup_path);

            std.fs.cwd().rename(old_backup_path, new_backup_path) catch |err| {
                log.warn("audit file rotation failed: {s}", .{@errorName(err)});
            };
        }

        if (self.config.backup_count > 0) {
            const backup_path = try std.fmt.allocPrint(self.allocator, "{s}.1", .{self.config.path});
            defer self.allocator.free(backup_path);
            std.fs.cwd().rename(self.config.path, backup_path) catch |err| {
                log.warn("audit file rotation failed: {s}", .{@errorName(err)});
            };
        }

        try self.openCurrentFile();
    }

    fn openCurrentFile(self: *FileSink) !void {
        if (std.mem.indexOf(u8, self.config.path, "..") != null) {
            return error.PathTraversalRejected;
        }

        if (std.fs.path.dirname(self.config.path)) |dir_path| {
            std.fs.cwd().makePath(dir_path) catch |err| {
                log.warn("audit file rotation failed: {s}", .{@errorName(err)});
            };
        }

        self.current_file = try std.fs.cwd().createFile(self.config.path, .{ .truncate = false });

        if (self.current_file) |file| {
            const stat = try file.stat();
            self.current_size = stat.size;

            if (builtin.os.tag != .windows) {
                try file.chmod(0o640);
            }
        }
    }
};

test "file sink rotation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const test_dir = "zig-out/tmp/test-logs";
    std.fs.cwd().makePath(test_dir) catch {};
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 512,
        .backup_count = 2,
    };

    const sink = try FileSink.init(allocator, file_config, clock);
    defer sink.deinit();

    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        const event = events.AuditEvent{
            .category = "test",
            .action = "rotation",
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

        try sink.write(&event, null);
    }

    const backup1_path = test_dir ++ "/audit.log.1";
    const backup1_exists = blk: {
        std.fs.cwd().access(backup1_path, .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(backup1_exists);
}
