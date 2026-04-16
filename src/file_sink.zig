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
const BoundedChannel = @import("channel.zig").BoundedChannel;
const log = std.log.scoped(.audit);

const FILE_QUEUE_SIZE = 10000;

inline fn systemIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const FileSink = struct {
    allocator: std.mem.Allocator,
    config: config.FileSinkConfig,
    clock: time.Clock,
    current_file: ?std.Io.File,
    current_size: u64,
    writes_since_sync: u32,
    ch: BoundedChannel([]const u8),
    thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator, file_config: config.FileSinkConfig, clock: time.Clock) !*FileSink {
        const sink = try allocator.create(FileSink);
        sink.* = FileSink{
            .allocator = allocator,
            .config = file_config,
            .clock = clock,
            .current_file = null,
            .current_size = 0,
            .writes_since_sync = 0,
            .ch = try BoundedChannel([]const u8).init(allocator, FILE_QUEUE_SIZE),
            .thread = null,
        };

        if (file_config.enabled) {
            try sink.openCurrentFile();
            sink.thread = try std.Thread.spawn(.{}, workerThread, .{sink});
        }

        return sink;
    }

    pub fn deinit(self: *FileSink) void {
        // Close channel — worker drains remaining writes then exits
        self.ch.close();

        if (self.thread) |thread| {
            thread.join();
        }

        // Free any messages left after worker exit
        while (self.ch.tryReceive()) |msg| {
            self.allocator.free(msg);
        }
        self.ch.deinit();

        if (self.current_file) |file| {
            file.close(systemIo());
        }
        self.allocator.destroy(self);
    }

    /// Enqueue a formatted JSON line for the background worker to write.
    /// Returns immediately after enqueue — file I/O happens on the worker thread.
    pub fn write(self: *FileSink, event: *const events.AuditEvent, filtered_metadata: ?std.json.Value) !void {
        if (!self.config.enabled) return;

        const json_line = try self.formatJsonLine(event, filtered_metadata);

        if (!self.ch.trySend(json_line)) {
            log.warn("file sink channel full; dropping audit event", .{});
            self.allocator.free(json_line);
        }
    }

    /// Enqueue an error message for the background worker to write.
    pub fn writeError(self: *FileSink, error_msg: []const u8) !void {
        if (!self.config.enabled) return;

        var ts_buf: [64]u8 = undefined;
        const timestamp = self.clock.nowRfc3339(&ts_buf);

        var obj: std.json.ObjectMap = .empty;
        defer obj.deinit(self.allocator);
        try obj.put(self.allocator, "ts", std.json.Value{ .string = timestamp });
        try obj.put(self.allocator, "level", std.json.Value{ .string = "ERROR" });
        try obj.put(self.allocator, "msg", std.json.Value{ .string = error_msg });
        const error_line = try std.json.Stringify.valueAlloc(self.allocator, std.json.Value{ .object = obj }, .{});

        if (!self.ch.trySend(error_line)) {
            log.warn("file sink channel full; dropping error message", .{});
            self.allocator.free(error_line);
        }
    }

    /// Background worker: receives formatted lines from the channel and writes
    /// them to the file. Handles rotation and fsync. Exits when channel is
    /// closed and fully drained.
    fn workerThread(self: *FileSink) void {
        while (self.ch.receive()) |line| {
            defer self.allocator.free(line);
            self.writeLine(line) catch |err| {
                log.warn("file sink write error: {s}", .{@errorName(err)});
            };
        }
    }

    /// Write a single line to the current file, handling rotation and fsync.
    /// Called only from the worker thread — no mutex needed.
    fn writeLine(self: *FileSink, line: []const u8) !void {
        try self.checkRotation(line.len);

        if (self.current_file) |file| {
            const io = systemIo();
            try file.writeStreamingAll(io, line);
            try file.writeStreamingAll(io, "\n");
            self.current_size += line.len + 1;
            try self.maybeFsync(file);
        }
    }

    /// Perform fsync based on the configured sync_mode.
    fn maybeFsync(self: *FileSink, file: std.Io.File) !void {
        const io = systemIo();
        switch (self.config.sync_mode) {
            .per_event => try file.sync(io),
            .periodic => {
                self.writes_since_sync += 1;
                if (self.writes_since_sync >= self.config.sync_interval) {
                    try file.sync(io);
                    self.writes_since_sync = 0;
                }
            },
            .none => {},
        }
    }

    /// Insert a string field into a JSON object, duplicating both the key and value.
    /// This reduces repetition in formatJsonLine where every field follows the
    /// same `try obj.put(try dupe(key), .{ .string = try dupe(value) })` pattern.
    fn putField(self: *FileSink, obj: *std.json.ObjectMap, key: []const u8, value: []const u8) !void {
        try obj.put(
            self.allocator,
            try self.allocator.dupe(u8, key),
            std.json.Value{ .string = try self.allocator.dupe(u8, value) },
        );
    }

    fn formatJsonLine(self: *FileSink, event: *const events.AuditEvent, filtered_metadata: ?std.json.Value) ![]const u8 {
        var json_obj: std.json.ObjectMap = .empty;
        defer {
            var iter = json_obj.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(self.allocator, entry.value_ptr.*);
            }
            json_obj.deinit(self.allocator);
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
                    try json_obj.put(self.allocator, key, value);
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
        const io = systemIo();
        const cwd = std.Io.Dir.cwd();
        if (self.current_file) |file| {
            file.close(io);
            self.current_file = null;
        }

        var i: u32 = self.config.backup_count;
        while (i > 1) : (i -= 1) {
            const old_backup_path = try std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ self.config.path, i - 1 });
            defer self.allocator.free(old_backup_path);

            const new_backup_path = try std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ self.config.path, i });
            defer self.allocator.free(new_backup_path);

            cwd.rename(old_backup_path, cwd, new_backup_path, io) catch |err| {
                log.warn("audit file rotation failed: {s}", .{@errorName(err)});
            };
        }

        if (self.config.backup_count > 0) {
            const backup_path = try std.fmt.allocPrint(self.allocator, "{s}.1", .{self.config.path});
            defer self.allocator.free(backup_path);
            cwd.rename(self.config.path, cwd, backup_path, io) catch |err| {
                log.warn("audit file rotation failed: {s}", .{@errorName(err)});
            };
        }

        try self.openCurrentFile();
    }

    fn openCurrentFile(self: *FileSink) !void {
        if (std.mem.indexOf(u8, self.config.path, "..") != null) {
            return error.PathTraversalRejected;
        }

        const io = systemIo();
        const cwd = std.Io.Dir.cwd();

        if (std.fs.path.dirname(self.config.path)) |dir_path| {
            cwd.createDirPath(io, dir_path) catch |err| {
                log.warn("audit file rotation failed: {s}", .{@errorName(err)});
            };
        }

        self.current_file = try cwd.createFile(io, self.config.path, .{ .truncate = false });

        if (self.current_file) |file| {
            const stat = try file.stat(io);
            self.current_size = stat.size;

            if (builtin.os.tag != .windows) {
                try file.setPermissions(io, std.Io.File.Permissions.fromMode(0o640));
            }
        }
    }
};

test "file sink rotation" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-logs";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 512,
        .backup_count = 2,
    };

    const sink = try FileSink.init(allocator, file_config, clock);

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

    // deinit drains all queued writes to disk before closing
    sink.deinit();

    const backup1_path = test_dir ++ "/audit.log.1";
    const backup1_exists = blk: {
        cwd.access(io, backup1_path, .{}) catch break :blk false;
        break :blk true;
    };
    try testing.expect(backup1_exists);
}

test "FileSink sync_mode per_event is default" {
    const testing = std.testing;
    const file_config = config.FileSinkConfig{
        .enabled = false,
        .path = "/dev/null",
        .max_bytes = 1024,
        .backup_count = 0,
    };
    try testing.expectEqual(config.SyncMode.per_event, file_config.sync_mode);
    try testing.expectEqual(@as(u32, 100), file_config.sync_interval);
}

test "FileSink sync_mode none writes to file" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-sync-none";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 1048576,
        .backup_count = 0,
        .sync_mode = .none,
    };

    const sink = try FileSink.init(allocator, file_config, clock);

    const event = events.AuditEvent{
        .category = "test",
        .action = "sync_none",
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

    // deinit drains writes to disk
    sink.deinit();

    // Verify file has content
    const file = try cwd.openFile(io, test_dir ++ "/audit.log", .{});
    defer file.close(io);
    const stat = try file.stat(io);
    try testing.expect(stat.size > 0);
}

test "FileSink sync_mode periodic writes to file" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-sync-periodic";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 1048576,
        .backup_count = 0,
        .sync_mode = .periodic,
        .sync_interval = 5,
    };

    const sink = try FileSink.init(allocator, file_config, clock);

    const event = events.AuditEvent{
        .category = "test",
        .action = "sync_periodic",
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

    // Write 6 events (interval=5, so fsync fires once at event 5)
    var i: u32 = 0;
    while (i < 6) : (i += 1) {
        try sink.write(&event, null);
    }

    // deinit drains all queued writes
    sink.deinit();

    // Verify all 6 events written (each event is a JSON line)
    const content = try cwd.readFileAlloc(io, test_dir ++ "/audit.log", allocator, .limited(1048576));
    defer allocator.free(content);
    var line_count: u32 = 0;
    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        if (line.len > 0) line_count += 1;
    }
    try testing.expectEqual(@as(u32, 6), line_count);
}

test "SyncMode.fromString parses valid modes" {
    const testing = std.testing;
    try testing.expectEqual(config.SyncMode.per_event, try config.SyncMode.fromString("per_event"));
    try testing.expectEqual(config.SyncMode.periodic, try config.SyncMode.fromString("periodic"));
    try testing.expectEqual(config.SyncMode.none, try config.SyncMode.fromString("none"));
    try testing.expectError(error.InvalidSyncMode, config.SyncMode.fromString("invalid"));
}
