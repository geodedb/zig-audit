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

/// PR-012: maximum number of queued lines the worker coalesces into a
/// single buffered write between channel receives.
const DRAIN_BATCH_CAP = 256;

/// One-time-per-process flag for the absolute-path-without-jail notice in
/// `validatePath` (rotation re-validates, so without this the message would
/// repeat on every rotation).
var abs_path_no_jail_noticed = std.atomic.Value(bool).init(false);

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
    dropped_count: std.atomic.Value(u64) = .init(0),

    pub fn init(allocator: std.mem.Allocator, file_config: config.FileSinkConfig, clock: time.Clock) !*FileSink {
        const sink = try allocator.create(FileSink);
        errdefer allocator.destroy(sink);
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
        // Runs before the destroy above if openCurrentFile/spawn fail (ADV-2).
        errdefer sink.ch.deinit();

        if (file_config.enabled) {
            errdefer if (sink.current_file) |file| file.close(systemIo());
            try sink.openCurrentFile();
            // daemon: one persistent consumer per file sink. Same rationale as
            // syslog.zig — long-lived ring-buffer consumer, not pool work.
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

    /// Total events/error messages discarded because the channel was full.
    pub fn getDroppedCount(self: *FileSink) u64 {
        return self.dropped_count.load(.monotonic);
    }

    /// Enqueue an owned line, surfacing channel-full as `.dropped` instead
    /// of silently discarding (GAP-041/A2). Frees `line` on drop, bumps the
    /// drop counter, and warns on the first drop and every 1000th after.
    fn enqueueLine(self: *FileSink, line: []const u8, what: []const u8) events.SendStatus {
        if (self.ch.trySend(line)) return .enqueued;

        self.allocator.free(line);
        const n = self.dropped_count.fetchAdd(1, .monotonic) + 1;
        if (n == 1 or n % 1000 == 0) {
            log.warn("file sink channel full; dropped {d} {s} so far", .{ n, what });
        }
        return .dropped;
    }

    /// Enqueue a formatted JSON line for the background worker to write.
    /// Returns immediately after enqueue — file I/O happens on the worker
    /// thread. Returns `.dropped` when the channel is full (the event is
    /// discarded and counted), `.enqueued` otherwise.
    pub fn write(self: *FileSink, event: *const events.AuditEvent, filtered_metadata: ?std.json.Value) !events.SendStatus {
        // A disabled sink accepts nothing and loses nothing.
        if (!self.config.enabled) return .enqueued;

        const json_line = try self.formatJsonLine(event, filtered_metadata);
        return self.enqueueLine(json_line, "audit events");
    }

    /// Enqueue an error message for the background worker to write.
    /// Same drop semantics as `write`.
    pub fn writeError(self: *FileSink, error_msg: []const u8) !events.SendStatus {
        if (!self.config.enabled) return .enqueued;

        var ts_buf: [64]u8 = undefined;
        const timestamp = self.clock.nowRfc3339(&ts_buf);

        var obj: std.json.ObjectMap = .empty;
        defer obj.deinit(self.allocator);
        try obj.put(self.allocator, "ts", std.json.Value{ .string = timestamp });
        try obj.put(self.allocator, "level", std.json.Value{ .string = "ERROR" });
        try obj.put(self.allocator, "msg", std.json.Value{ .string = error_msg });
        const json = try std.json.Stringify.valueAlloc(self.allocator, std.json.Value{ .object = obj }, .{});
        // PR-006a: the enqueued line owns its trailing newline so the worker
        // issues exactly one write per record.
        const error_line = try self.allocator.realloc(json, json.len + 1);
        error_line[error_line.len - 1] = '\n';

        return self.enqueueLine(error_line, "error messages");
    }

    /// Background worker: receives formatted lines from the channel and writes
    /// them to the file. Handles rotation and fsync. Exits when channel is
    /// closed and fully drained.
    ///
    /// PR-012: blocks for the first line, then opportunistically drains up to
    /// DRAIN_BATCH_CAP queued lines and writes them as one batch through a
    /// reusable buffer. Close-with-drain is preserved: receive() keeps
    /// returning items after close until the channel is empty.
    fn workerThread(self: *FileSink) void {
        var write_buf: std.ArrayList(u8) = .empty;
        defer write_buf.deinit(self.allocator);
        var batch: [DRAIN_BATCH_CAP][]const u8 = undefined;

        while (self.ch.receive()) |first| {
            batch[0] = first;
            var n: usize = 1;
            while (n < DRAIN_BATCH_CAP) : (n += 1) {
                batch[n] = self.ch.tryReceive() orelse break;
            }
            self.writeBatch(batch[0..n], &write_buf);
        }
    }

    /// Write one drained batch, consuming (freeing) every line.
    ///
    /// `.per_event` keeps its durability contract — one write and one fsync
    /// per LINE — so it never coalesces. `.periodic`/`.none` coalesce the
    /// batch into buffered writes and make a single fsync decision per batch
    /// (periodic still counts RECORDS, not batches). Write failures are
    /// logged per line/batch, matching the previous per-line behavior.
    fn writeBatch(self: *FileSink, lines: []const []const u8, write_buf: *std.ArrayList(u8)) void {
        if (self.config.sync_mode == .per_event) {
            for (lines) |line| {
                defer self.allocator.free(line);
                self.writeLine(line) catch |err| {
                    log.warn("file sink write error: {s}", .{@errorName(err)});
                };
            }
            return;
        }

        write_buf.clearRetainingCapacity();
        for (lines) |line| {
            defer self.allocator.free(line);
            self.bufferLine(write_buf, line) catch |err| {
                log.warn("file sink write error: {s}", .{@errorName(err)});
            };
        }
        self.flushBuffer(write_buf) catch |err| {
            log.warn("file sink write error: {s}", .{@errorName(err)});
        };

        if (self.current_file) |file| {
            self.maybeFsyncBatch(file, lines.len) catch |err| {
                log.warn("file sink fsync error: {s}", .{@errorName(err)});
            };
        }
    }

    /// Append one line to the reusable batch buffer. When the bytes already
    /// on disk plus the buffered bytes plus this line would exceed max_bytes,
    /// flush the buffer first (so rotation sees an accurate current_size),
    /// then rotate if this line still does not fit (QR-009 semantics:
    /// rotation happens BEFORE the write that would exceed max_bytes).
    fn bufferLine(self: *FileSink, write_buf: *std.ArrayList(u8), line: []const u8) !void {
        if (self.current_size + write_buf.items.len + line.len > self.config.max_bytes) {
            try self.flushBuffer(write_buf);
            try self.checkRotation(line.len);
        }
        try write_buf.appendSlice(self.allocator, line);
    }

    /// Write the buffered bytes in one streaming write and clear the buffer,
    /// retaining its capacity for the next batch.
    fn flushBuffer(self: *FileSink, write_buf: *std.ArrayList(u8)) !void {
        if (write_buf.items.len == 0) return;
        defer write_buf.clearRetainingCapacity();
        if (self.current_file) |file| {
            try file.writeStreamingAll(systemIo(), write_buf.items);
            self.current_size += write_buf.items.len;
        }
    }

    /// Per-batch fsync decision for `.periodic`/`.none`. Periodic counting
    /// stays per-record: sync_interval means "every N records", so the whole
    /// batch length is added before the threshold check. `.per_event` never
    /// reaches here (writeBatch handles it per line via writeLine/maybeFsync).
    fn maybeFsyncBatch(self: *FileSink, file: std.Io.File, batch_len: usize) !void {
        switch (self.config.sync_mode) {
            .per_event => unreachable,
            .periodic => {
                // Saturating add: batch_len is at most DRAIN_BATCH_CAP, but a
                // maxInt sync_interval must not let the counter overflow.
                self.writes_since_sync +|= @intCast(@min(batch_len, std.math.maxInt(u32)));
                if (self.writes_since_sync >= self.config.sync_interval) {
                    try file.sync(systemIo());
                    self.writes_since_sync = 0;
                }
            },
            .none => {},
        }
    }

    /// Write a single line to the current file, handling rotation and fsync.
    /// Called only from the worker thread — no mutex needed.
    /// PR-006a: `line` includes its trailing newline, so `line.len` is the
    /// exact on-disk size and one `writeStreamingAll` covers the record.
    fn writeLine(self: *FileSink, line: []const u8) !void {
        // QR-009: rotation must trigger BEFORE any write that would push the
        // file past max_bytes. The newline is part of line.len now.
        try self.checkRotation(line.len);

        if (self.current_file) |file| {
            const io = systemIo();
            try file.writeStreamingAll(io, line);
            self.current_size += line.len;
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

        // GAP-046/A7: the event's own timestamp is authoritative — audit()
        // stamps ts_unix_ms before fan-out. The clock fallback only covers
        // direct public-formatter calls with unstamped (ts == 0) events.
        var ts_buf: [64]u8 = undefined;
        const timestamp = if (event.ts_unix_ms != 0)
            time.formatRfc3339(event.ts_unix_ms, &ts_buf)
        else
            self.clock.nowRfc3339(&ts_buf);
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
        const json = try std.json.Stringify.valueAlloc(self.allocator, json_value, .{});
        // PR-006a: the line owns its trailing newline so the worker issues
        // exactly one write per record.
        const line = try self.allocator.realloc(json, json.len + 1);
        line[line.len - 1] = '\n';
        return line;
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

    /// Validate `config.path` against traversal and the optional jail.
    ///
    /// Rejects any path containing a `..` COMPONENT (component-wise check —
    /// a filename like `my..app.log` is fine). When `allowed_base_dir` is
    /// set, both paths are lexically resolved and the target must sit under
    /// the base (string prefix + separator boundary). Symlinked parents are
    /// NOT resolved — see the doc comment on
    /// `config.FileSinkConfig.allowed_base_dir`.
    fn validatePath(self: *FileSink) !void {
        var it = std.fs.path.componentIterator(self.config.path);
        while (it.next()) |component| {
            if (std.mem.eql(u8, component.name, "..")) {
                return error.PathTraversalRejected;
            }
        }

        if (self.config.allowed_base_dir) |base| {
            const resolved_path = try std.fs.path.resolve(self.allocator, &.{self.config.path});
            defer self.allocator.free(resolved_path);
            const resolved_base = try std.fs.path.resolve(self.allocator, &.{base});
            defer self.allocator.free(resolved_base);

            if (!isUnderBase(resolved_base, resolved_path)) {
                return error.PathOutsideAllowedBase;
            }
        } else if (std.fs.path.isAbsolute(self.config.path)) {
            // Absolute log paths (e.g. /var/log/audit.log) with no jail are
            // the normal operator deployment — config is operator-trusted by
            // design. Note it once per process at info (not warn: this is
            // not a fault) so the policy is visible without rotation noise.
            if (!abs_path_no_jail_noticed.swap(true, .monotonic)) {
                log.info(
                    "file sink writes to absolute path '{s}' with no allowed_base_dir confinement configured",
                    .{self.config.path},
                );
            }
        }
    }

    /// True when `target` is lexically under (or equal to) `base`. Both
    /// arguments must already be lexically resolved. A bare prefix match is
    /// not enough — the next byte after the prefix must be a path separator
    /// so `/jail` does not admit `/jailbreak/x.log`.
    fn isUnderBase(base: []const u8, target: []const u8) bool {
        // An empty base admits nothing (and must not read base[base.len-1]
        // below). parseConfig rejects "" already; this guards hand-built
        // configs and any future resolve() behavior change.
        if (base.len == 0) return false;
        if (!std.mem.startsWith(u8, target, base)) return false;
        if (target.len == base.len) return true;
        // A resolved base never has a trailing separator except the
        // filesystem root itself ("/" or e.g. "C:\").
        if (std.fs.path.isSep(base[base.len - 1])) return true;
        return std.fs.path.isSep(target[base.len]);
    }

    /// Test-only helper: builds a worker-less FileSink (no thread, no open
    /// file) with a 1-slot channel so drop/enqueue behavior is deterministic
    /// (nothing drains the channel). `pub` only because logger.zig's drop
    /// test constructs one across the file boundary — never use outside
    /// tests. Centralizes the struct literal so future field additions
    /// touch one place instead of every drop test.
    pub fn testInitWorkerless(allocator: std.mem.Allocator, file_config: config.FileSinkConfig, clock: time.Clock) !FileSink {
        comptime {
            if (!builtin.is_test) @compileError("testInitWorkerless is a test-only helper");
        }
        return .{
            .allocator = allocator,
            .config = file_config,
            .clock = clock,
            .current_file = null,
            .current_size = 0,
            .writes_since_sync = 0,
            .ch = try BoundedChannel([]const u8).init(allocator, 1),
            .thread = null,
            .dropped_count = .init(0),
        };
    }

    fn openCurrentFile(self: *FileSink) !void {
        try self.validatePath();

        const io = systemIo();
        const cwd = std.Io.Dir.cwd();

        if (std.fs.path.dirname(self.config.path)) |dir_path| {
            // createDirPath succeeds when the directory already exists
            // (see std.Io.Dir.createDirPathStatus), so any error here is
            // real and must propagate instead of being swallowed.
            try cwd.createDirPath(io, dir_path);
        }

        // GAP-063: apply the restrictive mode AT creation via
        // CreateFileOptions.permissions so a freshly created file never
        // exists with broader permissions (the old create-then-chmod
        // sequence left a umask-dependent window). umask can only remove
        // bits from the creation mode, never add them.
        self.current_file = try cwd.createFile(io, self.config.path, .{
            .truncate = false,
            .permissions = if (builtin.os.tag == .windows)
                .default_file
            else
                std.Io.File.Permissions.fromMode(0o640),
        });

        if (self.current_file) |file| {
            const stat = try file.stat(io);
            self.current_size = stat.size;

            if (builtin.os.tag != .windows) {
                // Normalize to exactly 0o640: covers pre-existing files
                // (creation permissions are ignored when the file already
                // exists) and umask-subtracted bits on fresh files. Safe
                // post-hoc now — the creation mode above is already
                // restrictive, so there is no permissive window.
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

    // Unique dir: tests/integration.zig uses zig-out/tmp/test-logs and the
    // two test binaries run in parallel — sharing the dir races its
    // deleteTree against this test's rotation (flaky missing .1 backup).
    const test_dir = "zig-out/tmp/test-fs-rotation";
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

        _ = try sink.write(&event, null);
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

test "QR-009: rotation size accounting includes the trailing newline" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();
    const test_dir = "zig-out/tmp/test-qr009-rotate";
    defer cwd.deleteTree(io, test_dir) catch {};

    // Worker-less sink: call writeLine directly for determinism.
    var sink = try FileSink.testInitWorkerless(allocator, .{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 10,
        .backup_count = 1,
    }, fixed_clock.clock());
    defer {
        if (sink.current_file) |file| file.close(io);
        sink.ch.deinit();
    }

    try sink.openCurrentFile();
    try testing.expectEqual(@as(u64, 0), sink.current_size);

    // Lines carry their own trailing newline (PR-006a). 6 bytes on disk;
    // fits in max_bytes = 10.
    try sink.writeLine("12345\n");
    try testing.expectEqual(@as(u64, 6), sink.current_size);

    // current_size (6) + line.len (5, newline included) = 11 > 10.
    // Rotation must trigger BEFORE this write so the file never exceeds
    // max_bytes.
    try sink.writeLine("1234\n");
    try testing.expectEqual(@as(u64, 5), sink.current_size);

    // The pre-rotation file (6 bytes) must have been moved to the backup.
    const backup_stat = try cwd.statFile(io, test_dir ++ "/audit.log.1", .{});
    try testing.expectEqual(@as(u64, 6), backup_stat.size);
}

test "GAP-046/A7: formatJsonLine renders the event's own timestamp, not format-time now" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Clock frozen at TEST_TIMESTAMP_MS; the event is stamped 5 seconds
    // later. The rendered "ts" must be the EVENT's timestamp.
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);

    var sink = try FileSink.testInitWorkerless(allocator, .{
        .enabled = true,
        .path = "zig-out/tmp/test-gap046/audit.log",
        .max_bytes = 1024 * 1024,
        .backup_count = 0,
    }, fixed_clock.clock());
    defer sink.ch.deinit();

    const event = events.AuditEvent{
        .category = "test",
        .action = "event_ts",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS + 5000,
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

    const line = try sink.formatJsonLine(&event, null);
    defer allocator.free(line);

    try testing.expect(std.mem.indexOf(u8, line, "\"ts\":\"2025-01-01T00:00:05.000Z\"") != null);
    try testing.expect(std.mem.indexOf(u8, line, "2025-01-01T00:00:00.000Z") == null);
}

test "GAP-046/A7: formatJsonLine falls back to the clock for unstamped events" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);

    var sink = try FileSink.testInitWorkerless(allocator, .{
        .enabled = true,
        .path = "zig-out/tmp/test-gap046-fb/audit.log",
        .max_bytes = 1024 * 1024,
        .backup_count = 0,
    }, fixed_clock.clock());
    defer sink.ch.deinit();

    const event = events.AuditEvent{
        .category = "test",
        .action = "event_ts",
        .outcome = .success,
        .ts_unix_ms = 0, // unstamped: direct formatter call without audit()
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

    const line = try sink.formatJsonLine(&event, null);
    defer allocator.free(line);

    try testing.expect(std.mem.indexOf(u8, line, "\"ts\":\"2025-01-01T00:00:00.000Z\"") != null);
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

    _ = try sink.write(&event, null);

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
        _ = try sink.write(&event, null);
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

test "PR-006a: on-disk content has exactly one newline per record and no blank lines" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-pr006a-newlines";
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

    const record_count = 5;
    var i: u32 = 0;
    while (i < record_count) : (i += 1) {
        const event = events.AuditEvent{
            .category = "test",
            .action = "newline_shape",
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
        _ = try sink.write(&event, null);
    }
    // An error record goes through the same enqueue path and must keep the
    // one-newline-per-record shape.
    _ = try sink.writeError("boom");

    sink.deinit();

    const content = try cwd.readFileAlloc(io, test_dir ++ "/audit.log", allocator, .limited(1048576));
    defer allocator.free(content);

    // Exactly one '\n' per record, file ends with a newline, no blank lines.
    try testing.expectEqual(@as(usize, record_count + 1), std.mem.count(u8, content, "\n"));
    try testing.expect(content.len > 0 and content[content.len - 1] == '\n');
    try testing.expect(content[0] != '\n');
    try testing.expect(std.mem.indexOf(u8, content, "\n\n") == null);
}

test "PR-012: 500-write burst drains fully through the worker (close-with-drain)" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-pr012-burst";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 64 * 1024 * 1024,
        .backup_count = 0,
        .sync_mode = .none,
    };

    const sink = try FileSink.init(allocator, file_config, clock);

    const burst = 500;
    var i: u32 = 0;
    while (i < burst) : (i += 1) {
        const event = events.AuditEvent{
            .category = "test",
            .action = "burst",
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
        try testing.expectEqual(events.SendStatus.enqueued, try sink.write(&event, null));
    }

    // deinit closes the channel; the worker must drain everything queued
    // (including mid-batch) before exiting.
    sink.deinit();

    const content = try cwd.readFileAlloc(io, test_dir ++ "/audit.log", allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(content);
    var line_count: u32 = 0;
    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        if (line.len > 0) line_count += 1;
    }
    try testing.expectEqual(@as(u32, burst), line_count);
}

test "PR-012: mid-batch rotations lose no records (50-line burst across backups)" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-pr012-midbatch-rotate";
    cwd.createDirPath(io, test_dir) catch {};
    defer cwd.deleteTree(io, test_dir) catch {};

    // max_bytes small enough that a 50-line burst (each record ~140 bytes)
    // forces many rotations while the worker drains a single batch.
    // backup_count is high enough that no backup is ever shifted off the end.
    const backup_count = 25;
    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 512,
        .backup_count = backup_count,
        .sync_mode = .none,
    };

    const sink = try FileSink.init(allocator, file_config, clock);

    const burst = 50;
    var i: u32 = 0;
    while (i < burst) : (i += 1) {
        const event = events.AuditEvent{
            .category = "test",
            .action = "mid_batch_rotation",
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
        try testing.expectEqual(events.SendStatus.enqueued, try sink.write(&event, null));
    }

    sink.deinit();

    // Count records across the live file plus every backup; nothing may be
    // lost or duplicated by rotation mid-batch, and no file may exceed
    // max_bytes.
    var total_lines: u32 = 0;
    var rotated_files: u32 = 0;
    var path_buf: [256]u8 = undefined;
    var file_idx: u32 = 0;
    while (file_idx <= backup_count) : (file_idx += 1) {
        const path = if (file_idx == 0)
            test_dir ++ "/audit.log"
        else
            try std.fmt.bufPrint(&path_buf, "{s}/audit.log.{d}", .{ test_dir, file_idx });

        const content = cwd.readFileAlloc(io, path, allocator, .limited(1048576)) catch continue;
        defer allocator.free(content);
        if (file_idx > 0) rotated_files += 1;

        try testing.expect(content.len <= file_config.max_bytes);
        var iter = std.mem.splitScalar(u8, content, '\n');
        while (iter.next()) |line| {
            if (line.len > 0) total_lines += 1;
        }
    }

    try testing.expectEqual(@as(u32, burst), total_lines);
    // The burst must actually have forced multiple rotations.
    try testing.expect(rotated_files >= 2);
}

test "GAP-063: fresh audit file has mode 0o640" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-gap063-mode";
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/audit.log",
        .max_bytes = 1024,
        .backup_count = 0,
    };

    const sink = try FileSink.init(allocator, file_config, clock);
    defer sink.deinit();

    // The restrictive mode is applied AT creation (no umask-window race
    // between createFile and a later setPermissions), so the file must
    // already be exactly 0o640 the moment init returns.
    const file = try cwd.openFile(io, file_config.path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    try testing.expectEqual(@as(std.posix.mode_t, 0o640), stat.permissions.toMode() & 0o777);
}

test "GAP-043: path with a '..' component is rejected" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = "zig-out/tmp/test-gap043-trav/../escape/audit.log",
        .max_bytes = 1024,
        .backup_count = 0,
    };

    try testing.expectError(error.PathTraversalRejected, FileSink.init(allocator, file_config, clock));
}

test "GAP-043: filename containing '..' substring is accepted (false positive fix)" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-gap043-fp";
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/my..app.log",
        .max_bytes = 1024,
        .backup_count = 0,
    };

    // "my..app.log" contains ".." as a substring but not as a path
    // component — it must be accepted.
    const sink = try FileSink.init(allocator, file_config, clock);
    sink.deinit();
}

test "GAP-043: allowed_base_dir rejects path outside the base" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = "zig-out/tmp/test-gap043-outside/x.log",
        .max_bytes = 1024,
        .backup_count = 0,
        .allowed_base_dir = "zig-out/tmp/test-gap043-jail",
    };

    try testing.expectError(error.PathOutsideAllowedBase, FileSink.init(allocator, file_config, clock));
}

test "GAP-043: allowed_base_dir accepts path inside the base" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-gap043-jail";
    defer cwd.deleteTree(io, test_dir) catch {};

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = test_dir ++ "/sub/x.log",
        .max_bytes = 1024,
        .backup_count = 0,
        .allowed_base_dir = test_dir,
    };

    const sink = try FileSink.init(allocator, file_config, clock);
    sink.deinit();
}

test "GAP-043: allowed_base_dir rejects prefix-only match (jail vs jailbreak)" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = "zig-out/tmp/test-gap043-jailbreak/x.log",
        .max_bytes = 1024,
        .backup_count = 0,
        .allowed_base_dir = "zig-out/tmp/test-gap043-jail",
    };

    // "...jailbreak" begins with "...jail" as a string prefix but is NOT
    // under it — the separator boundary check must reject this.
    try testing.expectError(error.PathOutsideAllowedBase, FileSink.init(allocator, file_config, clock));
}

test "GAP-043: isUnderBase returns false for empty base" {
    const testing = std.testing;
    // Defensive guard: std.fs.path.resolve never returns "" today (it
    // yields "." for empty input), but an empty base must never be
    // treated as "everything is under it" — and must never read
    // base[base.len - 1] out of bounds.
    try testing.expect(!FileSink.isUnderBase("", "/var/log/audit.log"));
    try testing.expect(!FileSink.isUnderBase("", "relative/x.log"));
    try testing.expect(!FileSink.isUnderBase("", ""));
}

test "GAP-043: empty allowed_base_dir never admits any path" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = "zig-out/tmp/test-gap043-empty-base/x.log",
        .max_bytes = 1024,
        .backup_count = 0,
        .allowed_base_dir = "",
    };

    // parseConfig rejects "" with error.InvalidConfig; a hand-built config
    // that bypasses parsing must still fail closed at init.
    try testing.expectError(error.PathOutsideAllowedBase, FileSink.init(allocator, file_config, clock));
}

test "GAP-043: absolute path with no allowed_base_dir is permitted (documented policy)" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const io = systemIo();
    const cwd = std.Io.Dir.cwd();

    const test_dir = "zig-out/tmp/test-gap043-abs";
    defer cwd.deleteTree(io, test_dir) catch {};

    // Resolve the test path to a real ABSOLUTE path under zig-out/tmp.
    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);
    const abs_path = try std.fs.path.resolve(allocator, &.{ cwd_path, test_dir, "audit.log" });
    defer allocator.free(abs_path);
    try testing.expect(std.fs.path.isAbsolute(abs_path));

    // Operator-trusted config: absolute log paths (e.g. /var/log/audit.log)
    // are the normal deployment. With no jail configured, init must
    // SUCCEED — this pins the documented policy (the sink emits a one-time
    // info notice instead of refusing).
    const file_config = config.FileSinkConfig{
        .enabled = true,
        .path = abs_path,
        .max_bytes = 1024,
        .backup_count = 0,
    };

    const sink = try FileSink.init(allocator, file_config, clock);
    sink.deinit();
}

test "GAP-041: write returns .dropped and counts when channel is full" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);

    // Worker-less construction: the 1-slot channel stays full
    // deterministically (nothing drains it).
    var sink = try FileSink.testInitWorkerless(allocator, .{
        .enabled = true,
        .path = "zig-out/tmp/test-gap041-drop/audit.log",
        .max_bytes = 1024 * 1024,
        .backup_count = 0,
    }, fixed_clock.clock());
    defer {
        while (sink.ch.tryReceive()) |msg| {
            allocator.free(msg);
        }
        sink.ch.deinit();
    }

    // Fill the single slot so the next enqueue must drop.
    const dummy = try allocator.dupe(u8, "occupant");
    try testing.expect(sink.ch.trySend(dummy));

    const event = events.AuditEvent{
        .category = "test",
        .action = "drop",
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

    try testing.expectEqual(@as(u64, 0), sink.getDroppedCount());
    const status = try sink.write(&event, null);
    try testing.expectEqual(events.SendStatus.dropped, status);
    try testing.expectEqual(@as(u64, 1), sink.getDroppedCount());

    const err_status = try sink.writeError("boom");
    try testing.expectEqual(events.SendStatus.dropped, err_status);
    try testing.expectEqual(@as(u64, 2), sink.getDroppedCount());
}

test "GAP-041: write returns .enqueued when the channel has room" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);

    var sink = try FileSink.testInitWorkerless(allocator, .{
        .enabled = true,
        .path = "zig-out/tmp/test-gap041-enq/audit.log",
        .max_bytes = 1024 * 1024,
        .backup_count = 0,
    }, fixed_clock.clock());
    defer {
        while (sink.ch.tryReceive()) |msg| {
            allocator.free(msg);
        }
        sink.ch.deinit();
    }

    const event = events.AuditEvent{
        .category = "test",
        .action = "enqueue",
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

    const status = try sink.write(&event, null);
    try testing.expectEqual(events.SendStatus.enqueued, status);
    try testing.expectEqual(@as(u64, 0), sink.getDroppedCount());
}

test "SyncMode.fromString parses valid modes" {
    const testing = std.testing;
    try testing.expectEqual(config.SyncMode.per_event, try config.SyncMode.fromString("per_event"));
    try testing.expectEqual(config.SyncMode.periodic, try config.SyncMode.fromString("periodic"));
    try testing.expectEqual(config.SyncMode.none, try config.SyncMode.fromString("none"));
    try testing.expectError(error.InvalidSyncMode, config.SyncMode.fromString("invalid"));
}
