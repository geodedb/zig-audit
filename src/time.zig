// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub const Clock = struct {
    context: *anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        nowMs: *const fn (context: *anyopaque) i128,
        nowRfc3339: *const fn (context: *anyopaque, buf: []u8) []const u8,
    };

    pub fn nowMs(self: Clock) i128 {
        return self.vtable.nowMs(self.context);
    }

    pub fn nowRfc3339(self: Clock, buf: []u8) []const u8 {
        return self.vtable.nowRfc3339(self.context, buf);
    }
};

/// Format a millisecond-precision UTC timestamp as an RFC 3339 string.
/// Shared implementation used by both SystemClock and FixedClock.
pub fn formatRfc3339(ts_ms: i128, buf: []u8) []const u8 {
    const seconds = @divTrunc(ts_ms, 1000);
    const millis = @mod(ts_ms, 1000);
    const millis_u32: u32 = @intCast(@as(i64, @intCast(millis)));

    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        millis_u32,
    }) catch "";
}

pub const SystemClock = struct {
    const vtable = Clock.VTable{
        .nowMs = nowMsImpl,
        .nowRfc3339 = nowRfc3339Impl,
    };

    pub fn clock(self: *SystemClock) Clock {
        return Clock{ .context = @ptrCast(self), .vtable = &vtable };
    }

    fn nowMsImpl(_: *anyopaque) i128 {
        return std.time.milliTimestamp();
    }

    fn nowRfc3339Impl(_: *anyopaque, buf: []u8) []const u8 {
        return formatRfc3339(std.time.milliTimestamp(), buf);
    }
};

pub const FixedClock = struct {
    fixed_time_ms: i128,

    const vtable = Clock.VTable{
        .nowMs = nowMsImpl,
        .nowRfc3339 = nowRfc3339Impl,
    };

    pub fn init(time_ms: i128) FixedClock {
        return FixedClock{ .fixed_time_ms = time_ms };
    }

    pub fn clock(self: *FixedClock) Clock {
        return Clock{ .context = @ptrCast(self), .vtable = &vtable };
    }

    fn nowMsImpl(context: *anyopaque) i128 {
        const self: *FixedClock = @ptrCast(@alignCast(context));
        return self.fixed_time_ms;
    }

    fn nowRfc3339Impl(context: *anyopaque, buf: []u8) []const u8 {
        const self: *FixedClock = @ptrCast(@alignCast(context));
        return formatRfc3339(self.fixed_time_ms, buf);
    }
};

pub const IdGen = struct {
    context: *anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        traceId: *const fn (ptr: *anyopaque, buf: *[32]u8) void,
        spanId: *const fn (ptr: *anyopaque, buf: *[16]u8) void,
        requestId: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) []const u8,
    };

    pub fn traceId(self: IdGen, buf: *[32]u8) void {
        return self.vtable.traceId(self.context, buf);
    }

    pub fn spanId(self: IdGen, buf: *[16]u8) void {
        return self.vtable.spanId(self.context, buf);
    }

    pub fn requestId(self: IdGen, allocator: std.mem.Allocator) []const u8 {
        return self.vtable.requestId(self.context, allocator);
    }
};

pub const SystemIdGen = struct {
    rng: std.Random.DefaultPrng,

    const vtable = IdGen.VTable{
        .traceId = traceIdImpl,
        .spanId = spanIdImpl,
        .requestId = requestIdImpl,
    };

    pub fn init() SystemIdGen {
        var seed_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&seed_bytes);
        return SystemIdGen{
            .rng = std.Random.DefaultPrng.init(@bitCast(seed_bytes)),
        };
    }

    pub fn idGen(self: *SystemIdGen) IdGen {
        return IdGen{ .context = @ptrCast(self), .vtable = &vtable };
    }

    fn traceIdImpl(ptr: *anyopaque, buf: *[32]u8) void {
        const self: *SystemIdGen = @ptrCast(@alignCast(ptr));
        var bytes: [16]u8 = undefined;
        self.rng.random().bytes(&bytes);
        buf.* = std.fmt.bytesToHex(bytes, .lower);
    }

    fn spanIdImpl(ptr: *anyopaque, buf: *[16]u8) void {
        const self: *SystemIdGen = @ptrCast(@alignCast(ptr));
        var bytes: [8]u8 = undefined;
        self.rng.random().bytes(&bytes);
        buf.* = std.fmt.bytesToHex(bytes, .lower);
    }

    fn requestIdImpl(ptr: *anyopaque, allocator: std.mem.Allocator) []const u8 {
        const self: *SystemIdGen = @ptrCast(@alignCast(ptr));
        const id = self.rng.random().int(u64);
        return std.fmt.allocPrint(allocator, "req-{x}", .{id}) catch "";
    }
};

pub const FixedIdGen = struct {
    trace_id: [32]u8,
    span_id: [16]u8,
    request_id: []const u8,

    const vtable = IdGen.VTable{
        .traceId = traceIdImpl,
        .spanId = spanIdImpl,
        .requestId = requestIdImpl,
    };

    pub fn init(trace_id: [32]u8, span_id: [16]u8, request_id: []const u8) FixedIdGen {
        return FixedIdGen{
            .trace_id = trace_id,
            .span_id = span_id,
            .request_id = request_id,
        };
    }

    pub fn idGen(self: *FixedIdGen) IdGen {
        return IdGen{ .context = @ptrCast(self), .vtable = &vtable };
    }

    fn traceIdImpl(ptr: *anyopaque, buf: *[32]u8) void {
        const self: *FixedIdGen = @ptrCast(@alignCast(ptr));
        @memcpy(buf, &self.trace_id);
    }

    fn spanIdImpl(ptr: *anyopaque, buf: *[16]u8) void {
        const self: *FixedIdGen = @ptrCast(@alignCast(ptr));
        @memcpy(buf, &self.span_id);
    }

    fn requestIdImpl(ptr: *anyopaque, allocator: std.mem.Allocator) []const u8 {
        const self: *FixedIdGen = @ptrCast(@alignCast(ptr));
        return allocator.dupe(u8, self.request_id) catch "";
    }
};

// Test timestamp for deterministic testing: 2025-01-01T00:00:00Z
pub const TEST_TIMESTAMP_MS: i128 = 1735689600000;
pub const TEST_TRACE_ID = "11111111111111111111111111111111".*;
pub const TEST_SPAN_ID = "2222222222222222".*;
pub const TEST_REQUEST_ID = "req-abc123";

fn isHexString(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

test "SystemIdGen produces valid 32-hex trace IDs via vtable dispatch" {
    var gen = SystemIdGen.init();
    const id_gen = gen.idGen();

    var buf: [32]u8 = undefined;
    id_gen.traceId(&buf);

    // Must be exactly 32 hex characters
    try std.testing.expect(isHexString(&buf));
    try std.testing.expectEqual(@as(usize, 32), buf.len);
}

test "SystemIdGen produces valid 16-hex span IDs via vtable dispatch" {
    var gen = SystemIdGen.init();
    const id_gen = gen.idGen();

    var buf: [16]u8 = undefined;
    id_gen.spanId(&buf);

    // Must be exactly 16 hex characters
    try std.testing.expect(isHexString(&buf));
    try std.testing.expectEqual(@as(usize, 16), buf.len);
}

test "SystemIdGen produces valid request IDs via vtable dispatch" {
    var gen = SystemIdGen.init();
    const id_gen = gen.idGen();

    const req_id = id_gen.requestId(std.testing.allocator);
    defer std.testing.allocator.free(req_id);

    // Request IDs start with "req-"
    try std.testing.expect(std.mem.startsWith(u8, req_id, "req-"));
    try std.testing.expect(req_id.len > 4);
}

test "FixedIdGen returns exact values via vtable dispatch" {
    const trace = "aabbccdd11223344aabbccdd11223344".*;
    const span = "aabbccdd11223344".*;
    const req = "req-fixed-test";

    var gen = FixedIdGen.init(trace, span, req);
    const id_gen = gen.idGen();

    var trace_buf: [32]u8 = undefined;
    id_gen.traceId(&trace_buf);
    try std.testing.expectEqualStrings(&trace, &trace_buf);

    var span_buf: [16]u8 = undefined;
    id_gen.spanId(&span_buf);
    try std.testing.expectEqualStrings(&span, &span_buf);

    const req_id = id_gen.requestId(std.testing.allocator);
    defer std.testing.allocator.free(req_id);
    try std.testing.expectEqualStrings(req, req_id);
}

test "SystemIdGen produces different trace IDs on consecutive calls" {
    var gen = SystemIdGen.init();
    const id_gen = gen.idGen();

    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    id_gen.traceId(&buf1);
    id_gen.traceId(&buf2);

    // Two consecutive calls should produce different IDs
    try std.testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}

test "formatRfc3339 formats known timestamp correctly" {
    var buf: [64]u8 = undefined;
    // TEST_TIMESTAMP_MS = 1735689600000 = 2025-01-01T00:00:00.000Z
    const result = formatRfc3339(TEST_TIMESTAMP_MS, &buf);
    try std.testing.expectEqualStrings("2025-01-01T00:00:00.000Z", result);
}

test "formatRfc3339 preserves sub-second precision" {
    var buf: [64]u8 = undefined;
    // 2025-01-01T00:00:01.456Z
    const result = formatRfc3339(TEST_TIMESTAMP_MS + 1456, &buf);
    try std.testing.expectEqualStrings("2025-01-01T00:00:01.456Z", result);
}

test "formatRfc3339 agrees with FixedClock output" {
    var buf_shared: [64]u8 = undefined;
    var buf_clock: [64]u8 = undefined;

    const shared_result = formatRfc3339(TEST_TIMESTAMP_MS, &buf_shared);

    var fixed_clock = FixedClock.init(TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();
    const clock_result = clock.nowRfc3339(&buf_clock);

    try std.testing.expectEqualStrings(shared_result, clock_result);
}
