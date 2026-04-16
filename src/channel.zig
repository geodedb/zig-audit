// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Thread-safe bounded channel for producer-consumer communication.
//!
//! Provides a fixed-capacity MPSC (multiple-producer, single-consumer) channel
//! with blocking receive and close-with-drain semantics. Used by syslog and
//! file sink workers to replace hand-rolled RingBuffer + external Mutex patterns.

const std = @import("std");
const sync = @import("sync.zig");

pub fn BoundedChannel(comptime T: type) type {
    return struct {
        const Self = @This();

        buf: []T,
        head: usize,
        tail: usize,
        count: usize,
        mutex: sync.Mutex,
        not_empty: sync.Condition,
        closed: bool,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, capacity: usize) error{OutOfMemory}!Self {
            return Self{
                .buf = try allocator.alloc(T, capacity),
                .head = 0,
                .tail = 0,
                .count = 0,
                .mutex = .{},
                .not_empty = .{},
                .closed = false,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buf);
        }

        /// Try to send an item. Returns true if enqueued, false if channel is
        /// full or closed. Non-blocking.
        pub fn trySend(self: *Self, item: T) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.closed) return false;
            if (self.count >= self.buf.len) return false;

            self.buf[self.tail] = item;
            self.tail = (self.tail + 1) % self.buf.len;
            self.count += 1;

            self.not_empty.signal();
            return true;
        }

        /// Blocking receive. Returns null only when the channel is closed AND
        /// empty (drain complete). Blocks until an item is available or the
        /// channel is closed.
        pub fn receive(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.count == 0) {
                if (self.closed) return null;
                self.not_empty.wait(&self.mutex);
            }

            return self.popLocked();
        }

        /// Non-blocking receive. Returns null if empty (does not distinguish
        /// empty-and-open from empty-and-closed).
        pub fn tryReceive(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.count == 0) return null;
            return self.popLocked();
        }

        /// Close the channel. No more sends accepted. Wakes all blocked
        /// receivers so they can drain remaining items and then return null.
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.closed = true;
            self.not_empty.broadcast();
        }

        /// Returns the number of items currently buffered.
        pub fn len(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.count;
        }

        pub fn isClosed(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.closed;
        }

        /// Pop one item. Caller must hold the mutex.
        fn popLocked(self: *Self) T {
            const item = self.buf[self.head];
            self.head = (self.head + 1) % self.buf.len;
            self.count -= 1;
            return item;
        }
    };
}

// ── Tests ──────────────────────────────────────────────────────────────────

test "BoundedChannel: basic send and receive" {
    const allocator = std.testing.allocator;
    var ch = try BoundedChannel(u32).init(allocator, 4);
    defer ch.deinit();

    try std.testing.expect(ch.trySend(1));
    try std.testing.expect(ch.trySend(2));
    try std.testing.expect(ch.trySend(3));
    try std.testing.expect(ch.trySend(4));

    // Full — should reject
    try std.testing.expect(!ch.trySend(5));

    try std.testing.expectEqual(@as(u32, 1), ch.tryReceive().?);
    try std.testing.expectEqual(@as(u32, 2), ch.tryReceive().?);
    try std.testing.expectEqual(@as(u32, 3), ch.tryReceive().?);
    try std.testing.expectEqual(@as(u32, 4), ch.tryReceive().?);

    // Empty
    try std.testing.expect(ch.tryReceive() == null);
}

test "BoundedChannel: close rejects sends" {
    const allocator = std.testing.allocator;
    var ch = try BoundedChannel(u32).init(allocator, 4);
    defer ch.deinit();

    try std.testing.expect(ch.trySend(1));
    ch.close();
    try std.testing.expect(!ch.trySend(2));

    // Can still receive items that were sent before close
    try std.testing.expectEqual(@as(u32, 1), ch.tryReceive().?);
    try std.testing.expect(ch.tryReceive() == null);
}

test "BoundedChannel: blocking receive drains then returns null on close" {
    const allocator = std.testing.allocator;
    var ch = try BoundedChannel(u32).init(allocator, 4);
    defer ch.deinit();

    try std.testing.expect(ch.trySend(10));
    try std.testing.expect(ch.trySend(20));
    ch.close();

    // Blocking receive should drain items first
    try std.testing.expectEqual(@as(u32, 10), ch.receive().?);
    try std.testing.expectEqual(@as(u32, 20), ch.receive().?);
    // Then return null
    try std.testing.expect(ch.receive() == null);
}

test "BoundedChannel: wrap-around" {
    const allocator = std.testing.allocator;
    var ch = try BoundedChannel(u8).init(allocator, 3);
    defer ch.deinit();

    // Fill and drain to advance head/tail
    try std.testing.expect(ch.trySend(10));
    try std.testing.expect(ch.trySend(20));
    try std.testing.expectEqual(@as(u8, 10), ch.tryReceive().?);
    try std.testing.expectEqual(@as(u8, 20), ch.tryReceive().?);

    // Now head=2, tail=2 — push 3 items to wrap
    try std.testing.expect(ch.trySend(30));
    try std.testing.expect(ch.trySend(40));
    try std.testing.expect(ch.trySend(50));
    try std.testing.expect(!ch.trySend(60)); // full

    try std.testing.expectEqual(@as(u8, 30), ch.tryReceive().?);
    try std.testing.expectEqual(@as(u8, 40), ch.tryReceive().?);
    try std.testing.expectEqual(@as(u8, 50), ch.tryReceive().?);
    try std.testing.expect(ch.tryReceive() == null);
}

test "BoundedChannel: multi-threaded producer-consumer" {
    const allocator = std.testing.allocator;
    var ch = try BoundedChannel(u32).init(allocator, 64);
    defer ch.deinit();

    const count = 1000;

    // Producer thread
    const producer = try std.Thread.spawn(.{}, struct {
        fn run(channel: *BoundedChannel(u32)) void {
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                while (!channel.trySend(i)) {
                    // Spin-wait if full (test only)
                    std.Thread.yield() catch {};
                }
            }
            channel.close();
        }
    }.run, .{&ch});

    // Consumer: blocking receive
    var sum: u64 = 0;
    var received: u32 = 0;
    while (ch.receive()) |val| {
        sum += val;
        received += 1;
    }

    producer.join();

    try std.testing.expectEqual(@as(u32, count), received);
    // Sum of 0..999 = 499500
    try std.testing.expectEqual(@as(u64, 499500), sum);
}

test "BoundedChannel: len tracks count" {
    const allocator = std.testing.allocator;
    var ch = try BoundedChannel(u32).init(allocator, 4);
    defer ch.deinit();

    try std.testing.expectEqual(@as(usize, 0), ch.len());
    _ = ch.trySend(1);
    try std.testing.expectEqual(@as(usize, 1), ch.len());
    _ = ch.trySend(2);
    try std.testing.expectEqual(@as(usize, 2), ch.len());
    _ = ch.tryReceive();
    try std.testing.expectEqual(@as(usize, 1), ch.len());
}

test "BoundedChannel: single capacity" {
    const allocator = std.testing.allocator;
    var ch = try BoundedChannel(i32).init(allocator, 1);
    defer ch.deinit();

    try std.testing.expect(ch.trySend(-42));
    try std.testing.expect(!ch.trySend(99)); // full

    try std.testing.expectEqual(@as(i32, -42), ch.tryReceive().?);
    try std.testing.expect(ch.tryReceive() == null);
}
