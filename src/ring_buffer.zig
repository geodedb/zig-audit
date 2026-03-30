// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Generic fixed-capacity ring buffer (circular queue).
//!
//! **NOT thread-safe.** This data structure has no internal synchronization.
//! For thread-safe producer-consumer queuing, use `channel.BoundedChannel`
//! which provides mutex + condition variable, blocking receive, and
//! close-with-drain semantics.
//!
//! This ring buffer is suitable for single-threaded batch processing or
//! cases where the caller manages external synchronization.

const std = @import("std");

pub fn RingBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,
        head: usize,
        tail: usize,
        count: usize,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, capacity: usize) error{OutOfMemory}!Self {
            return Self{
                .items = try allocator.alloc(T, capacity),
                .head = 0,
                .tail = 0,
                .count = 0,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.items);
        }

        pub fn push(self: *Self, item: T) bool {
            if (self.count >= self.items.len) {
                return false;
            }

            self.items[self.tail] = item;
            self.tail = (self.tail + 1) % self.items.len;
            self.count += 1;
            return true;
        }

        pub fn pop(self: *Self) ?T {
            if (self.count == 0) {
                return null;
            }

            const item = self.items[self.head];
            self.head = (self.head + 1) % self.items.len;
            self.count -= 1;
            return item;
        }

        pub fn isFull(self: *Self) bool {
            return self.count >= self.items.len;
        }

        pub fn isEmpty(self: *Self) bool {
            return self.count == 0;
        }
    };
}

test "RingBuffer: basic push and pop" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(u32).init(allocator, 4);
    defer rb.deinit();

    try std.testing.expect(rb.isEmpty());
    try std.testing.expect(!rb.isFull());

    try std.testing.expect(rb.push(1));
    try std.testing.expect(rb.push(2));
    try std.testing.expect(rb.push(3));
    try std.testing.expect(rb.push(4));

    try std.testing.expect(rb.isFull());
    try std.testing.expect(!rb.isEmpty());
    try std.testing.expect(!rb.push(5));

    try std.testing.expectEqual(@as(u32, 1), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 2), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 3), rb.pop().?);
    try std.testing.expectEqual(@as(u32, 4), rb.pop().?);

    try std.testing.expect(rb.isEmpty());
    try std.testing.expect(rb.pop() == null);
}

test "RingBuffer: wrap-around behavior" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(u8).init(allocator, 3);
    defer rb.deinit();

    // Fill and drain to advance head/tail past the initial position
    try std.testing.expect(rb.push(10));
    try std.testing.expect(rb.push(20));
    try std.testing.expectEqual(@as(u8, 10), rb.pop().?);
    try std.testing.expectEqual(@as(u8, 20), rb.pop().?);

    // Now head=2, tail=2, count=0 -- push 3 items to wrap around
    try std.testing.expect(rb.push(30));
    try std.testing.expect(rb.push(40));
    try std.testing.expect(rb.push(50));
    try std.testing.expect(rb.isFull());

    try std.testing.expectEqual(@as(u8, 30), rb.pop().?);
    try std.testing.expectEqual(@as(u8, 40), rb.pop().?);
    try std.testing.expectEqual(@as(u8, 50), rb.pop().?);
    try std.testing.expect(rb.isEmpty());
}

test "RingBuffer: single capacity" {
    const allocator = std.testing.allocator;
    var rb = try RingBuffer(i32).init(allocator, 1);
    defer rb.deinit();

    try std.testing.expect(rb.push(-42));
    try std.testing.expect(rb.isFull());
    try std.testing.expect(!rb.push(99));

    try std.testing.expectEqual(@as(i32, -42), rb.pop().?);
    try std.testing.expect(rb.isEmpty());
    try std.testing.expect(rb.pop() == null);
}
