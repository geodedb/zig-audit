// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Shared JSON value utilities for deep cloning and recursive deallocation.
//!
//! These helpers operate on `std.json.Value` trees and are used by events,
//! filters, file_sink, and logger modules to avoid duplicating the same
//! recursive traversal logic.

const std = @import("std");

/// Recursively free all heap-allocated memory owned by a `std.json.Value`.
///
/// Handles strings, number_strings, arrays (items + backing), and objects
/// (keys + values + backing).  Scalars (null, bool, integer, float) are
/// no-ops.
pub fn freeJsonValue(allocator: std.mem.Allocator, value: std.json.Value) void {
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
            obj.deinit(allocator);
        },
        else => {},
    }
}

/// Recursively deep-clone a `std.json.Value`, duplicating every heap-allocated
/// string, key, array element, and object entry using `allocator`.
pub fn cloneJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    return switch (value) {
        .null => .null,
        .bool => |b| std.json.Value{ .bool = b },
        .integer => |i| std.json.Value{ .integer = i },
        .float => |f| std.json.Value{ .float = f },
        .number_string => |ns| std.json.Value{ .number_string = try allocator.dupe(u8, ns) },
        .string => |s| std.json.Value{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var cloned_array = std.json.Array.init(allocator);
            // GAP-048: on mid-loop OOM, free every item cloned so far plus
            // the array's backing storage instead of leaking the partial clone.
            errdefer {
                for (cloned_array.items) |item| {
                    freeJsonValue(allocator, item);
                }
                cloned_array.deinit();
            }
            for (arr.items) |item| {
                const cloned_item = try cloneJsonValue(allocator, item);
                // Not yet owned by cloned_array if append fails.
                errdefer freeJsonValue(allocator, cloned_item);
                try cloned_array.append(cloned_item);
            }
            break :blk std.json.Value{ .array = cloned_array };
        },
        .object => |obj| blk: {
            var cloned_map: std.json.ObjectMap = .empty;
            // GAP-048: on mid-loop OOM, free every key/value already in the
            // map plus its backing storage instead of leaking the partial clone.
            errdefer {
                var cloned_iter = cloned_map.iterator();
                while (cloned_iter.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    freeJsonValue(allocator, entry.value_ptr.*);
                }
                cloned_map.deinit(allocator);
            }
            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const cloned_key = try allocator.dupe(u8, entry.key_ptr.*);
                // Key is orphaned if the value clone or the put fails.
                errdefer allocator.free(cloned_key);
                const cloned_value = try cloneJsonValue(allocator, entry.value_ptr.*);
                // Value is orphaned if the put fails.
                errdefer freeJsonValue(allocator, cloned_value);
                try cloned_map.put(allocator, cloned_key, cloned_value);
            }
            break :blk std.json.Value{ .object = cloned_map };
        },
    };
}

// ── Tests ───────────────────────────────────────────────────────────────

test "freeJsonValue on scalars does not crash" {
    const allocator = std.testing.allocator;
    freeJsonValue(allocator, .null);
    freeJsonValue(allocator, std.json.Value{ .bool = true });
    freeJsonValue(allocator, std.json.Value{ .integer = 42 });
    freeJsonValue(allocator, std.json.Value{ .float = 3.14 });
}

test "cloneJsonValue round-trips scalars" {
    const allocator = std.testing.allocator;

    const null_clone = try cloneJsonValue(allocator, .null);
    try std.testing.expect(null_clone == .null);

    const bool_clone = try cloneJsonValue(allocator, std.json.Value{ .bool = true });
    try std.testing.expect(bool_clone.bool == true);

    const int_clone = try cloneJsonValue(allocator, std.json.Value{ .integer = 99 });
    try std.testing.expect(int_clone.integer == 99);

    const float_clone = try cloneJsonValue(allocator, std.json.Value{ .float = 2.71 });
    try std.testing.expect(float_clone.float == 2.71);
}

test "cloneJsonValue duplicates string" {
    const allocator = std.testing.allocator;

    const original = std.json.Value{ .string = "hello" };
    const cloned = try cloneJsonValue(allocator, original);
    defer freeJsonValue(allocator, cloned);

    try std.testing.expectEqualStrings("hello", cloned.string);
    // Must be a distinct allocation
    try std.testing.expect(original.string.ptr != cloned.string.ptr);
}

test "cloneJsonValue deep-clones nested object" {
    const allocator = std.testing.allocator;

    // Build { "a": "v1", "nested": { "b": 42 } } with heap-allocated keys/values
    var inner: std.json.ObjectMap = .empty;
    try inner.put(allocator, try allocator.dupe(u8, "b"), std.json.Value{ .integer = 42 });
    const inner_val = std.json.Value{ .object = inner };

    var outer: std.json.ObjectMap = .empty;
    try outer.put(allocator, try allocator.dupe(u8, "a"), std.json.Value{ .string = try allocator.dupe(u8, "v1") });
    try outer.put(allocator, try allocator.dupe(u8, "nested"), inner_val);
    const original = std.json.Value{ .object = outer };

    const cloned = try cloneJsonValue(allocator, original);
    defer freeJsonValue(allocator, cloned);

    // Free original to prove clone is independent
    freeJsonValue(allocator, original);

    try std.testing.expect(cloned == .object);
    const cloned_a = cloned.object.get("a") orelse unreachable;
    try std.testing.expectEqualStrings("v1", cloned_a.string);

    const cloned_nested = cloned.object.get("nested") orelse unreachable;
    try std.testing.expect(cloned_nested == .object);
    const cloned_b = cloned_nested.object.get("b") orelse unreachable;
    try std.testing.expect(cloned_b.integer == 42);
}

test "cloneJsonValue frees partial clones on OOM (GAP-048)" {
    const allocator = std.testing.allocator;

    // Array fixture: 4 duped strings so a clone needs several allocations
    // (dupe per item + ArrayList growth) — plenty of mid-loop failure points.
    var arr = std.json.Array.init(allocator);
    for (0..4) |_| {
        try arr.append(std.json.Value{ .string = try allocator.dupe(u8, "payload") });
    }
    const arr_val = std.json.Value{ .array = arr };
    defer freeJsonValue(allocator, arr_val);

    // Object fixture: 3 entries — each clone iteration allocates the key,
    // then the value, then (possibly) map storage, so the sweep below hits
    // the window BETWEEN key-dupe and value-clone too (key must be freed).
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, try allocator.dupe(u8, "k1"), std.json.Value{ .string = try allocator.dupe(u8, "v1") });
    try obj.put(allocator, try allocator.dupe(u8, "k2"), std.json.Value{ .string = try allocator.dupe(u8, "v2") });
    try obj.put(allocator, try allocator.dupe(u8, "k3"), std.json.Value{ .string = try allocator.dupe(u8, "v3") });
    const obj_val = std.json.Value{ .object = obj };
    defer freeJsonValue(allocator, obj_val);

    // Sweep every failure point. For each fail index either the clone
    // errors (and must have released everything allocated so far) or it
    // succeeds (and we free it normally). std.testing.allocator's leak
    // check at test end proves no partial clone was leaked.
    for (0..16) |i| {
        var failing_arr = std.testing.FailingAllocator.init(allocator, .{ .fail_index = i });
        if (cloneJsonValue(failing_arr.allocator(), arr_val)) |clone| {
            freeJsonValue(failing_arr.allocator(), clone);
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }

        var failing_obj = std.testing.FailingAllocator.init(allocator, .{ .fail_index = i });
        if (cloneJsonValue(failing_obj.allocator(), obj_val)) |clone| {
            freeJsonValue(failing_obj.allocator(), clone);
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
    }
}

test "cloneJsonValue deep-clones array" {
    const allocator = std.testing.allocator;

    var arr = std.json.Array.init(allocator);
    try arr.append(std.json.Value{ .string = try allocator.dupe(u8, "x") });
    try arr.append(std.json.Value{ .integer = 7 });
    const original = std.json.Value{ .array = arr };

    const cloned = try cloneJsonValue(allocator, original);
    defer freeJsonValue(allocator, cloned);

    // Free original
    freeJsonValue(allocator, original);

    try std.testing.expect(cloned == .array);
    try std.testing.expect(cloned.array.items.len == 2);
    try std.testing.expectEqualStrings("x", cloned.array.items[0].string);
    try std.testing.expect(cloned.array.items[1].integer == 7);
}
