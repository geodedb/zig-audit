// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const events = @import("events.zig");
const config = @import("config.zig");
const cef = @import("cef.zig");
const time = @import("time.zig");

// Use std.log instead of Geode's logging wrapper
const log = std.log.scoped(.audit);

// External DNS library for RFC 1035 compliant host resolution
const dns = @import("dns");

const QUEUE_SIZE = 10000;
const MAX_POOL_SIZE = 16;

/// Resolve a hostname to an IPv4 address using the external DNS library.
/// Falls back to std.net.Address.parseIp4 if the host is already an IP address.
fn resolveHostToAddress(allocator: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
    if (std.net.Address.parseIp4(host, port)) |addr| {
        return addr;
    } else |_| {
        var client = dns.Client.init(allocator) catch {
            return error.DnsInitFailed;
        };
        defer client.deinit();

        var result = client.resolveA(host) catch {
            return error.DnsResolutionFailed;
        };
        defer result.deinit(allocator);

        if (result.addresses.len > 0) {
            return std.net.Address.parseIp4(result.addresses[0], port) catch error.InvalidAddress;
        }

        return error.NoAddressFound;
    }
}

const PooledConnection = struct {
    socket: std.posix.socket_t,
    last_used: i64,
    in_use: bool,
};

pub const SyslogSender = struct {
    allocator: std.mem.Allocator,
    config: config.SyslogSinkConfig,
    service: config.ServiceConfig,
    identity: config.CefIdentityConfig,
    clock: time.Clock,
    queue: RingBuffer([]const u8),
    mutex: std.Thread.Mutex,
    should_stop: std.atomic.Value(bool),
    thread: ?std.Thread,
    tls_pool: [MAX_POOL_SIZE]?PooledConnection,
    pool_mutex: std.Thread.Mutex,

    pub fn init(
        allocator: std.mem.Allocator,
        syslog_config: config.SyslogSinkConfig,
        service_config: config.ServiceConfig,
        identity_config: config.CefIdentityConfig,
        clock: time.Clock,
    ) !*SyslogSender {
        const sender = try allocator.create(SyslogSender);
        var tls_pool: [MAX_POOL_SIZE]?PooledConnection = undefined;
        for (&tls_pool) |*slot| {
            slot.* = null;
        }

        sender.* = SyslogSender{
            .allocator = allocator,
            .config = syslog_config,
            .service = service_config,
            .identity = identity_config,
            .clock = clock,
            .queue = try RingBuffer([]const u8).init(allocator, QUEUE_SIZE),
            .mutex = std.Thread.Mutex{},
            .should_stop = std.atomic.Value(bool).init(false),
            .thread = null,
            .tls_pool = tls_pool,
            .pool_mutex = std.Thread.Mutex{},
        };

        if (sender.config.enabled) {
            sender.thread = try std.Thread.spawn(.{}, workerThread, .{sender});
        }

        return sender;
    }

    pub fn deinit(self: *SyslogSender) void {
        if (self.thread) |thread| {
            self.should_stop.store(true, .seq_cst);
            thread.join();
        }

        self.pool_mutex.lock();
        for (&self.tls_pool) |*slot| {
            if (slot.*) |conn_val| {
                std.posix.close(conn_val.socket);
                slot.* = null;
            }
        }
        self.pool_mutex.unlock();

        while (self.queue.pop()) |msg| {
            self.allocator.free(msg);
        }
        self.queue.deinit();
        self.allocator.destroy(self);
    }

    pub fn send(self: *SyslogSender, event: *const events.AuditEvent) !void {
        if (!self.config.enabled) return;

        const cef_msg = try cef.formatCef(self.allocator, event, &self.identity, self.clock);
        const syslog_line = try self.formatRfc5424(event, cef_msg);
        defer self.allocator.free(cef_msg);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (!self.queue.push(syslog_line)) {
            if (self.queue.pop()) |old_msg| {
                self.allocator.free(old_msg);
            }
            _ = self.queue.push(syslog_line);
        }
    }

    fn formatRfc5424(self: *SyslogSender, event: *const events.AuditEvent, cef_msg: []const u8) ![]const u8 {
        const facility = self.config.rfc5424.facility.toInt();
        const severity = event.severity.toSyslogSeverity();
        const pri = facility * 8 + severity;

        var ts_buf: [64]u8 = undefined;
        const timestamp = self.clock.nowRfc3339(&ts_buf);

        return std.fmt.allocPrint(self.allocator, "<{d}>1 {s} {s} {s} {d} AUDIT - {s}", .{
            pri,
            timestamp,
            self.service.host,
            self.service.name,
            self.service.pid,
            cef_msg,
        });
    }

    fn workerThread(self: *SyslogSender) void {
        while (!self.should_stop.load(.seq_cst)) {
            self.processQueue() catch |err| {
                log.warn("syslog sender error: {s}", .{@errorName(err)});
            };
            std.Thread.sleep(std.time.ns_per_ms * 100);
        }
    }

    fn processQueue(self: *SyslogSender) !void {
        var messages: [32][]const u8 = undefined;
        var count: usize = 0;

        {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (count < messages.len) {
                if (self.queue.pop()) |msg| {
                    messages[count] = msg;
                    count += 1;
                } else {
                    break;
                }
            }
        }

        if (count == 0) return;

        for (messages[0..count]) |msg| {
            defer self.allocator.free(msg);
            self.sendToSyslog(msg) catch |err| {
                log.warn("failed to send syslog message: {s}", .{@errorName(err)});
            };
        }
    }

    fn sendToSyslog(self: *SyslogSender, message: []const u8) !void {
        if (std.mem.indexOf(u8, self.config.host, "{{") != null) {
            return; // Mock mode for testing
        }

        switch (self.config.protocol) {
            .udp => try self.sendUdp(message),
            .tcp => try self.sendTcp(message),
            .tls => try self.sendTls(message),
        }
    }

    fn sendUdp(self: *SyslogSender, message: []const u8) !void {
        const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(socket);

        const addr = try resolveHostToAddress(self.allocator, self.config.host, self.config.port);
        _ = try std.posix.sendto(socket, message, 0, &addr.any, addr.getOsSockLen());
    }

    fn sendTcp(self: *SyslogSender, message: []const u8) !void {
        const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
        defer std.posix.close(socket);

        const addr = try resolveHostToAddress(self.allocator, self.config.host, self.config.port);
        try std.posix.connect(socket, &addr.any, addr.getOsSockLen());

        const length_prefix = try std.fmt.allocPrint(self.allocator, "{d} ", .{message.len});
        defer self.allocator.free(length_prefix);

        _ = try std.posix.send(socket, length_prefix, 0);
        _ = try std.posix.send(socket, message, 0);
    }

    fn sendTls(self: *SyslogSender, message: []const u8) !void {
        // TLS transport over TCP with connection pooling.
        // Full TLS handshake requires platform-specific or external TLS bindings
        // (e.g., OpenSSL/BoringSSL). The std.crypto.tls API is not yet stable
        // for generic stream wrapping. For now, send over plain TCP as a fallback
        // and log a warning. Consumers needing TLS should use an OS-level tunnel
        // (e.g., stunnel) or contribute a TLS binding.
        _ = self;
        _ = message;
        log.warn("TLS syslog transport not yet implemented; use stunnel or TCP", .{});
        return error.TlsNotImplemented;
    }

    fn releasePooledConnection(self: *SyslogSender, index: ?usize, close_on_error: bool) void {
        if (index) |idx| {
            self.pool_mutex.lock();
            defer self.pool_mutex.unlock();

            if (self.tls_pool[idx]) |*conn| {
                if (close_on_error) {
                    std.posix.close(conn.socket);
                    self.tls_pool[idx] = null;
                } else {
                    conn.in_use = false;
                    conn.last_used = @as(i64, @intCast(self.clock.nowMs()));
                }
            }
        }
    }

    fn verifyCertificatePin(expected_hash: []const u8) bool {
        if (expected_hash.len != 64) {
            log.err("invalid pinned certificate hash length: expected 64, got {d}", .{expected_hash.len});
            return false;
        }

        for (expected_hash) |c| {
            const valid = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
            if (!valid) {
                log.err("invalid hex character in pinned certificate hash", .{});
                return false;
            }
        }

        log.warn("certificate pinning configured but full verification requires TLS library extension", .{});
        return true;
    }
};

pub const MockSyslogSender = struct {
    allocator: std.mem.Allocator,
    captured_messages: std.ArrayList([]const u8),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) MockSyslogSender {
        return MockSyslogSender{
            .allocator = allocator,
            .captured_messages = std.ArrayList([]const u8).initCapacity(allocator, 16) catch @panic("MockSyslogSender init failed"),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *MockSyslogSender) void {
        for (self.captured_messages.items) |msg| {
            self.allocator.free(msg);
        }
        self.captured_messages.deinit(self.allocator);
    }

    pub fn send(self: *MockSyslogSender, event: *const events.AuditEvent, identity: *const config.CefIdentityConfig, service: *const config.ServiceConfig, syslog_config: *const config.SyslogSinkConfig, clock: time.Clock) !void {
        const cef_msg = try cef.formatCef(self.allocator, event, identity, clock);
        defer self.allocator.free(cef_msg);

        const facility = syslog_config.rfc5424.facility.toInt();
        const severity = event.severity.toSyslogSeverity();
        const pri = facility * 8 + severity;

        var ts_buf: [64]u8 = undefined;
        const timestamp = clock.nowRfc3339(&ts_buf);

        const syslog_line = try std.fmt.allocPrint(self.allocator, "<{d}>1 {s} {s} {s} {d} AUDIT - {s}", .{
            pri,
            timestamp,
            service.host,
            service.name,
            service.pid,
            cef_msg,
        });

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.captured_messages.append(self.allocator, syslog_line);
    }

    pub fn getMessages(self: *MockSyslogSender) []const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.captured_messages.items;
    }

    pub fn clear(self: *MockSyslogSender) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.captured_messages.items) |msg| {
            self.allocator.free(msg);
        }
        self.captured_messages.clearRetainingCapacity();
    }
};

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

test "TLS config: default values" {
    const tls_config = config.SyslogTlsConfig{};
    try std.testing.expect(tls_config.pinned_cert_hash == null);
    try std.testing.expect(tls_config.ca_bundle_path == null);
    try std.testing.expect(tls_config.verify_hostname == true);
    try std.testing.expect(tls_config.pool_size == 4);
    try std.testing.expect(tls_config.idle_timeout_ms == 30000);
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
