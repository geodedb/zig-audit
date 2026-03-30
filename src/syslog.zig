// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Syslog transport for audit events over UDP, TCP, or TLS.
//! Formats messages as RFC 5424 with a CEF payload and sends via a background worker.

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

pub const SyslogSender = struct {
    allocator: std.mem.Allocator,
    config: config.SyslogSinkConfig,
    service: config.ServiceConfig,
    identity: config.CefIdentityConfig,
    clock: time.Clock,
    ch: BoundedChannel([]const u8),
    thread: ?std.Thread,
    dropped_count: std.atomic.Value(u64),

    // Persistent socket fields (GAP-021 / PERF-010)
    udp_socket: ?std.posix.socket_t = null,
    tcp_socket: ?std.posix.socket_t = null,

    // DNS cache fields (PERF-006)
    resolved_addr: ?std.net.Address = null,
    dns_cache_ttl_ms: u32 = 300_000, // 5 minutes
    last_dns_resolve_ms: i64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        syslog_config: config.SyslogSinkConfig,
        service_config: config.ServiceConfig,
        identity_config: config.CefIdentityConfig,
        clock: time.Clock,
    ) !*SyslogSender {
        const sender = try allocator.create(SyslogSender);

        var ch = try BoundedChannel([]const u8).init(allocator, QUEUE_SIZE);

        if (syslog_config.protocol == .tls) {
            ch.deinit();
            allocator.destroy(sender);
            return error.TlsNotSupported;
        }

        sender.* = SyslogSender{
            .allocator = allocator,
            .config = syslog_config,
            .service = service_config,
            .identity = identity_config,
            .clock = clock,
            .ch = ch,
            .thread = null,
            .dropped_count = std.atomic.Value(u64).init(0),
            .udp_socket = null,
            .tcp_socket = null,
            .resolved_addr = null,
            .dns_cache_ttl_ms = 300_000,
            .last_dns_resolve_ms = 0,
        };

        if (sender.config.enabled) {
            log.warn("syslog transport using plaintext {s}; use TLS tunnel for encrypted transport", .{@tagName(syslog_config.protocol)});
            sender.thread = try std.Thread.spawn(.{}, workerThread, .{sender});
        }

        return sender;
    }

    pub fn deinit(self: *SyslogSender) void {
        // Close the channel — worker will drain remaining messages then exit
        self.ch.close();

        if (self.thread) |thread| {
            thread.join();
        }

        // Close persistent sockets
        if (self.udp_socket) |sock| {
            std.posix.close(sock);
            self.udp_socket = null;
        }
        if (self.tcp_socket) |sock| {
            std.posix.close(sock);
            self.tcp_socket = null;
        }

        // Free any messages left after worker exit (shouldn't happen, but safe)
        while (self.ch.tryReceive()) |msg| {
            self.allocator.free(msg);
        }
        self.ch.deinit();
        self.allocator.destroy(self);
    }

    pub fn send(self: *SyslogSender, event: *const events.AuditEvent) !void {
        if (!self.config.enabled) return;

        const cef_msg = try cef.formatCef(self.allocator, event, &self.identity, self.clock);
        const syslog_line = try self.formatSyslogLine(event, cef_msg);
        defer self.allocator.free(cef_msg);

        if (!self.ch.trySend(syslog_line)) {
            const prev = self.dropped_count.fetchAdd(1, .monotonic);
            if (prev == 0) {
                log.warn("syslog channel full; dropping message", .{});
            }
            self.allocator.free(syslog_line);
        }
    }

    pub fn getDroppedCount(self: *SyslogSender) u64 {
        return self.dropped_count.load(.monotonic);
    }

    fn formatSyslogLine(self: *SyslogSender, event: *const events.AuditEvent, cef_msg: []const u8) ![]const u8 {
        return formatRfc5424(self.allocator, event, cef_msg, self.service, self.config, self.clock);
    }

    /// Background worker: blocks on channel.receive(), sends each message,
    /// and exits when channel is closed and drained.
    fn workerThread(self: *SyslogSender) void {
        while (self.ch.receive()) |msg| {
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

    /// Resolve or return the cached address, re-resolving when the DNS TTL expires.
    fn resolveOrCached(self: *SyslogSender) !std.net.Address {
        const now_i128 = self.clock.nowMs();
        // Safe truncation: millisecond timestamps fit in i64 for the foreseeable future
        const now_ms: i64 = @intCast(now_i128);
        const elapsed = now_ms -| self.last_dns_resolve_ms;
        if (self.resolved_addr != null and elapsed >= 0 and elapsed < self.dns_cache_ttl_ms) {
            return self.resolved_addr.?;
        }
        const addr = try resolveHostToAddress(self.allocator, self.config.host, self.config.port);
        self.resolved_addr = addr;
        self.last_dns_resolve_ms = now_ms;
        return addr;
    }

    fn sendUdp(self: *SyslogSender, message: []const u8) !void {
        // Create socket on first use, reuse thereafter
        if (self.udp_socket == null) {
            self.udp_socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        }
        const socket = self.udp_socket.?;

        const addr = try self.resolveOrCached();
        _ = try std.posix.sendto(socket, message, 0, &addr.any, addr.getOsSockLen());
    }

    fn sendTcp(self: *SyslogSender, message: []const u8) !void {
        // Create and connect socket on first use, reuse thereafter
        if (self.tcp_socket == null) {
            const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
            errdefer std.posix.close(socket);

            // Set a 5-second send timeout to avoid blocking indefinitely on
            // unresponsive peers.
            const timeout = std.posix.timeval{ .sec = 5, .usec = 0 };
            std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};

            const addr = try self.resolveOrCached();
            try std.posix.connect(socket, &addr.any, addr.getOsSockLen());

            self.tcp_socket = socket;
        }
        const socket = self.tcp_socket.?;

        const length_prefix = try std.fmt.allocPrint(self.allocator, "{d} ", .{message.len});
        defer self.allocator.free(length_prefix);

        _ = std.posix.send(socket, length_prefix, 0) catch |err| {
            // On send error, close socket so it reconnects on next attempt
            std.posix.close(socket);
            self.tcp_socket = null;
            return err;
        };
        _ = std.posix.send(socket, message, 0) catch |err| {
            std.posix.close(socket);
            self.tcp_socket = null;
            return err;
        };
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
};

/// Format an audit event as an RFC 5424 syslog line with a CEF payload.
/// Shared implementation used by both SyslogSender and MockSyslogSender.
pub fn formatRfc5424(allocator: std.mem.Allocator, event: *const events.AuditEvent, cef_msg: []const u8, service: config.ServiceConfig, syslog_cfg: config.SyslogSinkConfig, clock: time.Clock) ![]const u8 {
    const facility = syslog_cfg.rfc5424.facility.toInt();
    const severity = event.severity.toSyslogSeverity();
    const pri = facility * 8 + severity;

    var ts_buf: [64]u8 = undefined;
    const timestamp = clock.nowRfc3339(&ts_buf);

    return std.fmt.allocPrint(allocator, "<{d}>1 {s} {s} {s} {d} AUDIT - {s}", .{
        pri,
        timestamp,
        service.host,
        service.name,
        service.pid,
        cef_msg,
    });
}

pub const MockSyslogSender = struct {
    allocator: std.mem.Allocator,
    captured_messages: std.ArrayList([]const u8),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) !MockSyslogSender {
        return MockSyslogSender{
            .allocator = allocator,
            .captured_messages = try std.ArrayList([]const u8).initCapacity(allocator, 16),
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

        const syslog_line = try formatRfc5424(self.allocator, event, cef_msg, service.*, syslog_config.*, clock);

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

const BoundedChannel = @import("channel.zig").BoundedChannel;

test "SyslogSender.init rejects TLS protocol" {
    const allocator = std.testing.allocator;
    var fixed_clock = time.FixedClock.init(1735689600000);
    const clock = fixed_clock.clock();

    const syslog_config = config.SyslogSinkConfig{
        .enabled = true,
        .protocol = .tls,
        .host = "localhost",
        .port = 6514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local0,
        },
    };

    const service_config = config.ServiceConfig{
        .name = "test",
        .host = "test-host",
        .pid = 1,
    };

    const identity_config = config.CefIdentityConfig{
        .vendor = "V",
        .product = "P",
        .version = "1",
    };

    const result = SyslogSender.init(allocator, syslog_config, service_config, identity_config, clock);
    try std.testing.expectError(error.TlsNotSupported, result);
}

test "TLS config: default values" {
    const tls_config = config.SyslogTlsConfig{};
    try std.testing.expect(tls_config.pinned_cert_hash == null);
    try std.testing.expect(tls_config.ca_bundle_path == null);
    try std.testing.expect(tls_config.verify_hostname == true);
    try std.testing.expect(tls_config.pool_size == 4);
    try std.testing.expect(tls_config.idle_timeout_ms == 30000);
}

test "SyslogSender.getDroppedCount starts at zero" {
    const allocator = std.testing.allocator;
    var fixed_clock = time.FixedClock.init(1735689600000);
    const clock = fixed_clock.clock();

    const syslog_config = config.SyslogSinkConfig{
        .enabled = false, // disabled so no worker thread spawned
        .protocol = .udp,
        .host = "{{TEST_HOST}}",
        .port = 514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local0,
        },
    };

    const service_config = config.ServiceConfig{
        .name = "test",
        .host = "test-host",
        .pid = 1,
    };

    const identity_config = config.CefIdentityConfig{
        .vendor = "V",
        .product = "P",
        .version = "1",
    };

    const sender = try SyslogSender.init(allocator, syslog_config, service_config, identity_config, clock);
    defer sender.deinit();

    try std.testing.expectEqual(@as(u64, 0), sender.getDroppedCount());
}

test "SyslogSender persistent socket fields default to null" {
    const allocator = std.testing.allocator;
    var fixed_clock = time.FixedClock.init(1735689600000);
    const clock = fixed_clock.clock();

    const syslog_config = config.SyslogSinkConfig{
        .enabled = false,
        .protocol = .udp,
        .host = "{{TEST_HOST}}",
        .port = 514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local0,
        },
    };

    const service_config = config.ServiceConfig{
        .name = "test",
        .host = "test-host",
        .pid = 1,
    };

    const identity_config = config.CefIdentityConfig{
        .vendor = "V",
        .product = "P",
        .version = "1",
    };

    const sender = try SyslogSender.init(allocator, syslog_config, service_config, identity_config, clock);
    defer sender.deinit();

    // Persistent sockets start as null
    try std.testing.expect(sender.udp_socket == null);
    try std.testing.expect(sender.tcp_socket == null);

    // DNS cache starts empty
    try std.testing.expect(sender.resolved_addr == null);
    try std.testing.expectEqual(@as(i64, 0), sender.last_dns_resolve_ms);
    try std.testing.expectEqual(@as(u32, 300_000), sender.dns_cache_ttl_ms);
}

test "SyslogSender deinit closes persistent sockets safely" {
    const allocator = std.testing.allocator;
    var fixed_clock = time.FixedClock.init(1735689600000);
    const clock = fixed_clock.clock();

    const syslog_config = config.SyslogSinkConfig{
        .enabled = false,
        .protocol = .udp,
        .host = "{{TEST_HOST}}",
        .port = 514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local0,
        },
    };

    const service_config = config.ServiceConfig{
        .name = "test",
        .host = "test-host",
        .pid = 1,
    };

    const identity_config = config.CefIdentityConfig{
        .vendor = "V",
        .product = "P",
        .version = "1",
    };

    const sender = try SyslogSender.init(allocator, syslog_config, service_config, identity_config, clock);

    // Manually create a UDP socket to verify deinit closes it
    sender.udp_socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);

    // deinit should close it without error
    sender.deinit();
}

test "SyslogSender resolveOrCached caches address" {
    const allocator = std.testing.allocator;
    var fixed_clock = time.FixedClock.init(1735689600000);
    const clock = fixed_clock.clock();

    const syslog_config = config.SyslogSinkConfig{
        .enabled = false,
        .protocol = .udp,
        .host = "127.0.0.1", // IP literal avoids actual DNS
        .port = 514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local0,
        },
    };

    const service_config = config.ServiceConfig{
        .name = "test",
        .host = "test-host",
        .pid = 1,
    };

    const identity_config = config.CefIdentityConfig{
        .vendor = "V",
        .product = "P",
        .version = "1",
    };

    const sender = try SyslogSender.init(allocator, syslog_config, service_config, identity_config, clock);
    defer sender.deinit();

    // First call resolves and caches
    const addr1 = try sender.resolveOrCached();
    try std.testing.expect(sender.resolved_addr != null);
    try std.testing.expect(sender.last_dns_resolve_ms != 0);

    // Second call returns cached (same address)
    const addr2 = try sender.resolveOrCached();
    try std.testing.expectEqual(addr1.any.data, addr2.any.data);
}

test "SyslogSender resolveOrCached re-resolves after TTL" {
    const allocator = std.testing.allocator;

    // Start with time 1000 ms
    var fixed_clock = time.FixedClock.init(1000);
    const clock = fixed_clock.clock();

    const syslog_config = config.SyslogSinkConfig{
        .enabled = false,
        .protocol = .udp,
        .host = "127.0.0.1",
        .port = 514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local0,
        },
    };

    const service_config = config.ServiceConfig{
        .name = "test",
        .host = "test-host",
        .pid = 1,
    };

    const identity_config = config.CefIdentityConfig{
        .vendor = "V",
        .product = "P",
        .version = "1",
    };

    const sender = try SyslogSender.init(allocator, syslog_config, service_config, identity_config, clock);
    defer sender.deinit();

    // Set a very short TTL for testing
    sender.dns_cache_ttl_ms = 100;

    // First resolve at t=1000ms
    _ = try sender.resolveOrCached();
    const first_resolve_time = sender.last_dns_resolve_ms;
    try std.testing.expectEqual(@as(i64, 1000), first_resolve_time);

    // Advance clock past TTL (1000 + 100 = 1100, so 1200 is past)
    fixed_clock.fixed_time_ms = 1200;

    // Should re-resolve (elapsed 200ms >= 100ms ttl)
    _ = try sender.resolveOrCached();
    const second_resolve_time = sender.last_dns_resolve_ms;
    try std.testing.expectEqual(@as(i64, 1200), second_resolve_time);
}
