// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Syslog transport for audit events over UDP, TCP, or TLS.
//! Formats messages as RFC 5424 with a CEF payload and sends via a background worker.

const std = @import("std");
const events = @import("events.zig");
const config = @import("config.zig");
const cef = @import("cef.zig");
const time = @import("time.zig");
const sync = @import("sync.zig");

// Use std.log instead of Geode's logging wrapper
const log = std.log.scoped(.audit);

// External DNS library for RFC 1035 compliant host resolution
const dns = @import("dns");

const QUEUE_SIZE = 10000;

const linux = std.os.linux;

/// Small IPv4 address representation — replaces the removed `std.net.Address`
/// for the UDP/TCP socket code below. `bytes` are in network byte order but
/// stored as a 4-tuple ; `port` is native endian and converted on use.
pub const Ip4Addr = struct {
    bytes: [4]u8,
    port: u16,

    pub fn eqlData(a: Ip4Addr, b: Ip4Addr) bool {
        return a.port == b.port and std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// Produce a Linux `sockaddr.in` struct ready to hand to sendto/connect.
    pub fn toSockaddrIn(self: Ip4Addr) linux.sockaddr.in {
        return .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, self.port),
            .addr = @bitCast(self.bytes),
        };
    }
};

/// Resolve a hostname to an IPv4 address using the external DNS library.
/// Falls back to parseLiteral if the host is already an IP address.
fn resolveHostToAddress(allocator: std.mem.Allocator, host: []const u8, port: u16) !Ip4Addr {
    if (parseIp4(host, port)) |addr| {
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
            return parseIp4(result.addresses[0], port) catch error.InvalidAddress;
        }

        return error.NoAddressFound;
    }
}

/// Parse a dotted-quad IPv4 literal like "203.0.113.5" into `Ip4Addr`.
fn parseIp4(buf: []const u8, port: u16) !Ip4Addr {
    var bytes: [4]u8 = .{ 0, 0, 0, 0 };
    var part: usize = 0;
    var seen_digit = false;
    var current: u32 = 0;
    for (buf) |c| {
        if (c == '.') {
            if (!seen_digit) return error.InvalidAddress;
            if (part >= 3) return error.InvalidAddress;
            if (current > 255) return error.InvalidAddress;
            bytes[part] = @intCast(current);
            part += 1;
            current = 0;
            seen_digit = false;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            if (current > 255) return error.InvalidAddress;
            seen_digit = true;
        } else {
            return error.InvalidAddress;
        }
    }
    if (!seen_digit or part != 3) return error.InvalidAddress;
    bytes[3] = @intCast(current);
    return Ip4Addr{ .bytes = bytes, .port = port };
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

    // Persistent socket fields (GAP-021 / PERF-010) — raw Linux fd
    udp_socket: ?i32 = null,
    tcp_socket: ?i32 = null,

    // DNS cache fields (PERF-006)
    resolved_addr: ?Ip4Addr = null,
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
            // daemon: one persistent consumer per syslog sink; the worker loops
            // on a ring buffer for the sink's lifetime. Not pool work — putting
            // this on a bounded thread-pool would starve the pool since the
            // worker never returns.
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
            _ = linux.close(sock);
            self.udp_socket = null;
        }
        if (self.tcp_socket) |sock| {
            _ = linux.close(sock);
            self.tcp_socket = null;
        }

        // Free any messages left after worker exit (shouldn't happen, but safe)
        while (self.ch.tryReceive()) |msg| {
            self.allocator.free(msg);
        }
        self.ch.deinit();
        self.allocator.destroy(self);
    }

    /// Enqueue an event for the background worker. Returns `.dropped` when
    /// the channel is full (the message is discarded and counted by
    /// `dropped_count`), `.enqueued` otherwise (GAP-041/A2). Warn cadence
    /// matches the file sink: first drop and every 1000th after.
    pub fn send(self: *SyslogSender, event: *const events.AuditEvent) !events.SendStatus {
        // A disabled sink accepts nothing and loses nothing.
        if (!self.config.enabled) return .enqueued;

        const cef_msg = try cef.formatCef(self.allocator, event, &self.identity, self.clock);
        const syslog_line = try self.formatSyslogLine(event, cef_msg);
        defer self.allocator.free(cef_msg);

        if (!self.ch.trySend(syslog_line)) {
            self.allocator.free(syslog_line);
            const n = self.dropped_count.fetchAdd(1, .monotonic) + 1;
            if (n == 1 or n % 1000 == 0) {
                log.warn("syslog channel full; dropped {d} messages so far", .{n});
            }
            return .dropped;
        }
        return .enqueued;
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
    fn resolveOrCached(self: *SyslogSender) !Ip4Addr {
        const now_i128 = self.clock.nowMs();
        // QR-010: saturate instead of @intCast — a broken or hostile clock
        // outside i64 milliseconds (~±292 million years) must degrade to a
        // spurious re-resolve, never panic the syslog worker.
        const now_ms: i64 = std.math.cast(i64, now_i128) orelse
            (if (now_i128 > 0) std.math.maxInt(i64) else std.math.minInt(i64));
        const elapsed = now_ms -| self.last_dns_resolve_ms;
        if (self.resolved_addr != null and elapsed >= 0 and elapsed < @as(i64, self.dns_cache_ttl_ms)) {
            return self.resolved_addr.?;
        }
        const addr = try resolveHostToAddress(self.allocator, self.config.host, self.config.port);
        self.resolved_addr = addr;
        self.last_dns_resolve_ms = now_ms;
        return addr;
    }

    fn checkErrno(rc: usize) !void {
        const err = std.posix.errno(rc);
        if (err != .SUCCESS) {
            log.debug("syslog syscall errno: {s}", .{@tagName(err)});
            return error.SyscallFailed;
        }
    }

    fn rawSocket(domain: u32, socket_type: u32, protocol: u32) !i32 {
        const rc = linux.socket(domain, socket_type, protocol);
        try checkErrno(rc);
        return @intCast(rc);
    }

    fn sendUdp(self: *SyslogSender, message: []const u8) !void {
        // Create socket on first use, reuse thereafter
        if (self.udp_socket == null) {
            self.udp_socket = try rawSocket(linux.AF.INET, linux.SOCK.DGRAM, 0);
        }
        const socket = self.udp_socket.?;

        const addr = try self.resolveOrCached();
        const sa = addr.toSockaddrIn();
        const rc = linux.sendto(
            socket,
            message.ptr,
            message.len,
            0,
            @ptrCast(&sa),
            @sizeOf(linux.sockaddr.in),
        );
        try checkErrno(rc);
    }

    fn sendTcp(self: *SyslogSender, message: []const u8) !void {
        // Create and connect socket on first use, reuse thereafter
        if (self.tcp_socket == null) {
            const socket = try rawSocket(linux.AF.INET, linux.SOCK.STREAM, 0);
            errdefer _ = linux.close(socket);

            // Set a 5-second send timeout to avoid blocking indefinitely on
            // unresponsive peers.
            const timeout = linux.timeval{ .sec = 5, .usec = 0 };
            _ = linux.setsockopt(
                socket,
                linux.SOL.SOCKET,
                linux.SO.SNDTIMEO,
                @ptrCast(&timeout),
                @sizeOf(linux.timeval),
            );

            const addr = try self.resolveOrCached();
            const sa = addr.toSockaddrIn();
            const rc = linux.connect(
                socket,
                @ptrCast(&sa),
                @sizeOf(linux.sockaddr.in),
            );
            try checkErrno(rc);

            self.tcp_socket = socket;
        }
        const socket = self.tcp_socket.?;

        const length_prefix = try std.fmt.allocPrint(self.allocator, "{d} ", .{message.len});
        defer self.allocator.free(length_prefix);

        // Use sendto with NULL addr as a raw "send" equivalent on Linux.
        const rc1 = linux.sendto(socket, length_prefix.ptr, length_prefix.len, 0, null, 0);
        checkErrno(rc1) catch |err| {
            _ = linux.close(socket);
            self.tcp_socket = null;
            return err;
        };
        const rc2 = linux.sendto(socket, message.ptr, message.len, 0, null, 0);
        checkErrno(rc2) catch |err| {
            _ = linux.close(socket);
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

    // GAP-046/A7: the event's own timestamp is authoritative (audit()
    // stamps ts_unix_ms before fan-out); the clock fallback only covers
    // direct calls with unstamped (ts == 0) events.
    var ts_buf: [64]u8 = undefined;
    const timestamp = if (event.ts_unix_ms != 0)
        time.formatRfc3339(event.ts_unix_ms, &ts_buf)
    else
        clock.nowRfc3339(&ts_buf);

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
    mutex: sync.Mutex,

    pub fn init(allocator: std.mem.Allocator) !MockSyslogSender {
        return MockSyslogSender{
            .allocator = allocator,
            .captured_messages = try std.ArrayList([]const u8).initCapacity(allocator, 16),
            .mutex = .{},
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

test "GAP-046/A7: formatRfc5424 renders the event's own timestamp, not format-time now" {
    const allocator = std.testing.allocator;

    // Clock frozen at TEST_TIMESTAMP_MS; the event is stamped 5 seconds
    // later. The RFC 5424 header timestamp must carry the EVENT's timestamp.
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    const clock = fixed_clock.clock();

    const event = events.AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = time.TEST_TIMESTAMP_MS + 5000,
        .severity = .INFO,
        .actor_id = "jane.doe",
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = null,
    };

    const service_config = config.ServiceConfig{
        .name = "authsvc",
        .host = "app-host",
        .pid = 1234,
    };

    const syslog_config = config.SyslogSinkConfig{
        .enabled = false,
        .protocol = .udp,
        .host = "{{TEST_HOST}}",
        .port = 514,
        .rfc5424 = config.SyslogRfc5424Config{
            .facility = .local4,
        },
    };

    const line = try formatRfc5424(allocator, &event, "CEF:0|V|P|1|sig|name|5|", service_config, syslog_config, clock);
    defer allocator.free(line);

    try std.testing.expect(std.mem.indexOf(u8, line, "2025-01-01T00:00:05.000Z") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "2025-01-01T00:00:00.000Z") == null);
}

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
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    try std.testing.expect(std.posix.errno(rc) == .SUCCESS);
    sender.udp_socket = @intCast(rc);

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
    try std.testing.expect(addr1.eqlData(addr2));
}

test "QR-010: resolveOrCached saturates an absurd i128 clock instead of panicking" {
    const allocator = std.testing.allocator;

    // A clock past i64 milliseconds (~292 million years). The old
    // @intCast(now_i128) panicked here in safe builds.
    var fixed_clock = time.FixedClock.init(@as(i128, std.math.maxInt(i64)) + 1_000_000);
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

    // Must not panic; the timestamp saturates to maxInt(i64).
    const addr1 = try sender.resolveOrCached();
    try std.testing.expectEqual(@as(i64, std.math.maxInt(i64)), sender.last_dns_resolve_ms);

    // A second call at the same (saturated) time hits the cache: elapsed == 0.
    const addr2 = try sender.resolveOrCached();
    try std.testing.expect(addr1.eqlData(addr2));
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
