// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const root = @import("root.zig");

pub const SyslogProtocol = enum {
    udp,
    tcp,
    tls,

    pub fn fromString(s: []const u8) !SyslogProtocol {
        if (std.mem.eql(u8, s, "udp")) return .udp;
        if (std.mem.eql(u8, s, "tcp")) return .tcp;
        if (std.mem.eql(u8, s, "tls")) return .tls;
        return error.InvalidProtocol;
    }
};

pub const SyslogFacility = enum {
    local0,
    local1,
    local2,
    local3,
    local4,
    local5,
    local6,
    local7,

    pub fn fromString(s: []const u8) !SyslogFacility {
        if (std.mem.eql(u8, s, "local0")) return .local0;
        if (std.mem.eql(u8, s, "local1")) return .local1;
        if (std.mem.eql(u8, s, "local2")) return .local2;
        if (std.mem.eql(u8, s, "local3")) return .local3;
        if (std.mem.eql(u8, s, "local4")) return .local4;
        if (std.mem.eql(u8, s, "local5")) return .local5;
        if (std.mem.eql(u8, s, "local6")) return .local6;
        if (std.mem.eql(u8, s, "local7")) return .local7;
        return error.InvalidFacility;
    }

    pub fn toInt(self: SyslogFacility) u8 {
        return switch (self) {
            .local0 => 16,
            .local1 => 17,
            .local2 => 18,
            .local3 => 19,
            .local4 => 20,
            .local5 => 21,
            .local6 => 22,
            .local7 => 23,
        };
    }
};

pub const PiiMode = enum {
    off,
    mask,
    hash,

    pub fn fromString(s: []const u8) !PiiMode {
        if (std.mem.eql(u8, s, "off")) return .off;
        if (std.mem.eql(u8, s, "mask")) return .mask;
        if (std.mem.eql(u8, s, "hash")) return .hash;
        return error.InvalidPiiMode;
    }
};

pub const ServiceConfig = struct {
    name: []const u8,
    host: []const u8,
    pid: u32,
};

pub const CefIdentityConfig = struct {
    vendor: []const u8,
    product: []const u8,
    version: []const u8,
};

pub const IdentityConfig = struct {
    cef: CefIdentityConfig,
};

pub const FileSinkConfig = struct {
    enabled: bool,
    path: []const u8,
    max_bytes: u64,
    backup_count: u32,
};

pub const SyslogRfc5424Config = struct {
    facility: SyslogFacility,
};

pub const SyslogTlsConfig = struct {
    pinned_cert_hash: ?[]const u8 = null,
    ca_bundle_path: ?[]const u8 = null,
    verify_hostname: bool = true,
    pool_size: u8 = 4,
    idle_timeout_ms: u32 = 30000,
};

pub const SyslogSinkConfig = struct {
    enabled: bool,
    protocol: SyslogProtocol,
    host: []const u8,
    port: u16,
    rfc5424: SyslogRfc5424Config,
    tls: SyslogTlsConfig = .{},
};

pub const SinksConfig = struct {
    file: FileSinkConfig,
    syslog: SyslogSinkConfig,
};

pub const FiltersConfig = struct {
    default_deny: bool,
    allow_fields: [][]const u8,
    deny_key_patterns: [][]const u8,
    pii_mode: PiiMode,
    pci_mode: bool,
};

pub const Config = struct {
    version: u32,
    service: ServiceConfig,
    identity: IdentityConfig,
    sinks: SinksConfig,
    filters: FiltersConfig,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Config) void {
        self.allocator.free(self.service.name);
        self.allocator.free(self.service.host);
        self.allocator.free(self.identity.cef.vendor);
        self.allocator.free(self.identity.cef.product);
        self.allocator.free(self.identity.cef.version);
        self.allocator.free(self.sinks.file.path);
        self.allocator.free(self.sinks.syslog.host);

        for (self.filters.allow_fields) |field| {
            self.allocator.free(field);
        }
        self.allocator.free(self.filters.allow_fields);

        for (self.filters.deny_key_patterns) |pattern| {
            self.allocator.free(pattern);
        }
        self.allocator.free(self.filters.deny_key_patterns);
    }
};

pub fn loadConfig(allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.ConfigNotFound,
        else => return err,
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch |err| switch (err) {
        error.SyntaxError => return error.InvalidJson,
        else => return err,
    };
    defer parsed.deinit();

    return parseConfig(allocator, parsed.value);
}

fn parseConfig(allocator: std.mem.Allocator, json: std.json.Value) !Config {
    const root_obj = json.object;

    const version_value = root_obj.get("version") orelse return error.MissingVersion;
    const ver = switch (version_value) {
        .integer => |i| @as(u32, @intCast(i)),
        else => return error.InvalidVersion,
    };
    if (ver != 1) return error.UnsupportedVersion;

    const service_value = root_obj.get("service") orelse return error.MissingService;
    const service_obj = service_value.object;
    const service = ServiceConfig{
        .name = try allocator.dupe(u8, service_obj.get("name").?.string),
        .host = try allocator.dupe(u8, service_obj.get("host").?.string),
        .pid = @as(u32, @intCast(service_obj.get("pid").?.integer)),
    };

    const identity_value = root_obj.get("identity") orelse return error.MissingIdentity;
    const identity_obj = identity_value.object;
    const cef_obj = identity_obj.get("cef").?.object;
    const identity = IdentityConfig{
        .cef = CefIdentityConfig{
            .vendor = try allocator.dupe(u8, cef_obj.get("vendor").?.string),
            .product = try allocator.dupe(u8, cef_obj.get("product").?.string),
            .version = try allocator.dupe(u8, cef_obj.get("version").?.string),
        },
    };

    const sinks_value = root_obj.get("sinks") orelse return error.MissingSinks;
    const sinks_obj = sinks_value.object;

    const file_obj = sinks_obj.get("file").?.object;
    const file_sink = FileSinkConfig{
        .enabled = file_obj.get("enabled").?.bool,
        .path = try allocator.dupe(u8, file_obj.get("path").?.string),
        .max_bytes = @as(u64, @intCast(file_obj.get("max_bytes").?.integer)),
        .backup_count = @as(u32, @intCast(file_obj.get("backup_count").?.integer)),
    };

    const syslog_obj = sinks_obj.get("syslog").?.object;
    const rfc5424_obj = syslog_obj.get("rfc5424").?.object;
    const facility_str = rfc5424_obj.get("facility").?.string;
    const syslog_sink = SyslogSinkConfig{
        .enabled = syslog_obj.get("enabled").?.bool,
        .protocol = try SyslogProtocol.fromString(syslog_obj.get("protocol").?.string),
        .host = try allocator.dupe(u8, syslog_obj.get("host").?.string),
        .port = @as(u16, @intCast(syslog_obj.get("port").?.integer)),
        .rfc5424 = SyslogRfc5424Config{
            .facility = try SyslogFacility.fromString(facility_str),
        },
    };

    const sinks = SinksConfig{
        .file = file_sink,
        .syslog = syslog_sink,
    };

    const filters_value = root_obj.get("filters") orelse return error.MissingFilters;
    const filters_obj = filters_value.object;

    const allow_fields_value = filters_obj.get("allow_fields").?.array;
    const allow_fields = try allocator.alloc([]const u8, allow_fields_value.items.len);
    for (allow_fields_value.items, 0..) |item, i| {
        allow_fields[i] = try allocator.dupe(u8, item.string);
    }

    const deny_patterns_value = filters_obj.get("deny_key_patterns").?.array;
    const deny_patterns = try allocator.alloc([]const u8, deny_patterns_value.items.len);
    for (deny_patterns_value.items, 0..) |item, i| {
        deny_patterns[i] = try allocator.dupe(u8, item.string);
    }

    const filters = FiltersConfig{
        .default_deny = filters_obj.get("default_deny").?.bool,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = try PiiMode.fromString(filters_obj.get("pii_mode").?.string),
        .pci_mode = filters_obj.get("pci_mode").?.bool,
    };

    return Config{
        .version = ver,
        .service = service,
        .identity = identity,
        .sinks = sinks,
        .filters = filters,
        .allocator = allocator,
    };
}

/// Create a test configuration with sensible defaults.
/// Uses the library version instead of build_options.
pub fn loadTestConfig(allocator: std.mem.Allocator) !Config {
    const allow_fields = try allocator.alloc([]const u8, 10);
    allow_fields[0] = try allocator.dupe(u8, "actor_id");
    allow_fields[1] = try allocator.dupe(u8, "subject_id");
    allow_fields[2] = try allocator.dupe(u8, "request_id");
    allow_fields[3] = try allocator.dupe(u8, "session_id");
    allow_fields[4] = try allocator.dupe(u8, "source_ip");
    allow_fields[5] = try allocator.dupe(u8, "trace_id");
    allow_fields[6] = try allocator.dupe(u8, "span_id");
    allow_fields[7] = try allocator.dupe(u8, "category");
    allow_fields[8] = try allocator.dupe(u8, "action");
    allow_fields[9] = try allocator.dupe(u8, "outcome");

    const deny_patterns = try allocator.alloc([]const u8, 2);
    deny_patterns[0] = try allocator.dupe(u8, "password");
    deny_patterns[1] = try allocator.dupe(u8, "secret");

    return Config{
        .version = 1,
        .service = ServiceConfig{
            .name = try allocator.dupe(u8, "authsvc"),
            .host = try allocator.dupe(u8, "app-host"),
            .pid = 1234,
        },
        .identity = IdentityConfig{
            .cef = CefIdentityConfig{
                .vendor = try allocator.dupe(u8, "DEVNW"),
                .product = try allocator.dupe(u8, "AUDIT"),
                .version = try allocator.dupe(u8, root.version),
            },
        },
        .sinks = SinksConfig{
            .file = FileSinkConfig{
                .enabled = true,
                .path = try allocator.dupe(u8, "zig-out/tmp/audit.log"),
                .max_bytes = 1048576,
                .backup_count = 5,
            },
            .syslog = SyslogSinkConfig{
                .enabled = true,
                .protocol = .udp,
                .host = try allocator.dupe(u8, "{{SYSLOG_HOST}}"),
                .port = 514,
                .rfc5424 = SyslogRfc5424Config{
                    .facility = .local4,
                },
            },
        },
        .filters = FiltersConfig{
            .default_deny = true,
            .allow_fields = allow_fields,
            .deny_key_patterns = deny_patterns,
            .pii_mode = .mask,
            .pci_mode = true,
        },
        .allocator = allocator,
    };
}
