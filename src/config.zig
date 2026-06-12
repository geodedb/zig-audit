// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Audit configuration types and JSON config file parsing.
//! Defines service, sink, filter, and identity configuration structs.

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

pub const SyncMode = enum {
    per_event, // fsync after every write (safest, slowest)
    periodic, // fsync every N events (default: 100)
    none, // no explicit fsync — let OS handle it

    pub fn fromString(s: []const u8) !SyncMode {
        if (std.mem.eql(u8, s, "per_event")) return .per_event;
        if (std.mem.eql(u8, s, "periodic")) return .periodic;
        if (std.mem.eql(u8, s, "none")) return .none;
        return error.InvalidSyncMode;
    }
};

pub const FileSinkConfig = struct {
    enabled: bool,
    path: []const u8,
    max_bytes: u64,
    backup_count: u32,
    sync_mode: SyncMode = .per_event,
    sync_interval: u32 = 100,
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

/// Parsed configuration. OWNERSHIP: `AuditLogger.init`/`buildAuditLogger`
/// take ownership of a `Config` passed to them — the logger calls
/// `config.deinit()` in its own `deinit()`. Callers must NOT call `deinit()`
/// on a Config after handing it to a logger, and must not retain copies
/// (the struct embeds heap pointers).
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
    const io = std.Io.Threaded.global_single_threaded.io();
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return error.ConfigNotFound,
        else => return err,
    };
    defer allocator.free(content);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch |err| switch (err) {
        error.SyntaxError => return error.InvalidJson,
        else => return err,
    };
    defer parsed.deinit();

    return parseConfig(allocator, parsed.value);
}

/// Safely extract a string from a json value, returning error.InvalidConfig if missing or wrong type.
fn jsonString(obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const val = obj.get(key) orelse return error.InvalidConfig;
    if (val != .string) return error.InvalidConfig;
    return val.string;
}

/// Safely extract an integer from a json value, returning error.InvalidConfig if missing or wrong type.
fn jsonInteger(obj: std.json.ObjectMap, key: []const u8) !i64 {
    const val = obj.get(key) orelse return error.InvalidConfig;
    if (val != .integer) return error.InvalidConfig;
    return val.integer;
}

/// Safely extract an integer from a json value and range-check it into `T`,
/// returning error.InvalidConfig if missing, wrong type, negative (for
/// unsigned targets), or out of range for `T`.
fn jsonIntegerInRange(comptime T: type, obj: std.json.ObjectMap, key: []const u8) !T {
    const raw = try jsonInteger(obj, key);
    return std.math.cast(T, raw) orelse error.InvalidConfig;
}

/// Safely extract a bool from a json value, returning error.InvalidConfig if missing or wrong type.
fn jsonBool(obj: std.json.ObjectMap, key: []const u8) !bool {
    const val = obj.get(key) orelse return error.InvalidConfig;
    if (val != .bool) return error.InvalidConfig;
    return val.bool;
}

/// Safely extract an object from a json value, returning error.InvalidConfig if missing or wrong type.
fn jsonObject(obj: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const val = obj.get(key) orelse return error.InvalidConfig;
    if (val != .object) return error.InvalidConfig;
    return val.object;
}

/// Safely extract an array from a json value, returning error.InvalidConfig if missing or wrong type.
fn jsonArray(obj: std.json.ObjectMap, key: []const u8) !std.json.Array {
    const val = obj.get(key) orelse return error.InvalidConfig;
    if (val != .array) return error.InvalidConfig;
    return val.array;
}

fn parseConfig(allocator: std.mem.Allocator, json: std.json.Value) !Config {
    if (json != .object) return error.InvalidConfig;
    const root_obj = json.object;

    const version_value = root_obj.get("version") orelse return error.MissingVersion;
    const ver = switch (version_value) {
        .integer => |i| std.math.cast(u32, i) orelse return error.InvalidConfig,
        else => return error.InvalidVersion,
    };
    if (ver != 1) return error.UnsupportedVersion;

    const service_value = root_obj.get("service") orelse return error.MissingService;
    if (service_value != .object) return error.InvalidConfig;
    const service_obj = service_value.object;
    const service = ServiceConfig{
        .name = try allocator.dupe(u8, try jsonString(service_obj, "name")),
        .host = try allocator.dupe(u8, try jsonString(service_obj, "host")),
        .pid = try jsonIntegerInRange(u32, service_obj, "pid"),
    };

    const identity_value = root_obj.get("identity") orelse return error.MissingIdentity;
    if (identity_value != .object) return error.InvalidConfig;
    const identity_obj = identity_value.object;
    const cef_obj = try jsonObject(identity_obj, "cef");
    const identity = IdentityConfig{
        .cef = CefIdentityConfig{
            .vendor = try allocator.dupe(u8, try jsonString(cef_obj, "vendor")),
            .product = try allocator.dupe(u8, try jsonString(cef_obj, "product")),
            .version = try allocator.dupe(u8, try jsonString(cef_obj, "version")),
        },
    };

    const sinks_value = root_obj.get("sinks") orelse return error.MissingSinks;
    if (sinks_value != .object) return error.InvalidConfig;
    const sinks_obj = sinks_value.object;

    const file_obj = try jsonObject(sinks_obj, "file");

    const sync_mode: SyncMode = blk: {
        const val = file_obj.get("sync_mode") orelse break :blk .per_event;
        if (val != .string) return error.InvalidConfig;
        break :blk SyncMode.fromString(val.string) catch return error.InvalidConfig;
    };

    const sync_interval: u32 = blk: {
        if (file_obj.get("sync_interval") == null) break :blk 100;
        break :blk try jsonIntegerInRange(u32, file_obj, "sync_interval");
    };

    const file_sink = FileSinkConfig{
        .enabled = try jsonBool(file_obj, "enabled"),
        .path = try allocator.dupe(u8, try jsonString(file_obj, "path")),
        .max_bytes = try jsonIntegerInRange(u64, file_obj, "max_bytes"),
        .backup_count = try jsonIntegerInRange(u32, file_obj, "backup_count"),
        .sync_mode = sync_mode,
        .sync_interval = sync_interval,
    };

    const syslog_obj = try jsonObject(sinks_obj, "syslog");
    const rfc5424_obj = try jsonObject(syslog_obj, "rfc5424");
    const facility_str = try jsonString(rfc5424_obj, "facility");
    const port = try jsonIntegerInRange(u16, syslog_obj, "port");
    if (port == 0) return error.InvalidConfig;
    const syslog_sink = SyslogSinkConfig{
        .enabled = try jsonBool(syslog_obj, "enabled"),
        .protocol = try SyslogProtocol.fromString(try jsonString(syslog_obj, "protocol")),
        .host = try allocator.dupe(u8, try jsonString(syslog_obj, "host")),
        .port = port,
        .rfc5424 = SyslogRfc5424Config{
            .facility = try SyslogFacility.fromString(facility_str),
        },
    };

    const sinks = SinksConfig{
        .file = file_sink,
        .syslog = syslog_sink,
    };

    const filters_value = root_obj.get("filters") orelse return error.MissingFilters;
    if (filters_value != .object) return error.InvalidConfig;
    const filters_obj = filters_value.object;

    const allow_fields_arr = try jsonArray(filters_obj, "allow_fields");
    const allow_fields = try allocator.alloc([]const u8, allow_fields_arr.items.len);
    for (allow_fields_arr.items, 0..) |item, i| {
        if (item != .string) return error.InvalidConfig;
        allow_fields[i] = try allocator.dupe(u8, item.string);
    }

    const deny_patterns_arr = try jsonArray(filters_obj, "deny_key_patterns");
    const deny_patterns = try allocator.alloc([]const u8, deny_patterns_arr.items.len);
    for (deny_patterns_arr.items, 0..) |item, i| {
        if (item != .string) return error.InvalidConfig;
        deny_patterns[i] = try allocator.dupe(u8, item.string);
    }

    const filters = FiltersConfig{
        .default_deny = try jsonBool(filters_obj, "default_deny"),
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = try PiiMode.fromString(try jsonString(filters_obj, "pii_mode")),
        .pci_mode = try jsonBool(filters_obj, "pci_mode"),
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

/// Build a complete valid JSON config object for testing purposes.
/// Caller must call parsed.deinit() when done.
fn buildValidTestJson(allocator: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    const valid_json =
        \\{
        \\  "version": 1,
        \\  "service": {"name": "svc", "host": "h", "pid": 1},
        \\  "identity": {"cef": {"vendor": "V", "product": "P", "version": "1"}},
        \\  "sinks": {
        \\    "file": {"enabled": false, "path": "/tmp/a.log", "max_bytes": 1024, "backup_count": 1},
        \\    "syslog": {"enabled": false, "protocol": "udp", "host": "localhost", "port": 514, "rfc5424": {"facility": "local0"}}
        \\  },
        \\  "filters": {"default_deny": false, "allow_fields": [], "deny_key_patterns": [], "pii_mode": "off", "pci_mode": false}
        \\}
    ;
    return std.json.parseFromSlice(std.json.Value, allocator, valid_json, .{});
}

test "parseConfig rejects missing version" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"service": {"name": "s", "host": "h", "pid": 1}}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.MissingVersion, parseConfig(allocator, parsed.value));
}

test "parseConfig rejects invalid version type" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"version": "one"}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidVersion, parseConfig(allocator, parsed.value));
}

test "parseConfig rejects unsupported version" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"version": 99}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.UnsupportedVersion, parseConfig(allocator, parsed.value));
}

test "parseConfig rejects missing service" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"version": 1}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.MissingService, parseConfig(allocator, parsed.value));
}

test "parseConfig rejects missing service.name" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"version": 1, "service": {"host": "h", "pid": 1}}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidConfig, parseConfig(allocator, parsed.value));
}

test "parseConfig rejects wrong type for service.name" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"version": 1, "service": {"name": 42, "host": "h", "pid": 1}}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidConfig, parseConfig(allocator, parsed.value));
}

test "parseConfig accepts valid complete config" {
    const allocator = std.testing.allocator;
    var parsed = try buildValidTestJson(allocator);
    defer parsed.deinit();

    var cfg = try parseConfig(allocator, parsed.value);
    defer cfg.deinit();

    try std.testing.expectEqual(@as(u32, 1), cfg.version);
    try std.testing.expectEqualStrings("svc", cfg.service.name);
    try std.testing.expectEqualStrings("h", cfg.service.host);
    try std.testing.expectEqual(@as(u32, 1), cfg.service.pid);

    // sync_mode defaults to per_event when absent from JSON
    try std.testing.expectEqual(SyncMode.per_event, cfg.sinks.file.sync_mode);
    try std.testing.expectEqual(@as(u32, 100), cfg.sinks.file.sync_interval);
}

test "parseConfig parses sync_mode and sync_interval from JSON" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{
        \\  "version": 1,
        \\  "service": {"name": "svc", "host": "h", "pid": 1},
        \\  "identity": {"cef": {"vendor": "V", "product": "P", "version": "1"}},
        \\  "sinks": {
        \\    "file": {"enabled": false, "path": "/tmp/a.log", "max_bytes": 1024, "backup_count": 1, "sync_mode": "periodic", "sync_interval": 50},
        \\    "syslog": {"enabled": false, "protocol": "udp", "host": "localhost", "port": 514, "rfc5424": {"facility": "local0"}}
        \\  },
        \\  "filters": {"default_deny": false, "allow_fields": [], "deny_key_patterns": [], "pii_mode": "off", "pci_mode": false}
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var cfg = try parseConfig(allocator, parsed.value);
    defer cfg.deinit();

    try std.testing.expectEqual(SyncMode.periodic, cfg.sinks.file.sync_mode);
    try std.testing.expectEqual(@as(u32, 50), cfg.sinks.file.sync_interval);
}

test "parseConfig parses sync_mode none" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{
        \\  "version": 1,
        \\  "service": {"name": "svc", "host": "h", "pid": 1},
        \\  "identity": {"cef": {"vendor": "V", "product": "P", "version": "1"}},
        \\  "sinks": {
        \\    "file": {"enabled": false, "path": "/tmp/a.log", "max_bytes": 1024, "backup_count": 1, "sync_mode": "none"},
        \\    "syslog": {"enabled": false, "protocol": "udp", "host": "localhost", "port": 514, "rfc5424": {"facility": "local0"}}
        \\  },
        \\  "filters": {"default_deny": false, "allow_fields": [], "deny_key_patterns": [], "pii_mode": "off", "pci_mode": false}
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var cfg = try parseConfig(allocator, parsed.value);
    defer cfg.deinit();

    try std.testing.expectEqual(SyncMode.none, cfg.sinks.file.sync_mode);
    // sync_interval defaults to 100 when not provided
    try std.testing.expectEqual(@as(u32, 100), cfg.sinks.file.sync_interval);
}

test "parseConfig rejects out-of-range integer fields (GAP-040/A1)" {
    // parseConfig is not leak-safe on mid-parse errors (pre-existing: no
    // errdefer on earlier dupes), so run the error cases under an arena.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Template: every integer field is substitutable so each case can
    // poison exactly one field while keeping the rest valid.
    const template =
        \\{{
        \\  "version": {s},
        \\  "service": {{"name": "svc", "host": "h", "pid": {s}}},
        \\  "identity": {{"cef": {{"vendor": "V", "product": "P", "version": "1"}}}},
        \\  "sinks": {{
        \\    "file": {{"enabled": false, "path": "/tmp/a.log", "max_bytes": {s}, "backup_count": {s}, "sync_interval": {s}}},
        \\    "syslog": {{"enabled": false, "protocol": "udp", "host": "localhost", "port": {s}, "rfc5424": {{"facility": "local0"}}}}
        \\  }},
        \\  "filters": {{"default_deny": false, "allow_fields": [], "deny_key_patterns": [], "pii_mode": "off", "pci_mode": false}}
        \\}}
    ;

    const Case = struct {
        version: []const u8 = "1",
        pid: []const u8 = "1",
        max_bytes: []const u8 = "1024",
        backup_count: []const u8 = "1",
        sync_interval: []const u8 = "100",
        port: []const u8 = "514",
    };

    const cases = [_]Case{
        .{ .version = "4294967296" }, // > u32 max
        .{ .pid = "-5" }, // negative
        .{ .pid = "4294967296" }, // > u32 max
        .{ .max_bytes = "-1" }, // negative
        .{ .backup_count = "-1" }, // negative
        .{ .backup_count = "4294967296" }, // > u32 max
        .{ .sync_interval = "-1" }, // negative
        .{ .port = "99999" }, // > u16 max
        .{ .port = "-1" }, // negative
        .{ .port = "0" }, // port 0 is not a routable listener port
    };

    for (cases) |c| {
        const json_str = try std.fmt.allocPrint(allocator, template, .{
            c.version, c.pid, c.max_bytes, c.backup_count, c.sync_interval, c.port,
        });
        defer allocator.free(json_str);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try std.testing.expectError(error.InvalidConfig, parseConfig(allocator, parsed.value));
    }
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
