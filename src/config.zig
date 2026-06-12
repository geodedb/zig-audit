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

/// Durability/throughput tradeoff for the file sink's fsync policy.
///
/// `.per_event` is the DELIBERATE default: this is an audit library, so
/// durability comes first — every event is fsynced before `audit()` returns,
/// making the file-sink path disk-latency-bound. `.periodic` and `.none` are
/// explicit opt-ins for throughput: in this repo's scale-bench, a batched
/// worker with `.none` measured ~13x faster on the file-sink path. Choose
/// them only when losing the tail of the audit log on power loss / crash is
/// an acceptable tradeoff.
pub const SyncMode = enum {
    per_event, // fsync after every write (safest, slowest; the default)
    // fsync once >= N records written (default: 100). The threshold is
    // checked at worker batch boundaries, so under bursts the fsync may
    // land a few records past N (never before).
    periodic,
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
    /// Optional jail directory for `path`. When set, the lexically resolved
    /// `path` must be under the lexically resolved base directory or
    /// `FileSink.init` fails with `error.PathOutsideAllowedBase`.
    ///
    /// Enforcement is LEXICAL only: symlinked parent directories are NOT
    /// resolved (realpath of a not-yet-existing file is unreliable), so a
    /// symlink inside the base can still point outside it. Operators who
    /// need symlink-safe containment must guarantee the base directory
    /// tree contains no hostile symlinks.
    ///
    /// When null, `path` is trusted as-is (including absolute paths) — the
    /// component-wise `..` check still applies. Set this to confine log
    /// output below a base directory. Must not be the empty string
    /// (`parseConfig` rejects "" with `error.InvalidConfig`).
    allowed_base_dir: ?[]const u8 = null,
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
        if (self.sinks.file.allowed_base_dir) |base| {
            self.allocator.free(base);
        }
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

    // ADV-1: every dupe in the parse helpers below is paired with an
    // errdefer so a mid-parse error (wrong type, out-of-range integer,
    // OOM, ...) frees everything allocated so far. Each helper cleans up
    // its OWN partial allocations on failure; the errdefers HERE free a
    // helper's successfully-returned members when a LATER helper fails. On
    // success none of them fire and ownership of all heap members transfers
    // to the returned Config (freed by its deinit). Mirrors the
    // errdefer-chain style of events.zig clone().

    const service = try parseService(allocator, root_obj);
    errdefer {
        allocator.free(service.name);
        allocator.free(service.host);
    }

    const identity = try parseIdentity(allocator, root_obj);
    errdefer {
        allocator.free(identity.cef.vendor);
        allocator.free(identity.cef.product);
        allocator.free(identity.cef.version);
    }

    const sinks = try parseSinks(allocator, root_obj);
    errdefer {
        allocator.free(sinks.file.path);
        if (sinks.file.allowed_base_dir) |base| allocator.free(base);
        allocator.free(sinks.syslog.host);
    }

    const filters = try parseFilters(allocator, root_obj);
    errdefer {
        for (filters.allow_fields) |field| allocator.free(field);
        allocator.free(filters.allow_fields);
        for (filters.deny_key_patterns) |pattern| allocator.free(pattern);
        allocator.free(filters.deny_key_patterns);
    }

    return Config{
        .version = ver,
        .service = service,
        .identity = identity,
        .sinks = sinks,
        .filters = filters,
        .allocator = allocator,
    };
}

/// Parse the `service` section. On success the caller owns `name`/`host`;
/// on error every partial allocation is freed here (ADV-1).
fn parseService(allocator: std.mem.Allocator, root_obj: std.json.ObjectMap) !ServiceConfig {
    const service_value = root_obj.get("service") orelse return error.MissingService;
    if (service_value != .object) return error.InvalidConfig;
    const service_obj = service_value.object;
    const service_name = try allocator.dupe(u8, try jsonString(service_obj, "name"));
    errdefer allocator.free(service_name);
    const service_host = try allocator.dupe(u8, try jsonString(service_obj, "host"));
    errdefer allocator.free(service_host);
    return ServiceConfig{
        .name = service_name,
        .host = service_host,
        .pid = try jsonIntegerInRange(u32, service_obj, "pid"),
    };
}

/// Parse the `identity` section. On success the caller owns the three CEF
/// strings; on error every partial allocation is freed here (ADV-1).
fn parseIdentity(allocator: std.mem.Allocator, root_obj: std.json.ObjectMap) !IdentityConfig {
    const identity_value = root_obj.get("identity") orelse return error.MissingIdentity;
    if (identity_value != .object) return error.InvalidConfig;
    const identity_obj = identity_value.object;
    const cef_obj = try jsonObject(identity_obj, "cef");
    const cef_vendor = try allocator.dupe(u8, try jsonString(cef_obj, "vendor"));
    errdefer allocator.free(cef_vendor);
    const cef_product = try allocator.dupe(u8, try jsonString(cef_obj, "product"));
    errdefer allocator.free(cef_product);
    const cef_version = try allocator.dupe(u8, try jsonString(cef_obj, "version"));
    errdefer allocator.free(cef_version);
    return IdentityConfig{
        .cef = CefIdentityConfig{
            .vendor = cef_vendor,
            .product = cef_product,
            .version = cef_version,
        },
    };
}

/// Parse the `sinks` section (file + syslog). On success the caller owns
/// `file.path`, `file.allowed_base_dir`, and `syslog.host`; on error every
/// partial allocation is freed here (ADV-1).
fn parseSinks(allocator: std.mem.Allocator, root_obj: std.json.ObjectMap) !SinksConfig {
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

    const allowed_base_dir: ?[]const u8 = blk: {
        const val = file_obj.get("allowed_base_dir") orelse break :blk null;
        if (val != .string) return error.InvalidConfig;
        // An empty jail is meaningless (it would lexically resolve to "."
        // and reject every path) — almost certainly a config mistake, so
        // fail loudly at parse time. Omit the key to disable the jail.
        if (val.string.len == 0) return error.InvalidConfig;
        break :blk try allocator.dupe(u8, val.string);
    };
    errdefer if (allowed_base_dir) |base| allocator.free(base);

    const file_path = try allocator.dupe(u8, try jsonString(file_obj, "path"));
    errdefer allocator.free(file_path);

    const file_sink = FileSinkConfig{
        .enabled = try jsonBool(file_obj, "enabled"),
        .path = file_path,
        .max_bytes = try jsonIntegerInRange(u64, file_obj, "max_bytes"),
        .backup_count = try jsonIntegerInRange(u32, file_obj, "backup_count"),
        .sync_mode = sync_mode,
        .sync_interval = sync_interval,
        .allowed_base_dir = allowed_base_dir,
    };

    const syslog_obj = try jsonObject(sinks_obj, "syslog");
    const rfc5424_obj = try jsonObject(syslog_obj, "rfc5424");
    const facility_str = try jsonString(rfc5424_obj, "facility");
    const port = try jsonIntegerInRange(u16, syslog_obj, "port");
    if (port == 0) return error.InvalidConfig;
    const syslog_host = try allocator.dupe(u8, try jsonString(syslog_obj, "host"));
    errdefer allocator.free(syslog_host);
    const syslog_sink = SyslogSinkConfig{
        .enabled = try jsonBool(syslog_obj, "enabled"),
        .protocol = try SyslogProtocol.fromString(try jsonString(syslog_obj, "protocol")),
        .host = syslog_host,
        .port = port,
        .rfc5424 = SyslogRfc5424Config{
            .facility = try SyslogFacility.fromString(facility_str),
        },
    };

    return SinksConfig{
        .file = file_sink,
        .syslog = syslog_sink,
    };
}

/// Parse the `filters` section. On success the caller owns both string
/// arrays and their elements; on error every partial allocation is freed
/// here (ADV-1).
fn parseFilters(allocator: std.mem.Allocator, root_obj: std.json.ObjectMap) !FiltersConfig {
    const filters_value = root_obj.get("filters") orelse return error.MissingFilters;
    if (filters_value != .object) return error.InvalidConfig;
    const filters_obj = filters_value.object;

    const allow_fields_arr = try jsonArray(filters_obj, "allow_fields");
    const allow_fields = try allocator.alloc([]const u8, allow_fields_arr.items.len);
    var allow_fields_count: usize = 0;
    errdefer {
        // Free only the populated prefix plus the slice itself.
        for (allow_fields[0..allow_fields_count]) |field| allocator.free(field);
        allocator.free(allow_fields);
    }
    for (allow_fields_arr.items, 0..) |item, i| {
        if (item != .string) return error.InvalidConfig;
        allow_fields[i] = try allocator.dupe(u8, item.string);
        allow_fields_count = i + 1;
    }

    const deny_patterns_arr = try jsonArray(filters_obj, "deny_key_patterns");
    const deny_patterns = try allocator.alloc([]const u8, deny_patterns_arr.items.len);
    var deny_patterns_count: usize = 0;
    errdefer {
        for (deny_patterns[0..deny_patterns_count]) |pattern| allocator.free(pattern);
        allocator.free(deny_patterns);
    }
    for (deny_patterns_arr.items, 0..) |item, i| {
        if (item != .string) return error.InvalidConfig;
        deny_patterns[i] = try allocator.dupe(u8, item.string);
        deny_patterns_count = i + 1;
    }

    return FiltersConfig{
        .default_deny = try jsonBool(filters_obj, "default_deny"),
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = try PiiMode.fromString(try jsonString(filters_obj, "pii_mode")),
        .pci_mode = try jsonBool(filters_obj, "pci_mode"),
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

test "parseConfig parses optional allowed_base_dir (GAP-043/A4)" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{
        \\  "version": 1,
        \\  "service": {"name": "svc", "host": "h", "pid": 1},
        \\  "identity": {"cef": {"vendor": "V", "product": "P", "version": "1"}},
        \\  "sinks": {
        \\    "file": {"enabled": false, "path": "/var/log/audit/a.log", "max_bytes": 1024, "backup_count": 1, "allowed_base_dir": "/var/log/audit"},
        \\    "syslog": {"enabled": false, "protocol": "udp", "host": "localhost", "port": 514, "rfc5424": {"facility": "local0"}}
        \\  },
        \\  "filters": {"default_deny": false, "allow_fields": [], "deny_key_patterns": [], "pii_mode": "off", "pci_mode": false}
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var cfg = try parseConfig(allocator, parsed.value);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("/var/log/audit", cfg.sinks.file.allowed_base_dir.?);
}

test "parseConfig rejects empty allowed_base_dir (GAP-043 review follow-up)" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{
        \\  "version": 1,
        \\  "service": {"name": "svc", "host": "h", "pid": 1},
        \\  "identity": {"cef": {"vendor": "V", "product": "P", "version": "1"}},
        \\  "sinks": {
        \\    "file": {"enabled": false, "path": "/var/log/audit/a.log", "max_bytes": 1024, "backup_count": 1, "allowed_base_dir": ""},
        \\    "syslog": {"enabled": false, "protocol": "udp", "host": "localhost", "port": 514, "rfc5424": {"facility": "local0"}}
        \\  },
        \\  "filters": {"default_deny": false, "allow_fields": [], "deny_key_patterns": [], "pii_mode": "off", "pci_mode": false}
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidConfig, parseConfig(allocator, parsed.value));
}

test "parseConfig defaults allowed_base_dir to null when absent (GAP-043/A4)" {
    const allocator = std.testing.allocator;
    var parsed = try buildValidTestJson(allocator);
    defer parsed.deinit();

    var cfg = try parseConfig(allocator, parsed.value);
    defer cfg.deinit();

    try std.testing.expect(cfg.sinks.file.allowed_base_dir == null);
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
    // std.testing.allocator's leak check doubles as the regression proof
    // that parseConfig frees every earlier dupe on mid-parse errors (ADV-1).
    const allocator = std.testing.allocator;

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
