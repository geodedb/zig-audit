// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const config = @import("config.zig");

pub const FilterResult = enum {
    allow,
    redact,
    drop_event,
};

pub const RedactionToken = enum {
    password,
    token,
    jwt,
    card,
    cvv,
    ssn,
    iban,
    private_key,
    email,
    phone,

    pub fn toString(self: RedactionToken) []const u8 {
        return switch (self) {
            .password => "[REDACTED]",
            .token => "[REDACTED_TOKEN]",
            .jwt => "[REDACTED_JWT]",
            .card => "[REDACTED_PAN]",
            .cvv => "[REDACTED_CVV]",
            .ssn => "[REDACTED_SSN]",
            .iban => "[REDACTED_IBAN]",
            .private_key => "[REDACTED_PK]",
            .email => "[REDACTED_EMAIL]",
            .phone => "[REDACTED_PHONE]",
        };
    }
};

pub fn isSensitiveKey(allocator: std.mem.Allocator, key: []const u8) ?RedactionToken {
    const lower_key = std.ascii.allocLowerString(allocator, key) catch return null;
    defer allocator.free(lower_key);

    // Password-related
    if (std.mem.indexOf(u8, lower_key, "password") != null or
        std.mem.indexOf(u8, lower_key, "passwd") != null) return .password;

    // Token-related
    if (std.mem.indexOf(u8, lower_key, "token") != null or
        std.mem.indexOf(u8, lower_key, "apikey") != null or
        std.mem.indexOf(u8, lower_key, "api_key") != null) return .token;

    // JWT
    if (std.mem.indexOf(u8, lower_key, "jwt") != null) return .jwt;

    // Payment card
    if (std.mem.indexOf(u8, lower_key, "card") != null or
        std.mem.indexOf(u8, lower_key, "cc") != null or
        std.mem.indexOf(u8, lower_key, "pan") != null) return .card;

    // CVV
    if (std.mem.indexOf(u8, lower_key, "cvv") != null or
        std.mem.indexOf(u8, lower_key, "cvc") != null) return .cvv;

    // SSN/SIN/NIN
    if (std.mem.indexOf(u8, lower_key, "ssn") != null or
        std.mem.indexOf(u8, lower_key, "sin") != null or
        std.mem.indexOf(u8, lower_key, "nin") != null) return .ssn;

    // IBAN
    if (std.mem.indexOf(u8, lower_key, "iban") != null) return .iban;

    // Private keys
    if (std.mem.indexOf(u8, lower_key, "private_key") != null or
        std.mem.indexOf(u8, lower_key, "privkey") != null) return .private_key;

    // PII
    if (std.mem.indexOf(u8, lower_key, "email") != null) return .email;
    if (std.mem.indexOf(u8, lower_key, "phone") != null) return .phone;

    // Session/cookie
    if (std.mem.indexOf(u8, lower_key, "cookie") != null or
        std.mem.indexOf(u8, lower_key, "session") != null) return .token;

    return null;
}

pub fn isJwt(value: []const u8) bool {
    var segments: u8 = 0;
    var in_segment = false;
    var segment_length: usize = 0;

    for (value) |c| {
        if (c == '.') {
            if (!in_segment or segment_length == 0) return false;
            segments += 1;
            in_segment = false;
            segment_length = 0;
        } else if (isBase64UrlChar(c)) {
            if (!in_segment) {
                in_segment = true;
            }
            segment_length += 1;
        } else {
            return false;
        }
    }

    return segments == 2 and in_segment and segment_length > 0;
}

fn isBase64UrlChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '-' or c == '_';
}

pub fn isPan(value: []const u8) bool {
    var digits: [32]u8 = undefined;
    var digit_count: usize = 0;

    for (value) |c| {
        if (c >= '0' and c <= '9') {
            if (digit_count >= digits.len) return false;
            digits[digit_count] = c - '0';
            digit_count += 1;
        } else if (c != ' ' and c != '-') {
            return false;
        }
    }

    if (digit_count < 13 or digit_count > 19) return false;

    // Luhn algorithm
    var sum: u32 = 0;
    var alternate = false;
    var i = digit_count;
    while (i > 0) {
        i -= 1;
        var digit = digits[i];
        if (alternate) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        alternate = !alternate;
    }

    return sum % 10 == 0;
}

pub fn isEmail(value: []const u8) bool {
    const at_pos = std.mem.indexOf(u8, value, "@") orelse return false;
    if (at_pos == 0 or at_pos == value.len - 1) return false;

    const local = value[0..at_pos];
    const domain = value[at_pos + 1 ..];

    if (local.len == 0 or domain.len == 0) return false;

    for (local) |c| {
        if (c > 127) return false;
    }

    for (domain) |c| {
        if (c > 127) return false;
    }

    return std.mem.indexOf(u8, domain, ".") != null;
}

pub fn isPhone(value: []const u8) bool {
    var digit_count: usize = 0;
    for (value) |c| {
        if (c >= '0' and c <= '9') {
            digit_count += 1;
        } else if (c != ' ' and c != '-' and c != '(' and c != ')' and c != '+') {
            return false;
        }
    }
    return digit_count >= 10 and digit_count <= 15;
}

pub fn isPemPrivateKey(value: []const u8) bool {
    return std.mem.indexOf(u8, value, "-----BEGIN") != null and
        std.mem.indexOf(u8, value, "PRIVATE KEY-----") != null;
}

pub fn maskEmail(allocator: std.mem.Allocator, email_addr: []const u8) ![]const u8 {
    const at_pos = std.mem.indexOf(u8, email_addr, "@") orelse return allocator.dupe(u8, email_addr);
    const domain = email_addr[at_pos..];
    return std.fmt.allocPrint(allocator, "***{s}", .{domain});
}

pub fn maskPhone(allocator: std.mem.Allocator, phone: []const u8) ![]const u8 {
    var digits: [32]u8 = undefined;
    var digit_count: usize = 0;
    for (phone) |c| {
        if (c >= '0' and c <= '9') {
            if (digit_count < digits.len) {
                digits[digit_count] = c;
                digit_count += 1;
            }
        }
    }

    if (digit_count < 10) return allocator.dupe(u8, phone);

    const first_part = digits[0..3];
    const last_part = digits[digit_count - 4 .. digit_count];
    return std.fmt.allocPrint(allocator, "{s}***{s}", .{ first_part, last_part });
}

pub fn detectValueType(value: []const u8) ?RedactionToken {
    if (isJwt(value)) return .jwt;
    if (isPan(value)) return .card;
    if (isEmail(value)) return .email;
    if (isPhone(value)) return .phone;
    if (isPemPrivateKey(value)) return .private_key;

    if (value.len >= 64 and isHexString(value)) return .token;
    if (value.len == 3 and isAllDigits(value)) return .cvv;

    return null;
}

fn isHexString(s: []const u8) bool {
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) {
            return false;
        }
    }
    return true;
}

fn isAllDigits(s: []const u8) bool {
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

pub fn filterAndRedactMetadata(
    allocator: std.mem.Allocator,
    metadata: std.json.Value,
    filters: *const config.FiltersConfig,
) !?std.json.Value {
    return switch (metadata) {
        .object => |obj| blk: {
            var filtered_map = std.json.ObjectMap.init(allocator);
            errdefer filtered_map.deinit();

            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const key = entry.key_ptr.*;
                const value = entry.value_ptr.*;

                const filter_result = shouldFilterField(allocator, key, value, filters);
                switch (filter_result) {
                    .allow => {
                        const cloned_value = try cloneJsonValue(allocator, value);
                        try filtered_map.put(try allocator.dupe(u8, key), cloned_value);
                    },
                    .redact => {
                        if (isSensitiveKey(allocator, key)) |redaction_token| {
                            const redacted = std.json.Value{ .string = try allocator.dupe(u8, redaction_token.toString()) };
                            try filtered_map.put(try allocator.dupe(u8, key), redacted);
                        }
                    },
                    .drop_event => {
                        filtered_map.deinit();
                        return null;
                    },
                }
            }

            break :blk std.json.Value{ .object = filtered_map };
        },
        else => metadata,
    };
}

fn shouldFilterField(allocator: std.mem.Allocator, key: []const u8, value: std.json.Value, filters: *const config.FiltersConfig) FilterResult {
    const is_allowed = for (filters.allow_fields) |allowed_field| {
        if (std.mem.eql(u8, key, allowed_field)) break true;
    } else false;

    const is_denied = for (filters.deny_key_patterns) |pattern| {
        if (std.ascii.indexOfIgnoreCase(key, pattern) != null) break true;
    } else false;

    const sensitive_token = isSensitiveKey(allocator, key);

    if (is_denied or sensitive_token != null) {
        if (value == .string) {
            const str_value = value.string;
            if (isPemPrivateKey(str_value) and !std.mem.startsWith(u8, str_value, "-----BEGIN")) {
                return .drop_event;
            }
        }
        return .redact;
    }

    if (filters.default_deny and !is_allowed) {
        return .redact;
    }

    if (value == .string) {
        const detected_type = detectValueType(value.string);
        if (detected_type != null) {
            return .redact;
        }
    }

    return .allow;
}

fn cloneJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    return switch (value) {
        .null => .null,
        .bool => |b| std.json.Value{ .bool = b },
        .integer => |i| std.json.Value{ .integer = i },
        .float => |f| std.json.Value{ .float = f },
        .number_string => |ns| std.json.Value{ .number_string = try allocator.dupe(u8, ns) },
        .string => |s| std.json.Value{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var cloned_array = std.json.Array.init(allocator);
            for (arr.items) |item| {
                try cloned_array.append(try cloneJsonValue(allocator, item));
            }
            break :blk std.json.Value{ .array = cloned_array };
        },
        .object => |obj| blk: {
            var cloned_map = std.json.ObjectMap.init(allocator);
            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const cloned_key = try allocator.dupe(u8, entry.key_ptr.*);
                const cloned_value = try cloneJsonValue(allocator, entry.value_ptr.*);
                try cloned_map.put(cloned_key, cloned_value);
            }
            break :blk std.json.Value{ .object = cloned_map };
        },
    };
}
