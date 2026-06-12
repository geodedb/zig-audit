// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Metadata filtering, sensitive-key detection, and PII/PCI data redaction.
//! Supports configurable allow/deny lists, value-type heuristics, and masking modes.

const std = @import("std");
const config = @import("config.zig");
const json_util = @import("json_util.zig");

pub const FilterResult = union(enum) {
    allow: void,
    redact: ?RedactionToken, // token from isSensitiveKey; null for deny-pattern or value-only match
    drop_event: void,
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
    _ = allocator; // no longer needed; lowercase conversion uses stack buffer
    var buf: [256]u8 = undefined;
    if (key.len > buf.len) return null; // oversized keys are not sensitive
    const lower_key = buf[0..key.len];
    for (key, 0..) |c, i| {
        lower_key[i] = std.ascii.toLower(c);
    }

    // Password-related
    if (std.mem.indexOf(u8, lower_key, "password") != null or
        std.mem.indexOf(u8, lower_key, "passwd") != null or
        std.mem.indexOf(u8, lower_key, "passphrase") != null) return .password;

    // Token-related
    if (std.mem.indexOf(u8, lower_key, "token") != null or
        std.mem.indexOf(u8, lower_key, "apikey") != null or
        std.mem.indexOf(u8, lower_key, "api_key") != null) return .token;

    // Secret/credential/auth-related
    if (std.mem.indexOf(u8, lower_key, "secret") != null or
        std.mem.indexOf(u8, lower_key, "credential") != null or
        std.mem.indexOf(u8, lower_key, "bearer") != null or
        std.mem.indexOf(u8, lower_key, "authorization") != null or
        std.mem.indexOf(u8, lower_key, "access_key") != null) return .token;

    // JWT
    if (std.mem.indexOf(u8, lower_key, "jwt") != null) return .jwt;

    // Payment card
    if (std.mem.indexOf(u8, lower_key, "card") != null or
        std.mem.indexOf(u8, lower_key, "cc") != null or
        std.mem.indexOf(u8, lower_key, "pan") != null) return .card;

    // Banking PIN
    if (std.mem.indexOf(u8, lower_key, "pin") != null) return .card;

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

/// Like detectValueType, but respects pii_mode and pci_mode settings.
/// When pii_mode == .off, PII types (email, phone) are not detected.
/// PCI types (card, cvv) are always detected when pci_mode is true,
/// and follow normal detection when pci_mode is false.
fn detectValueTypeFiltered(value: []const u8, filters_cfg: *const config.FiltersConfig) ?RedactionToken {
    if (isJwt(value)) return .jwt;
    if (isPan(value)) return .card;
    if (isPemPrivateKey(value)) return .private_key;

    if (filters_cfg.pii_mode != .off) {
        if (isEmail(value)) return .email;
        if (isPhone(value)) return .phone;
    }

    if (value.len >= 64 and isHexString(value)) return .token;
    if (value.len == 3 and isAllDigits(value)) return .cvv;

    return null;
}

/// Deterministic pseudonymization for pii_mode == .hash:
/// `sha256:<first 16 hex chars of SHA-256(value)>`.
///
/// LIMITATION: this is an unkeyed hash of low-entropy PII (emails, phone
/// numbers), so it is vulnerable to dictionary/brute-force attacks — anyone
/// with a candidate value can confirm it by hashing. Treat the output as
/// correlatable-but-not-secret: it lets log consumers join events for the
/// same subject without exposing the raw value, but it is NOT a substitute
/// for redaction when confidentiality from the log reader is required.
fn hashValue(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..8].*, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{hex});
}

/// Produce the redacted (or masked/hashed) string for a detected value type,
/// respecting pii_mode. When pii_mode == .mask and the detected type is
/// email or phone, returns a masked version instead of the full redaction
/// token. When pii_mode == .hash, returns a deterministic sha256
/// pseudonym (see hashValue) for email/phone values.
fn redactOrMaskValue(allocator: std.mem.Allocator, value: []const u8, detected: RedactionToken, filters_cfg: *const config.FiltersConfig) ![]const u8 {
    if (filters_cfg.pii_mode == .mask) {
        if (detected == .email) return maskEmail(allocator, value);
        if (detected == .phone) return maskPhone(allocator, value);
    }
    if (filters_cfg.pii_mode == .hash and (detected == .email or detected == .phone)) {
        return hashValue(allocator, value);
    }
    return allocator.dupe(u8, detected.toString());
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

/// Maximum recursion depth for nested metadata redaction to prevent stack overflow.
const max_redaction_depth: u32 = 10;

pub fn filterAndRedactMetadata(
    allocator: std.mem.Allocator,
    metadata: std.json.Value,
    filters_cfg: *const config.FiltersConfig,
) !?std.json.Value {
    return filterAndRedactMetadataRecursive(allocator, metadata, filters_cfg, 0);
}

fn filterAndRedactMetadataRecursive(
    allocator: std.mem.Allocator,
    metadata: std.json.Value,
    filters_cfg: *const config.FiltersConfig,
    depth: u32,
) std.mem.Allocator.Error!?std.json.Value {
    if (depth >= max_redaction_depth) {
        return try json_util.cloneJsonValue(allocator, metadata);
    }

    return switch (metadata) {
        .object => |obj| blk: {
            var filtered_map: std.json.ObjectMap = .empty;
            errdefer filtered_map.deinit(allocator);

            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const key = entry.key_ptr.*;
                const value = entry.value_ptr.*;

                const filter_result = shouldFilterField(allocator, key, value, filters_cfg);
                switch (filter_result) {
                    .allow => {
                        const processed_value = try redactValueRecursive(allocator, value, filters_cfg, depth + 1);
                        try filtered_map.put(allocator, try allocator.dupe(u8, key), processed_value);
                    },
                    .redact => |key_token| {
                        // Determine the redacted string, applying masking when pii_mode == .mask.
                        // key_token is the pre-resolved isSensitiveKey result from shouldFilterField,
                        // avoiding a redundant second call.
                        const redacted_str = redact_blk: {
                            // First check if the value itself is a detectable type
                            if (value == .string) {
                                if (detectValueType(value.string)) |detected| {
                                    break :redact_blk try redactOrMaskValue(allocator, value.string, detected, filters_cfg);
                                }
                            }
                            // Fall back to key-based redaction token (already resolved)
                            if (key_token) |kt| {
                                // For key-based PII redaction with masking, check value
                                if (filters_cfg.pii_mode == .mask and value == .string) {
                                    if (kt == .email and isEmail(value.string)) {
                                        break :redact_blk try maskEmail(allocator, value.string);
                                    }
                                    if (kt == .phone and isPhone(value.string)) {
                                        break :redact_blk try maskPhone(allocator, value.string);
                                    }
                                }
                                // For key-based PII redaction with hashing, pseudonymize
                                // detected email/phone values (GAP-050).
                                if (filters_cfg.pii_mode == .hash and value == .string) {
                                    if (kt == .email and isEmail(value.string)) {
                                        break :redact_blk try hashValue(allocator, value.string);
                                    }
                                    if (kt == .phone and isPhone(value.string)) {
                                        break :redact_blk try hashValue(allocator, value.string);
                                    }
                                }
                                break :redact_blk try allocator.dupe(u8, kt.toString());
                            }
                            break :redact_blk try allocator.dupe(u8, "[REDACTED]");
                        };
                        const redacted = std.json.Value{ .string = redacted_str };
                        try filtered_map.put(allocator, try allocator.dupe(u8, key), redacted);
                    },
                    .drop_event => {
                        filtered_map.deinit(allocator);
                        return null;
                    },
                }
            }

            break :blk std.json.Value{ .object = filtered_map };
        },
        // Deep-copy non-object metadata: the caller frees the original and
        // the filtered result independently, so aliasing the input here
        // caused a use-after-free + double-free (QR-002).
        else => try json_util.cloneJsonValue(allocator, metadata),
    };
}

/// Recursively process a value for redaction. For objects, recurse into
/// filterAndRedactMetadataRecursive. For arrays, scan each element for
/// sensitive values and recurse into object elements. For strings, apply
/// value-type detection. Other scalars pass through unchanged.
fn redactValueRecursive(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    filters_cfg: *const config.FiltersConfig,
    depth: u32,
) std.mem.Allocator.Error!std.json.Value {
    if (depth >= max_redaction_depth) {
        return try json_util.cloneJsonValue(allocator, value);
    }

    return switch (value) {
        .object => blk: {
            const result = try filterAndRedactMetadataRecursive(allocator, value, filters_cfg, depth);
            // filterAndRedactMetadataRecursive returns null for drop_event;
            // in a nested context, replace with an empty object
            break :blk result orelse std.json.Value{ .object = .empty };
        },
        .array => |arr| blk: {
            var redacted_array = std.json.Array.init(allocator);
            errdefer redacted_array.deinit();

            for (arr.items) |item| {
                switch (item) {
                    .string => |s| {
                        // Apply value-type detection on string elements, respecting modes
                        if (detectValueTypeFiltered(s, filters_cfg)) |detected_token| {
                            try redacted_array.append(std.json.Value{
                                .string = try redactOrMaskValue(allocator, s, detected_token, filters_cfg),
                            });
                        } else {
                            try redacted_array.append(std.json.Value{
                                .string = try allocator.dupe(u8, s),
                            });
                        }
                    },
                    .object => {
                        // Recurse into nested objects within arrays
                        const processed = try redactValueRecursive(allocator, item, filters_cfg, depth + 1);
                        try redacted_array.append(processed);
                    },
                    .array => {
                        // Recurse into nested arrays
                        const processed = try redactValueRecursive(allocator, item, filters_cfg, depth + 1);
                        try redacted_array.append(processed);
                    },
                    else => {
                        try redacted_array.append(try json_util.cloneJsonValue(allocator, item));
                    },
                }
            }

            break :blk std.json.Value{ .array = redacted_array };
        },
        .string => |s| blk: {
            // Apply value-type detection on allowed string values, respecting modes
            if (detectValueTypeFiltered(s, filters_cfg)) |detected_token| {
                break :blk std.json.Value{ .string = try redactOrMaskValue(allocator, s, detected_token, filters_cfg) };
            }
            break :blk std.json.Value{ .string = try allocator.dupe(u8, s) };
        },
        else => try json_util.cloneJsonValue(allocator, value),
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

    // When pci_mode is true, enforce PAN/CVV detection regardless of allow_fields
    if (filters.pci_mode and value == .string) {
        const detected = detectValueType(value.string);
        if (detected == .card or detected == .cvv) {
            return .{ .redact = sensitive_token };
        }
    }

    if (is_denied or sensitive_token != null) {
        if (value == .string) {
            const str_value = value.string;
            // NOTE: This condition is currently unreachable because isPemPrivateKey
            // checks for "-----BEGIN" — it exists as a forward-looking guard for
            // future PEM detection changes that might not require that prefix.
            if (isPemPrivateKey(str_value) and !std.mem.startsWith(u8, str_value, "-----BEGIN")) {
                return .drop_event;
            }
        }
        return .{ .redact = sensitive_token };
    }

    if (filters.default_deny and !is_allowed) {
        return .{ .redact = sensitive_token };
    }

    if (value == .string) {
        const detected_type = detectValueTypeFiltered(value.string, filters);
        if (detected_type != null) {
            return .{ .redact = sensitive_token };
        }
    }

    return .allow;
}
