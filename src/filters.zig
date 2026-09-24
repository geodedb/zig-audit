// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Metadata filtering, sensitive-key detection, and PII/PCI data redaction.
//! Supports configurable allow/deny lists, value-type heuristics, and masking modes.

const std = @import("std");
const config = @import("config.zig");
const json_util = @import("json_util.zig");

pub const FilterResult = union(enum) {
    allow: void,
    redact: Redaction,
    drop_event: void,

    /// Carries both detection results out of `shouldFilterField` so the
    /// redaction consumer never re-runs value-type detection (GAP-054).
    pub const Redaction = struct {
        /// Token from `isSensitiveKey`; null for deny-pattern, default-deny,
        /// or value-only matches.
        key_token: ?RedactionToken = null,
        /// Detected type of the string value; null for non-string values or
        /// values that match no detector.
        value_token: ?RedactionToken = null,
    };
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
    _ = allocator; // retained for API stability; matching needs no allocation
    // QR-011: match patterns case-insensitively against the key directly
    // (same approach as the deny-pattern loop in shouldFilterField). The
    // previous implementation lowercased into a 256-byte stack buffer and
    // returned null for longer keys — failing OPEN on oversized keys.
    const contains = std.ascii.indexOfIgnoreCase;

    // Password-related
    if (contains(key, "password") != null or
        contains(key, "passwd") != null or
        contains(key, "passphrase") != null) return .password;

    // Token-related
    if (contains(key, "token") != null or
        contains(key, "apikey") != null or
        contains(key, "api_key") != null) return .token;

    // Secret/credential/auth-related
    if (contains(key, "secret") != null or
        contains(key, "credential") != null or
        contains(key, "bearer") != null or
        contains(key, "authorization") != null or
        contains(key, "access_key") != null) return .token;

    // JWT
    if (contains(key, "jwt") != null) return .jwt;

    // Payment card
    if (contains(key, "card") != null or
        contains(key, "cc") != null or
        contains(key, "pan") != null) return .card;

    // Banking PIN
    if (contains(key, "pin") != null) return .card;

    // CVV
    if (contains(key, "cvv") != null or
        contains(key, "cvc") != null) return .cvv;

    // SSN/SIN/NIN
    if (contains(key, "ssn") != null or
        contains(key, "sin") != null or
        contains(key, "nin") != null) return .ssn;

    // IBAN
    if (contains(key, "iban") != null) return .iban;

    // Private keys
    if (contains(key, "private_key") != null or
        contains(key, "privkey") != null) return .private_key;

    // PII
    if (contains(key, "email") != null) return .email;
    if (contains(key, "phone") != null) return .phone;

    // Session/cookie
    if (contains(key, "cookie") != null or
        contains(key, "session") != null) return .token;

    return null;
}

/// Exposed for testing (tests/test_filters.zig).
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

/// Exposed for testing (tests/test_filters.zig).
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

/// Exposed for testing (tests/test_filters.zig).
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

/// Exposed for testing (tests/test_filters.zig).
pub fn isPhone(value: []const u8) bool {
    var digit_count: usize = 0;
    var has_dot = false;
    for (value) |c| {
        if (c >= '0' and c <= '9') {
            digit_count += 1;
        } else if (c == '.') {
            has_dot = true;
        } else if (c != ' ' and c != '-' and c != '(' and c != ')' and c != '+') {
            return false;
        }
    }
    if (digit_count < 10 or digit_count > 15) return false;
    return !has_dot or isDottedPhone(value);
}

/// Dot-separated phone numbers ("555.123.4567", "+1.555.123.4567",
/// "01.23.45.67.89") used to be rejected outright, so they reached audit
/// records unmasked (SONNY-2394). Dots also separate IPv4 addresses and
/// decimals, so a dotted value only counts as a phone in a strict dotted
/// grouping: an optional leading '+', then all-digit groups joined by single
/// dots (no other separator), at least 3 groups, and not IPv4-shaped
/// (exactly 4 groups of at most 3 digits).
fn isDottedPhone(value: []const u8) bool {
    const rest = if (value.len > 0 and value[0] == '+') value[1..] else value;
    var groups: usize = 0;
    var longest: usize = 0;
    var it = std.mem.splitScalar(u8, rest, '.');
    while (it.next()) |group| {
        if (group.len == 0) return false;
        for (group) |c| {
            if (c < '0' or c > '9') return false;
        }
        groups += 1;
        longest = @max(longest, group.len);
    }
    if (groups < 3) return false;
    if (groups == 4 and longest <= 3) return false; // IPv4-shaped
    return true;
}

/// Exposed for testing (tests/test_filters.zig).
pub fn isPemPrivateKey(value: []const u8) bool {
    return std.mem.indexOf(u8, value, "-----BEGIN") != null and
        std.mem.indexOf(u8, value, "PRIVATE KEY-----") != null;
}

/// Exposed for testing (tests/test_filters.zig).
pub fn maskEmail(allocator: std.mem.Allocator, email_addr: []const u8) ![]const u8 {
    const at_pos = std.mem.indexOf(u8, email_addr, "@") orelse return allocator.dupe(u8, email_addr);
    const domain = email_addr[at_pos..];
    return std.fmt.allocPrint(allocator, "***{s}", .{domain});
}

/// Exposed for testing (tests/test_filters.zig).
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

fn detectValueType(value: []const u8) ?RedactionToken {
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
    // fips-exempt: non-security — pseudonymization of low-entropy PII for log
    // correlation only; output is explicitly NOT a secret (see doc-comment above)
    // and is not used for authentication, integrity, or confidentiality.
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    // fips-exempt: non-security — see doc-comment/notes above; pseudonymization
    // hash for log correlation, not authentication/integrity/confidentiality.
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..8].*, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{hex});
}

test "fips-exempt annotation present on hashValue Sha256 site" {
    const src = @embedFile("filters.zig");
    // The non-security SHA-256 digest must carry the FIPS exemption marker.
    try std.testing.expect(std.mem.indexOf(u8, src, "fips-exempt: non-security — pseudonymization") != null);
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
            // Free entries (duped keys + allocated values), not just the
            // backing storage — a bare deinit leaks everything inserted
            // before a mid-iteration failure.
            errdefer json_util.freeJsonValue(allocator, std.json.Value{ .object = filtered_map });

            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const key = entry.key_ptr.*;
                const value = entry.value_ptr.*;

                const filter_result = shouldFilterField(allocator, key, value, filters_cfg);
                switch (filter_result) {
                    .allow => {
                        const processed_value = try redactValueRecursive(allocator, value, filters_cfg, depth + 1);
                        errdefer json_util.freeJsonValue(allocator, processed_value);
                        const dup_key = try allocator.dupe(u8, key);
                        errdefer allocator.free(dup_key);
                        try filtered_map.put(allocator, dup_key, processed_value);
                    },
                    .redact => |redaction| {
                        const redacted_str = try resolveRedactedString(allocator, value, redaction, filters_cfg);
                        errdefer allocator.free(redacted_str);
                        const dup_key = try allocator.dupe(u8, key);
                        errdefer allocator.free(dup_key);
                        try filtered_map.put(allocator, dup_key, std.json.Value{ .string = redacted_str });
                    },
                    .drop_event => {
                        // Free entries inserted before the drop, not just the
                        // backing storage (pre-existing leak found in E1 review).
                        json_util.freeJsonValue(allocator, std.json.Value{ .object = filtered_map });
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

/// Determine the redacted replacement string for a field, applying masking
/// when pii_mode == .mask. Both tokens are pre-resolved by
/// shouldFilterField (GAP-054): key_token from isSensitiveKey, value_token
/// from value-type detection — no redundant second detection pass here.
/// Caller owns the returned string.
fn resolveRedactedString(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    redaction: FilterResult.Redaction,
    filters_cfg: *const config.FiltersConfig,
) std.mem.Allocator.Error![]const u8 {
    // First check if the value itself is a detectable type
    if (value == .string) {
        if (redaction.value_token) |detected| {
            return redactOrMaskValue(allocator, value.string, detected, filters_cfg);
        }
    }
    // Fall back to key-based redaction token (already resolved)
    if (redaction.key_token) |kt| {
        // For key-based PII redaction with masking, check value
        if (filters_cfg.pii_mode == .mask and value == .string) {
            if (kt == .email and isEmail(value.string)) {
                return maskEmail(allocator, value.string);
            }
            if (kt == .phone and isPhone(value.string)) {
                return maskPhone(allocator, value.string);
            }
        }
        // For key-based PII redaction with hashing, pseudonymize
        // detected email/phone values (GAP-050).
        if (filters_cfg.pii_mode == .hash and value == .string) {
            if (kt == .email and isEmail(value.string)) {
                return hashValue(allocator, value.string);
            }
            if (kt == .phone and isPhone(value.string)) {
                return hashValue(allocator, value.string);
            }
        }
        return allocator.dupe(u8, kt.toString());
    }
    return allocator.dupe(u8, "[REDACTED]");
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

    // GAP-054/PERF-014: run value-type detection at most once per field and
    // hand the result to the redaction consumer via FilterResult, instead of
    // the consumer re-detecting. The unfiltered pass runs eagerly only when
    // some path below will need it: the pci_mode gate, or a key-driven
    // redaction (denied / sensitive / default-deny) whose consumer redacts
    // by detected value type first.
    const key_redacts = is_denied or sensitive_token != null or (filters.default_deny and !is_allowed);
    const value_token: ?RedactionToken = if (value == .string and (filters.pci_mode or key_redacts))
        detectValueType(value.string)
    else
        null;

    // When pci_mode is true, enforce PAN/CVV detection regardless of allow_fields
    if (filters.pci_mode and value == .string) {
        if (value_token == .card or value_token == .cvv) {
            return .{ .redact = .{ .key_token = sensitive_token, .value_token = value_token } };
        }
    }

    if (is_denied or sensitive_token != null) {
        if (value == .string) {
            // GAP-061: a PEM private key under a sensitive/denied key is
            // unredactable content — drop the whole event (fail closed)
            // rather than emit anything alongside key material.
            //
            // Documented asymmetry: a PEM caught purely by VALUE detection
            // under a non-sensitive, non-denied key (the fall-through paths
            // below and redactValueRecursive for nested values) is redacted
            // to [REDACTED_PK] instead — the key carries no sensitive
            // intent, so the rest of the event is presumed safe to keep.
            //
            // Deliberately NOT folded into value_token: detectValueType's
            // detector ordering could shadow .private_key behind an earlier
            // match, and this drop is a security control that must not
            // depend on detector precedence. isPemPrivateKey is a cheap
            // prefix check, so the extra call costs nothing material.
            if (isPemPrivateKey(value.string)) {
                return .drop_event;
            }
        }
        return .{ .redact = .{ .key_token = sensitive_token, .value_token = value_token } };
    }

    if (filters.default_deny and !is_allowed) {
        return .{ .redact = .{ .key_token = sensitive_token, .value_token = value_token } };
    }

    if (value == .string) {
        const detected_type: ?RedactionToken = if (filters.pci_mode) blk: {
            // pci_mode already ran the unfiltered pass above; apply the
            // pii_mode gate that detectValueTypeFiltered would apply rather
            // than scanning the value a second time.
            const d = value_token orelse break :blk null;
            if (filters.pii_mode == .off and (d == .email or d == .phone)) break :blk null;
            break :blk d;
        } else detectValueTypeFiltered(value.string, filters);
        if (detected_type) |d| {
            return .{ .redact = .{ .key_token = sensitive_token, .value_token = d } };
        }
    }

    return .allow;
}
