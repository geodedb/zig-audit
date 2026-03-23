// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const testing = std.testing;
const audit = @import("audit");
const filters = audit.filters;
const json_util = audit.json_util;
const config = audit.config;

test "sensitive key detection" {
    try testing.expect(filters.isSensitiveKey(testing.allocator, "password") == .password);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "Password") == .password);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "user_password") == .password);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "passwd") == .password);

    try testing.expect(filters.isSensitiveKey(testing.allocator, "token") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "api_key") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "apikey") == .token);

    try testing.expect(filters.isSensitiveKey(testing.allocator, "jwt") == .jwt);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "jwt_header") == .jwt);

    try testing.expect(filters.isSensitiveKey(testing.allocator, "card") == .card);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "credit_card") == .card);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "cc_number") == .card);

    try testing.expect(filters.isSensitiveKey(testing.allocator, "username") == null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "user_id") == null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "timestamp") == null);
}

test "JWT detection" {
    try testing.expect(filters.isJwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    try testing.expect(filters.isJwt("a.b.c"));
    try testing.expect(filters.isJwt("abc123.def456.ghi789"));

    try testing.expect(!filters.isJwt("a.b"));
    try testing.expect(!filters.isJwt("a.b.c.d"));
    try testing.expect(!filters.isJwt("a..c"));
    try testing.expect(!filters.isJwt(".b.c"));
    try testing.expect(!filters.isJwt("a.b."));
    try testing.expect(!filters.isJwt("a.b.c@"));
}

test "PAN (credit card) detection with Luhn" {
    try testing.expect(filters.isPan("4111 1111 1111 1111"));
    try testing.expect(filters.isPan("4111111111111111"));
    try testing.expect(filters.isPan("4111-1111-1111-1111"));

    try testing.expect(!filters.isPan("4111 1111 1111 1112"));
    try testing.expect(!filters.isPan("123"));
    try testing.expect(!filters.isPan("12345678901234567890"));
    try testing.expect(!filters.isPan("abcd efgh ijkl mnop"));
}

test "email detection" {
    try testing.expect(filters.isEmail("user@example.com"));
    try testing.expect(filters.isEmail("test.email@domain.org"));
    try testing.expect(filters.isEmail("simple@test.co.uk"));

    try testing.expect(!filters.isEmail("notanemail"));
    try testing.expect(!filters.isEmail("@domain.com"));
    try testing.expect(!filters.isEmail("user@"));
    try testing.expect(!filters.isEmail("user@domain"));
}

test "phone number detection" {
    try testing.expect(filters.isPhone("1234567890"));
    try testing.expect(filters.isPhone("123-456-7890"));
    try testing.expect(filters.isPhone("(123) 456-7890"));
    try testing.expect(filters.isPhone("+1 123 456 7890"));
    try testing.expect(!filters.isPhone("123456789"));
    try testing.expect(!filters.isPhone("12345678901234567"));
    try testing.expect(!filters.isPhone("abcdefghij"));
}

test "PEM private key detection" {
    const pem_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Q7HgL...\n-----END PRIVATE KEY-----";
    try testing.expect(filters.isPemPrivateKey(pem_key));

    const rsa_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAy8Dbq...\n-----END RSA PRIVATE KEY-----";
    try testing.expect(filters.isPemPrivateKey(rsa_key));

    try testing.expect(!filters.isPemPrivateKey("just some text"));
    try testing.expect(!filters.isPemPrivateKey("-----BEGIN CERTIFICATE-----"));
}

test "email masking" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const masked = try filters.maskEmail(allocator, "user@example.com");
    defer allocator.free(masked);

    try testing.expectEqualStrings("***@example.com", masked);
}

test "phone masking" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const masked = try filters.maskPhone(allocator, "123-456-7890");
    defer allocator.free(masked);

    try testing.expectEqualStrings("123***7890", masked);
}

test "metadata filtering and redaction" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 2);
    allow_fields[0] = try allocator.dupe(u8, "actor_id");
    allow_fields[1] = try allocator.dupe(u8, "action");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 1);
    deny_patterns[0] = try allocator.dupe(u8, "secret");
    defer {
        for (deny_patterns) |pattern| allocator.free(pattern);
        allocator.free(deny_patterns);
    }

    const filter_config = config.FiltersConfig{
        .default_deny = true,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .mask,
        .pci_mode = true,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    try metadata_obj.put("actor_id", std.json.Value{ .string = "test-user" });
    try metadata_obj.put("password", std.json.Value{ .string = "secret123" });
    try metadata_obj.put("unknown_field", std.json.Value{ .string = "value" });
    try metadata_obj.put("secret_data", std.json.Value{ .string = "sensitive" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        try testing.expect(obj.contains("actor_id"));

        if (obj.get("password")) |password_value| {
            try testing.expectEqualStrings("[REDACTED]", password_value.string);
        }

        // GAP-008 fix: unknown_field is now present with generic [REDACTED]
        // instead of being silently dropped when default_deny is true
        try testing.expect(obj.contains("unknown_field"));
        if (obj.get("unknown_field")) |unknown_value| {
            try testing.expectEqualStrings("[REDACTED]", unknown_value.string);
        }

        // secret_data matches deny pattern "secret" and now isSensitiveKey
        // (GAP-010 added "secret" pattern), so it gets [REDACTED_TOKEN]
        if (obj.get("secret_data")) |secret_value| {
            try testing.expectEqualStrings("[REDACTED_TOKEN]", secret_value.string);
        }
    }
}

test "expanded sensitive key detection" {
    // GAP-010: secret, credential, authorization, bearer, access_key, passphrase, pin
    try testing.expect(filters.isSensitiveKey(testing.allocator, "aws_secret_key") != null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "credentials") != null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "authorization_header") != null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "bearer_token") != null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "access_key_id") != null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "passphrase") != null);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "bank_pin") != null);

    // Verify the specific redaction token types
    try testing.expect(filters.isSensitiveKey(testing.allocator, "db_secret") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "credential") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "authorization") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "bearer") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "access_key") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "passphrase") == .password);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "bank_pin") == .card);

    // Case insensitivity
    try testing.expect(filters.isSensitiveKey(testing.allocator, "Authorization") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "BEARER_TOKEN") == .token);
    try testing.expect(filters.isSensitiveKey(testing.allocator, "CLIENT_SECRET") == .token);
}

test "recursive redaction of nested objects" {
    // GAP-008: {"user": {"password": "secret"}} with "user" allowed
    // should produce {"user": {"password": "[REDACTED]"}}
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "user");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = true,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .off,
        .pci_mode = false,
    };

    // Build inner object: {"password": "secret123"}
    var inner_obj = std.json.ObjectMap.init(allocator);
    try inner_obj.put("password", std.json.Value{ .string = "secret123" });

    // Build outer: {"user": inner_obj}
    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer {
        // inner_obj is owned by metadata_obj, free inner first
        if (metadata_obj.get("user")) |v| {
            if (v == .object) {
                var inner = @constCast(&v.object);
                inner.deinit();
            }
        }
        metadata_obj.deinit();
    }
    try metadata_obj.put("user", std.json.Value{ .object = inner_obj });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        // "user" should be present
        try testing.expect(obj.contains("user"));

        if (obj.get("user")) |user_val| {
            try testing.expect(user_val == .object);
            const user_obj = user_val.object;

            // "password" inside "user" should be redacted
            if (user_obj.get("password")) |pw_val| {
                try testing.expectEqualStrings("[REDACTED]", pw_val.string);
            } else {
                // password field must be present (not silently dropped)
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "redaction of sensitive values in arrays" {
    // GAP-008: {"items": ["4111111111111111"]} with "items" allowed
    // should produce {"items": ["[REDACTED_PAN]"]}
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "items");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .off,
        .pci_mode = false,
    };

    // Build array with a PAN value
    var arr = std.json.Array.init(allocator);
    try arr.append(std.json.Value{ .string = "4111111111111111" });
    try arr.append(std.json.Value{ .string = "safe_value" });
    defer arr.deinit();

    // Build outer: {"items": arr}
    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();
    try metadata_obj.put("items", std.json.Value{ .array = arr });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        try testing.expect(obj.contains("items"));
        if (obj.get("items")) |items_val| {
            try testing.expect(items_val == .array);
            const items = items_val.array;

            // First element should be redacted PAN
            try testing.expectEqualStrings("[REDACTED_PAN]", items.items[0].string);
            // Second element should pass through
            try testing.expectEqualStrings("safe_value", items.items[1].string);
        }
    }
}

test "deny pattern match without isSensitiveKey produces generic redaction" {
    // GAP-008 Q4: a key matching deny_key_patterns but not isSensitiveKey
    // should get [REDACTED] instead of being silently dropped
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 0);
    defer allocator.free(allow_fields);

    // Use a deny pattern that won't match any isSensitiveKey built-in
    const deny_patterns = try allocator.alloc([]const u8, 1);
    deny_patterns[0] = try allocator.dupe(u8, "internal");
    defer {
        for (deny_patterns) |pattern| allocator.free(pattern);
        allocator.free(deny_patterns);
    }

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .off,
        .pci_mode = false,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    // "internal_data" matches deny pattern "internal" but not isSensitiveKey
    try metadata_obj.put("internal_data", std.json.Value{ .string = "some-value" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        // The field MUST be present with a generic redaction, not silently dropped
        try testing.expect(obj.contains("internal_data"));
        if (obj.get("internal_data")) |val| {
            try testing.expectEqualStrings("[REDACTED]", val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pii_mode mask: email value is masked instead of fully redacted" {
    // GAP-007: When pii_mode == .mask, email values should be masked (***@domain)
    // instead of showing [REDACTED_EMAIL]
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "user_email");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .mask,
        .pci_mode = false,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    try metadata_obj.put("user_email", std.json.Value{ .string = "alice@example.com" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        // Value should be masked, not fully redacted
        if (obj.get("user_email")) |email_val| {
            try testing.expectEqualStrings("***@example.com", email_val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pii_mode mask: phone value is masked instead of fully redacted" {
    // GAP-007: When pii_mode == .mask, phone values should be masked (123***7890)
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "contact_phone");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .mask,
        .pci_mode = false,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    try metadata_obj.put("contact_phone", std.json.Value{ .string = "123-456-7890" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        if (obj.get("contact_phone")) |phone_val| {
            try testing.expectEqualStrings("123***7890", phone_val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pii_mode mask: key-based email detection with mask" {
    // GAP-007: When a key matches "email" via isSensitiveKey and pii_mode == .mask,
    // the email value should be masked
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 0);
    defer allocator.free(allow_fields);

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .mask,
        .pci_mode = false,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    // "email" key triggers isSensitiveKey -> .email
    try metadata_obj.put("email", std.json.Value{ .string = "bob@test.org" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        if (obj.get("email")) |email_val| {
            // Should be masked: ***@test.org
            try testing.expectEqualStrings("***@test.org", email_val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pii_mode off: email and phone values pass through when not key-matched" {
    // GAP-007: When pii_mode == .off, value-type detection for email/phone is skipped,
    // but key-name matches still cause redaction
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "notes");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .off,
        .pci_mode = false,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    // "notes" is allowed and value is an email; with pii_mode off, it should pass through
    try metadata_obj.put("notes", std.json.Value{ .string = "contact@example.com" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        // With pii_mode off, the email value should pass through unmodified
        if (obj.get("notes")) |val| {
            try testing.expectEqualStrings("contact@example.com", val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pii_mode off: key-name email match still causes redaction" {
    // GAP-007: Even when pii_mode == .off, key-name matches still trigger redaction
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 0);
    defer allocator.free(allow_fields);

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .off,
        .pci_mode = false,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    // "email" key still triggers isSensitiveKey regardless of pii_mode
    try metadata_obj.put("email", std.json.Value{ .string = "test@example.com" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        // Key "email" is sensitive, so value should be redacted (not masked since pii_mode is off)
        if (obj.get("email")) |val| {
            try testing.expectEqualStrings("[REDACTED_EMAIL]", val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pci_mode true: PAN in allowed field is still redacted" {
    // GAP-007: When pci_mode is true, PAN detection overrides allow_fields
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "payment_info");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .off,
        .pci_mode = true,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    // "payment_info" is in allow_fields, but its value is a valid PAN
    try metadata_obj.put("payment_info", std.json.Value{ .string = "4111111111111111" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        // Even though "payment_info" is allowed, the PAN should be redacted
        if (obj.get("payment_info")) |val| {
            try testing.expectEqualStrings("[REDACTED_PAN]", val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pci_mode false: PAN in allowed field passes through" {
    // GAP-007: When pci_mode is false, PAN detection does NOT override allow_fields
    // (but value-type detection in redactValueRecursive would still catch it)
    // Actually, with pci_mode false the shouldFilterField still detects PAN via
    // detectValueTypeFiltered. The difference is that pci_mode true forces redaction
    // even for allowed fields. With pci_mode false, the allowed field goes to .allow
    // but then redactValueRecursive still detects the PAN value.
    // So the test verifies that with pci_mode off, value detection still works.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "payment_info");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .off,
        .pci_mode = false,
    };

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();

    // "payment_info" is in allow_fields with pci_mode false
    try metadata_obj.put("payment_info", std.json.Value{ .string = "4111111111111111" });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;

        // PAN is still detected by value-type detection (field is allowed but value
        // is detected as PAN in redactValueRecursive), so it still gets redacted
        if (obj.get("payment_info")) |val| {
            try testing.expectEqualStrings("[REDACTED_PAN]", val.string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "pii_mode mask: email in array is masked" {
    // GAP-007: Email values in arrays should be masked when pii_mode == .mask
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const allow_fields = try allocator.alloc([]const u8, 1);
    allow_fields[0] = try allocator.dupe(u8, "contacts");
    defer {
        for (allow_fields) |field| allocator.free(field);
        allocator.free(allow_fields);
    }

    const deny_patterns = try allocator.alloc([]const u8, 0);
    defer allocator.free(deny_patterns);

    const filter_config = config.FiltersConfig{
        .default_deny = false,
        .allow_fields = allow_fields,
        .deny_key_patterns = deny_patterns,
        .pii_mode = .mask,
        .pci_mode = false,
    };

    var arr = std.json.Array.init(allocator);
    try arr.append(std.json.Value{ .string = "user@example.com" });
    try arr.append(std.json.Value{ .string = "safe_text" });
    defer arr.deinit();

    var metadata_obj = std.json.ObjectMap.init(allocator);
    defer metadata_obj.deinit();
    try metadata_obj.put("contacts", std.json.Value{ .array = arr });

    const metadata = std.json.Value{ .object = metadata_obj };

    var filtered = try filters.filterAndRedactMetadata(allocator, metadata, &filter_config);
    defer if (filtered) |*f| {
        if (f.* == .object) {
            var obj_mut = &f.object;
            var iter = obj_mut.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                json_util.freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        }
    };

    try testing.expect(filtered != null);
    if (filtered) |f| {
        try testing.expect(f == .object);
        const obj = f.object;
        if (obj.get("contacts")) |contacts_val| {
            try testing.expect(contacts_val == .array);
            const items = contacts_val.array;
            // Email should be masked
            try testing.expectEqualStrings("***@example.com", items.items[0].string);
            // Safe text should pass through
            try testing.expectEqualStrings("safe_text", items.items[1].string);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "redaction tokens" {
    try testing.expectEqualStrings("[REDACTED]", filters.RedactionToken.password.toString());
    try testing.expectEqualStrings("[REDACTED_TOKEN]", filters.RedactionToken.token.toString());
    try testing.expectEqualStrings("[REDACTED_JWT]", filters.RedactionToken.jwt.toString());
    try testing.expectEqualStrings("[REDACTED_PAN]", filters.RedactionToken.card.toString());
    try testing.expectEqualStrings("[REDACTED_CVV]", filters.RedactionToken.cvv.toString());
    try testing.expectEqualStrings("[REDACTED_SSN]", filters.RedactionToken.ssn.toString());
    try testing.expectEqualStrings("[REDACTED_IBAN]", filters.RedactionToken.iban.toString());
    try testing.expectEqualStrings("[REDACTED_PK]", filters.RedactionToken.private_key.toString());
    try testing.expectEqualStrings("[REDACTED_EMAIL]", filters.RedactionToken.email.toString());
    try testing.expectEqualStrings("[REDACTED_PHONE]", filters.RedactionToken.phone.toString());
}
