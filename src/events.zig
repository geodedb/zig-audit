// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const json_util = @import("json_util.zig");

pub const Severity = enum {
    DEBUG,
    INFO,
    WARN,
    ERROR,

    pub fn toSyslogSeverity(self: Severity) u8 {
        return switch (self) {
            .DEBUG => 7,
            .INFO => 6,
            .WARN => 4,
            .ERROR => 3,
        };
    }

    pub fn toCefSeverity(self: Severity) u8 {
        return switch (self) {
            .DEBUG => 2,
            .INFO => 5,
            .WARN => 8,
            .ERROR => 10,
        };
    }
};

pub const Outcome = enum {
    success,
    failure,
    deny,
    @"error",

    pub fn toString(self: Outcome) []const u8 {
        return switch (self) {
            .success => "success",
            .failure => "failure",
            .deny => "deny",
            .@"error" => "error",
        };
    }
};

pub const AuditEvent = struct {
    category: []const u8, // "auth" | "db"
    action: []const u8, // e.g., "login", "password.change", "db.update"
    outcome: Outcome,
    ts_unix_ms: i128, // UTC epoch ms; if 0, use injected clock
    severity: Severity,
    actor_id: []const u8,
    subject_id: ?[]const u8,
    request_id: ?[]const u8,
    session_id: ?[]const u8,
    source_ip: ?[]const u8,
    trace_id: ?[32]u8, // 32 hex (lowercase)
    span_id: ?[16]u8, // 16 hex (lowercase)
    metadata: ?std.json.Value, // arbitrary object; filtered/redacted

    pub const MAX_FIELD_LEN = 1024;

    pub const ValidateError = error{
        EmptyCategory,
        EmptyAction,
        EmptyActorId,
        FieldTooLong,
    };

    /// Validates required fields and length constraints on the audit event.
    pub fn validate(self: *const AuditEvent) ValidateError!void {
        if (self.category.len == 0) return error.EmptyCategory;
        if (self.action.len == 0) return error.EmptyAction;
        if (self.actor_id.len == 0) return error.EmptyActorId;

        // Check all string fields against max length
        const string_fields = [_][]const u8{
            self.category,
            self.action,
            self.actor_id,
        };
        for (string_fields) |field| {
            if (field.len > MAX_FIELD_LEN) return error.FieldTooLong;
        }

        const optional_fields = [_]?[]const u8{
            self.subject_id,
            self.request_id,
            self.session_id,
            self.source_ip,
        };
        for (optional_fields) |maybe_field| {
            if (maybe_field) |field| {
                if (field.len > MAX_FIELD_LEN) return error.FieldTooLong;
            }
        }
    }

    pub fn deinit(self: *AuditEvent, allocator: std.mem.Allocator) void {
        if (self.metadata) |metadata| {
            json_util.freeJsonValue(allocator, metadata);
        }
    }

    pub fn clone(self: *const AuditEvent, allocator: std.mem.Allocator) !AuditEvent {
        var cloned = AuditEvent{
            .category = try allocator.dupe(u8, self.category),
            .action = try allocator.dupe(u8, self.action),
            .outcome = self.outcome,
            .ts_unix_ms = self.ts_unix_ms,
            .severity = self.severity,
            .actor_id = try allocator.dupe(u8, self.actor_id),
            .subject_id = if (self.subject_id) |sid| try allocator.dupe(u8, sid) else null,
            .request_id = if (self.request_id) |rid| try allocator.dupe(u8, rid) else null,
            .session_id = if (self.session_id) |sid| try allocator.dupe(u8, sid) else null,
            .source_ip = if (self.source_ip) |sip| try allocator.dupe(u8, sip) else null,
            .trace_id = self.trace_id,
            .span_id = self.span_id,
            .metadata = null,
        };

        if (self.metadata) |metadata| {
            cloned.metadata = try json_util.cloneJsonValue(allocator, metadata);
        }

        return cloned;
    }

    pub fn freeCloned(self: *AuditEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.category);
        allocator.free(self.action);
        allocator.free(self.actor_id);
        if (self.subject_id) |sid| allocator.free(sid);
        if (self.request_id) |rid| allocator.free(rid);
        if (self.session_id) |sid| allocator.free(sid);
        if (self.source_ip) |sip| allocator.free(sip);
        if (self.metadata) |metadata| {
            json_util.freeJsonValue(allocator, metadata);
        }
    }
};

fn makeValidEvent() AuditEvent {
    return AuditEvent{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .ts_unix_ms = 0,
        .severity = .INFO,
        .actor_id = "user-1",
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = null,
    };
}

test "AuditEvent.validate: valid event passes" {
    const event = makeValidEvent();
    try event.validate();
}

test "AuditEvent.validate: empty category returns EmptyCategory" {
    var event = makeValidEvent();
    event.category = "";
    try std.testing.expectError(error.EmptyCategory, event.validate());
}

test "AuditEvent.validate: empty action returns EmptyAction" {
    var event = makeValidEvent();
    event.action = "";
    try std.testing.expectError(error.EmptyAction, event.validate());
}

test "AuditEvent.validate: empty actor_id returns EmptyActorId" {
    var event = makeValidEvent();
    event.actor_id = "";
    try std.testing.expectError(error.EmptyActorId, event.validate());
}

test "AuditEvent.validate: field exceeding 1024 bytes returns FieldTooLong" {
    var event = makeValidEvent();
    var long_field: [1025]u8 = undefined;
    @memset(&long_field, 'a');
    event.category = &long_field;
    try std.testing.expectError(error.FieldTooLong, event.validate());
}

test "AuditEvent.validate: optional field exceeding 1024 bytes returns FieldTooLong" {
    var event = makeValidEvent();
    var long_field: [1025]u8 = undefined;
    @memset(&long_field, 'a');
    event.subject_id = &long_field;
    try std.testing.expectError(error.FieldTooLong, event.validate());
}

test "AuditEvent.validate: field at exactly 1024 bytes passes" {
    var event = makeValidEvent();
    var max_field: [1024]u8 = undefined;
    @memset(&max_field, 'a');
    event.category = &max_field;
    try event.validate();
}
