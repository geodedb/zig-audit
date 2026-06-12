// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! AuditEvent model, severity/outcome enums, and field validation.

const std = @import("std");
const json_util = @import("json_util.zig");

/// Result of handing an event to a sink's bounded queue (GAP-041/A2).
/// `enqueued` means the sink accepted the record for asynchronous
/// delivery; `dropped` means the queue was full and the record was
/// discarded (counted by the sink's drop counter). Lives here because
/// both `file_sink.zig` and `syslog.zig` already import `events.zig`,
/// keeping the import direction sink -> events with no sink-to-sink
/// dependency.
pub const SendStatus = enum { enqueued, dropped };

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
        InvalidCharacter,
    };

    /// Validates required fields, length constraints, and character
    /// constraints on the audit event. Core identity fields must not
    /// contain ASCII control characters (0x00-0x1F, 0x7F) -- they are
    /// rejected at the API boundary rather than relying on downstream
    /// formatter escaping (GAP-047/A8). Metadata values are intentionally
    /// NOT validated here; they are neutralized by the CEF escape layer.
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

        // Reject ASCII control characters in all core string fields.
        for (string_fields) |field| {
            try checkNoControlChars(field);
        }
        for (optional_fields) |maybe_field| {
            if (maybe_field) |field| {
                try checkNoControlChars(field);
            }
        }
    }

    fn checkNoControlChars(field: []const u8) ValidateError!void {
        for (field) |c| {
            if (c < 0x20 or c == 0x7F) return error.InvalidCharacter;
        }
    }

    pub fn deinit(self: *AuditEvent, allocator: std.mem.Allocator) void {
        if (self.metadata) |metadata| {
            json_util.freeJsonValue(allocator, metadata);
        }
    }

    /// Shared string-dupe core of `clone` / `cloneWithoutMetadata`: deep-copy
    /// every string field and copy the scalar fields, leaving `metadata`
    /// null. On error, everything duped so far is released.
    fn cloneStrings(self: *const AuditEvent, allocator: std.mem.Allocator) !AuditEvent {
        const cat = try allocator.dupe(u8, self.category);
        errdefer allocator.free(cat);

        const act = try allocator.dupe(u8, self.action);
        errdefer allocator.free(act);

        const aid = try allocator.dupe(u8, self.actor_id);
        errdefer allocator.free(aid);

        const sid = if (self.subject_id) |s| try allocator.dupe(u8, s) else null;
        errdefer if (sid) |s| allocator.free(s);

        const rid = if (self.request_id) |r| try allocator.dupe(u8, r) else null;
        errdefer if (rid) |r| allocator.free(r);

        const ses = if (self.session_id) |s| try allocator.dupe(u8, s) else null;
        errdefer if (ses) |s| allocator.free(s);

        const sip = if (self.source_ip) |s| try allocator.dupe(u8, s) else null;
        errdefer if (sip) |s| allocator.free(s);

        return AuditEvent{
            .category = cat,
            .action = act,
            .outcome = self.outcome,
            .ts_unix_ms = self.ts_unix_ms,
            .severity = self.severity,
            .actor_id = aid,
            .subject_id = sid,
            .request_id = rid,
            .session_id = ses,
            .source_ip = sip,
            .trace_id = self.trace_id,
            .span_id = self.span_id,
            .metadata = null,
        };
    }

    pub fn clone(self: *const AuditEvent, allocator: std.mem.Allocator) !AuditEvent {
        var cloned = try self.cloneStrings(allocator);
        // Frees the duped strings if the metadata clone fails; `cloned.metadata`
        // is still null at that point, so freeCloned touches nothing else.
        errdefer cloned.freeCloned(allocator);

        if (self.metadata) |metadata| {
            cloned.metadata = try json_util.cloneJsonValue(allocator, metadata);
        }

        return cloned;
    }

    /// Like `clone`, but does not copy `metadata` (left null). The logger
    /// derives the event's metadata from the original via the redaction
    /// filter and attaches the filtered tree directly (single-copy
    /// pipeline, GAP-049/PERF-001/PERF-005).
    pub fn cloneWithoutMetadata(self: *const AuditEvent, allocator: std.mem.Allocator) !AuditEvent {
        return self.cloneStrings(allocator);
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

test "AuditEvent.validate: control character in actor_id returns InvalidCharacter" {
    var event = makeValidEvent();
    event.actor_id = "user\x00name";
    try std.testing.expectError(error.InvalidCharacter, event.validate());
}

test "AuditEvent.validate: control characters in core and optional fields return InvalidCharacter (GAP-047/A8)" {
    const cases = [_]struct {
        field: enum { category, action, actor_id, subject_id, request_id, session_id, source_ip },
        value: []const u8,
    }{
        .{ .field = .category, .value = "au\x1Fth" },
        .{ .field = .action, .value = "log\x07in" },
        .{ .field = .actor_id, .value = "user\x7F" },
        .{ .field = .subject_id, .value = "sub\x00ject" },
        .{ .field = .request_id, .value = "req\x0A123" },
        .{ .field = .session_id, .value = "ses\x0D999" },
        .{ .field = .source_ip, .value = "1.2.3.4\x09" },
    };

    for (cases) |case| {
        var event = makeValidEvent();
        switch (case.field) {
            .category => event.category = case.value,
            .action => event.action = case.value,
            .actor_id => event.actor_id = case.value,
            .subject_id => event.subject_id = case.value,
            .request_id => event.request_id = case.value,
            .session_id => event.session_id = case.value,
            .source_ip => event.source_ip = case.value,
        }
        try std.testing.expectError(error.InvalidCharacter, event.validate());
    }
}
