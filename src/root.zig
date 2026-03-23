// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # audit
//!
//! A standalone Zig library for audit event modeling, metadata filtering and
//! redaction, CEF formatting, syslog and file sinks, logger orchestration,
//! and deterministic clock/ID helpers for testing.
//!
//! ## Quick Start
//!
//! ```zig
//! const audit = @import("audit");
//!
//! // Create a logger with file + syslog sinks
//! var cfg = try audit.config.loadConfig(allocator, "audit.json");
//! const logger = try audit.logger.buildAuditLogger(allocator, &cfg);
//! defer logger.deinit();
//!
//! // Emit an audit event
//! try logger.audit(&.{
//!     .category = "auth",
//!     .action   = "login",
//!     .outcome  = .success,
//!     .severity = .INFO,
//!     .actor_id = "jane.doe",
//!     // remaining fields default to null / 0
//! });
//! ```
//!
//! ## License
//!
//! Apache-2.0

/// Library version
pub const version = "0.1.0";

// ── Re-exported submodules ──────────────────────────────────────────────

pub const events = @import("events.zig");
pub const filters = @import("filters.zig");
pub const config = @import("config.zig");
pub const syslog = @import("syslog.zig");
pub const file_sink = @import("file_sink.zig");
pub const time = @import("time.zig");
pub const cef = @import("cef.zig");
pub const json_util = @import("json_util.zig");
pub const logger = @import("logger.zig");
pub const ring_buffer = @import("ring_buffer.zig");

// ── Convenience re-exports ──────────────────────────────────────────────

pub const AuditEvent = events.AuditEvent;
pub const AuditLogger = logger.AuditLogger;
pub const Config = config.Config;
pub const FileSink = file_sink.FileSink;
pub const SyslogSender = syslog.SyslogSender;
pub const RedactionToken = filters.RedactionToken;
pub const filterAndRedactMetadata = filters.filterAndRedactMetadata;
pub const Clock = time.Clock;
pub const IdGen = time.IdGen;
pub const formatCef = cef.formatCef;
pub const RingBuffer = ring_buffer.RingBuffer;

// ── Tests ───────────────────────────────────────────────────────────────

test {
    // Ensure all declarations are referenced for test coverage
    @import("std").testing.refAllDecls(@This());
}
