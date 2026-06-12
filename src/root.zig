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
//! const cfg = try audit.config.loadConfig(allocator, "audit.json");
//! // The logger takes ownership of cfg and frees it in deinit().
//! const logger = try audit.logger.buildAuditLogger(allocator, cfg);
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

/// Library version. Single-sourced from build.zig.zon via build.zig's
/// `package_version` build option (GAP-074/QR-017) — it cannot drift from
/// the package version.
pub const version: []const u8 = @import("build_options").package_version;

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
pub const channel = @import("channel.zig");

// Observability seam (otel). NAMED module — see `build.zig` for why we
// can't use a relative `@import("observability.zig")` here. When
// `-Dwith_otel=false` (the default), every public helper in this
// module collapses to a comptime-known no-op and the otel dependency
// is never resolved.
pub const observability = @import("observability");

// Bootstrap helper for `-Dwith_otel=true` builds. Gated through the
// seam's compile-time `enabled` flag so the disabled build never
// touches otel-namespaced identifiers. Consumers wire this up from
// their `main()` once per process — see README "Observability"
// section.
pub const observability_init = if (observability.enabled)
    @import("observability_init")
else
    struct {};

// ── Convenience re-exports ──────────────────────────────────────────────

pub const AuditEvent = events.AuditEvent;
pub const SendStatus = events.SendStatus;
pub const AuditLogger = logger.AuditLogger;
pub const Config = config.Config;
pub const FileSink = file_sink.FileSink;
pub const SyslogSender = syslog.SyslogSender;
pub const RedactionToken = filters.RedactionToken;
pub const filterAndRedactMetadata = filters.filterAndRedactMetadata;
pub const Clock = time.Clock;
pub const IdGen = time.IdGen;
pub const formatCef = cef.formatCef;
pub const BoundedChannel = channel.BoundedChannel;

// ── Tests ───────────────────────────────────────────────────────────────

test {
    // Ensure all declarations are referenced for test coverage
    @import("std").testing.refAllDecls(@This());
}

test "root.version is a valid semantic version (GAP-074)" {
    // Single-sourcing is enforced at build time: build.zig reads
    // `@import("build.zig.zon").version` and injects it as
    // build_options.package_version, which `version` aliases. Drift
    // between root.zig and build.zig.zon is therefore structurally
    // impossible; this test guards the remaining runtime property —
    // that the injected string is well-formed semver.
    const std = @import("std");
    const parsed = try std.SemanticVersion.parse(version);
    try std.testing.expect(parsed.major != 0 or parsed.minor != 0 or parsed.patch != 0);
}
