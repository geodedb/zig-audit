# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.14] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5, config v0.1.13 (GAP-0838 diamond sync).

## [0.1.13] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5 (GAP-0838 diamond sync).

## [0.1.0] - 2026-03-22

### Added

- Audit event modeling with structured `AuditEvent` type
- CEF (Common Event Format) formatting for syslog output
- Syslog sink with RFC 5424 framing over UDP and TCP transports
- File sink with JSON-line output and size-based log rotation
- Metadata filtering with default-deny allow-list and deny-key patterns
- PII redaction (mask/hash modes) and PCI-DSS PAN detection
- JWT, private-key, and bearer-token redaction in metadata
- Logger orchestration combining file and syslog sinks
- Deterministic Clock and IdGen interfaces for testing
- DNS-based hostname resolution via external dns library

[Unreleased]: https://gitlab.com/devnw/zig/audit/-/compare/v0.1.0...HEAD
[0.1.0]: https://gitlab.com/devnw/zig/audit/-/releases/v0.1.0
