# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.25] - 2026-11-17

### Changed

- dns v0.1.28 -> v0.1.29 and otel v0.1.28 -> v0.1.30 (grpc-zig v0.1.16), so audit and its consumers (geode) resolve a single dns, config, otel and thread-pool (SONNY-6630).

## [0.1.24] - 2026-11-12

### Fixed

- Syslog sink uses native POSIX sockets on macOS (first tagged release to
  carry the fix that landed on `main` after 0.1.23).

### Changed

- Update dns to v0.1.28, whose `Address.eql` no longer reaches `unreachable`
  (SONNY-6447).
- Versions 0.1.21 through 0.1.23 were dependency-convergence releases
  (SONNY-4829) with no audit source changes.

## [0.1.20] - 2026-09-24

### Fixed

- Detect and mask dot-separated phone numbers (`555.123.4567`,
  `+1.555.123.4567`, `01.23.45.67.89`) as PII; IPv4-shaped values (four groups
  of at most three digits) are still not phones (SONNY-2394).

### Changed

- Versions 0.1.15 through 0.1.19 were dependency-convergence releases cut on
  the diamond-sync line (GAP-0838 grpc_zig convergence); 0.1.20 carries the
  same dependency set from `main`.

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
