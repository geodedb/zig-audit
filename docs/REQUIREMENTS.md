# Requirements

Last updated: 2026-03-21

## Scope

This repository will host the reusable audit core extracted from Geode. It is not intended to own database persistence, Geode-specific audit schemas, or Geode runtime wiring.

## Functional Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUDIT-REQ-001 | The library SHALL expose an `AuditEvent` model suitable for standalone creation and serialization. | `src/audit/events.zig:44`, `src/audit/events.zig:59` |
| AUDIT-REQ-002 | The library SHALL provide metadata filtering and redaction helpers for sensitive values. | `src/audit/filters.zig:39`, `src/audit/filters.zig:251` |
| AUDIT-REQ-003 | The library SHALL provide deterministic clock and ID abstractions for tests and replayable examples. | `src/audit/time.zig:4`, `src/audit/time.zig:102`, `src/audit/time.zig:163` |
| AUDIT-REQ-004 | The library SHALL format audit events as CEF without relying on Geode build options. | `src/audit/cef.zig:194`, blocker `src/audit/cef.zig:206` |
| AUDIT-REQ-005 | The library SHALL support file-sink output with rotation. | `src/audit/file_sink.zig:17`, `src/audit/file_sink.zig:25`, test `src/audit/file_sink.zig:241` |
| AUDIT-REQ-006 | The library SHALL support syslog transport via a reusable sender abstraction. | `src/audit/syslog.zig:60`, `src/audit/syslog.zig:74` |
| AUDIT-REQ-007 | The library SHALL provide a high-level logger that fans out to configured sinks. | `src/audit/logger.zig:39`, `src/audit/logger.zig:99` |
| AUDIT-REQ-008 | The library SHALL NOT embed Geode database integration. | `src/audit/db_adapter.zig:183` must remain adapter code |

## Packaging Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUDIT-PKG-001 | All public dependencies SHALL be explicit in this repo’s build manifest. | Current repo-level imports are implicit in Geode |
| AUDIT-PKG-002 | No library source file SHALL import Geode `build_options`. | `src/audit/cef.zig:206`, `src/audit/config.zig:310` |
| AUDIT-PKG-003 | The library SHALL ship a single package root exporting only the reusable audit surface. | `src/audit/mod.zig:5` through `src/audit/mod.zig:11` |

## Test Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUDIT-TEST-001 | Library tests SHALL cover CEF formatting parity. | `tests/test_cef.zig:10`, `:59`, `:66`, `:117` |
| AUDIT-TEST-002 | Library tests SHALL cover filter and redaction behavior parity. | `tests/test_filters.zig:8`, `:35`, `:52`, `:65`, `:78`, `:92`, `:104`, `:115`, `:126`, `:225` |
| AUDIT-TEST-003 | Library tests SHALL cover transport and sink integration parity. | `tests/test_transports.zig:11`, `:70`, `:83`, `:165`, `:225`, `:233`, `:247` |
| AUDIT-TEST-004 | Library tests SHALL cover end-to-end logger behavior. | `tests/test_audit_integration.zig:11`, `:59`, `:130`, `:208`, `:270`, `:334`, `src/audit/logger.zig:279` |

## Documentation Requirements

- Provide one example for local file logging.
- Provide one example for syslog emission.
- Document the config required to supply product identity/version externally.
- Document what stays outside the library: DB adapters and product-specific event enrichment.

## Migration Requirements

1. Geode must replace imports of `src/audit/*` core files with this library.
2. Geode must keep `src/audit/db_adapter.zig` locally and adapt it to the library surface.
3. Legacy audit code under `src/security` must be removed, wrapped, or redirected to avoid duplicate ownership.
