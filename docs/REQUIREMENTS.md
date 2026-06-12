# Requirements

Last updated: 2026-06-11

> Note: the `db_adapter.zig` references below intentionally retain the `src/audit/` (Geode) path -- that file is Geode-specific and stays in Geode by design (AUDIT-REQ-008). All other source references have been updated to this repo's actual layout (`src/*.zig`, `src/root.zig`, `tests/integration.zig`).

## Scope

This repository will host the reusable audit core extracted from Geode. It is not intended to own database persistence, Geode-specific audit schemas, or Geode runtime wiring.

## Functional Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUDIT-REQ-001 | The library SHALL expose an `AuditEvent` model suitable for standalone creation and serialization. | `src/events.zig:44`, `src/events.zig:59` |
| AUDIT-REQ-002 | The library SHALL provide metadata filtering and redaction helpers for sensitive values. | `src/filters.zig:39`, `src/filters.zig:251` |
| AUDIT-REQ-003 | The library SHALL provide deterministic clock and ID abstractions for tests and replayable examples. | `src/time.zig:4`, `src/time.zig:102`, `src/time.zig:163` |
| AUDIT-REQ-004 | The library SHALL format audit events as CEF without relying on Geode build options. | `src/cef.zig:194`, blocker `src/cef.zig:206` |
| AUDIT-REQ-005 | The library SHALL support file-sink output with rotation. | `src/file_sink.zig:17`, `src/file_sink.zig:25`, test `src/file_sink.zig:241` |
| AUDIT-REQ-006 | The library SHALL support syslog transport via a reusable sender abstraction. | `src/syslog.zig:60`, `src/syslog.zig:74` |
| AUDIT-REQ-007 | The library SHALL provide a high-level logger that fans out to configured sinks. | `src/logger.zig:39`, `src/logger.zig:99` |
| AUDIT-REQ-008 | The library SHALL NOT embed Geode database integration. | `src/audit/db_adapter.zig:183` must remain adapter code |

## Packaging Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUDIT-PKG-001 | All public dependencies SHALL be explicit in this repo’s build manifest. | Current repo-level imports are implicit in Geode |
| AUDIT-PKG-002 | No library source file SHALL import Geode `build_options`. | `src/cef.zig:206`, `src/config.zig:310` |
| AUDIT-PKG-003 | The library SHALL ship a single package root exporting only the reusable audit surface. | `src/root.zig:5` through `src/root.zig:11` |

## Test Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUDIT-TEST-001 | Library tests SHALL cover CEF formatting parity. | `tests/test_cef.zig:10`, `:59`, `:66`, `:117` |
| AUDIT-TEST-002 | Library tests SHALL cover filter and redaction behavior parity. | `tests/test_filters.zig:8`, `:35`, `:52`, `:65`, `:78`, `:92`, `:104`, `:115`, `:126`, `:225` |
| AUDIT-TEST-003 | Library tests SHALL cover transport and sink integration parity. | `tests/test_transports.zig:11`, `:70`, `:83`, `:165`, `:225`, `:233`, `:247` |
| AUDIT-TEST-004 | Library tests SHALL cover end-to-end logger behavior. | `tests/integration.zig:11`, `:59`, `:130`, `:208`, `:270`, `:334`, `src/logger.zig:279` |

## Documentation Requirements

- Provide one example for local file logging.
- Provide one example for syslog emission.
- Document the config required to supply product identity/version externally.
- Document what stays outside the library: DB adapters and product-specific event enrichment.

## Migration Requirements

1. Geode must replace imports of `src/*` core files with this library.
2. Geode must keep `src/audit/db_adapter.zig` locally and adapt it to the library surface.
3. Legacy audit code under `src/security` must be removed, wrapped, or redirected to avoid duplicate ownership.
