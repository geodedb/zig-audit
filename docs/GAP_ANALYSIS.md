# GAP Analysis

Last updated: 2026-03-21

Repository status: bootstrapped from `../zig-template`; no Geode code has been moved yet.

## Goal

Turn the reusable audit stack currently living in Geode into a standalone Zig library with a stable surface for:

- audit event modeling
- metadata filtering and redaction
- CEF formatting
- syslog and file sinks
- logger orchestration
- deterministic clock and ID helpers for testing

## Intended Boundary

Move into this library:

| Geode source | Why it belongs here |
|---|---|
| `src/audit/mod.zig:5` through `src/audit/mod.zig:11` | Current package root already defines the reusable audit submodules |
| `src/audit/events.zig:44` and `src/audit/events.zig:59` | Canonical `AuditEvent` model and constructor |
| `src/audit/filters.zig:39` and `src/audit/filters.zig:251` | Reusable sensitive-key detection and metadata redaction |
| `src/audit/time.zig:4`, `src/audit/time.zig:102`, `src/audit/time.zig:124`, `src/audit/time.zig:163` | Clock and ID generation abstractions used to make tests deterministic |
| `src/audit/cef.zig:194` | CEF formatting logic and format tests belong in the library |
| `src/audit/syslog.zig:60`, `src/audit/syslog.zig:74` | Reusable syslog sender and transport abstraction |
| `src/audit/file_sink.zig:17` and `src/audit/file_sink.zig:25` | Rotating file sink implementation |
| `src/audit/logger.zig:39`, `src/audit/logger.zig:47`, `src/audit/logger.zig:99` | High-level logger orchestration and sink fan-out |

Keep in Geode:

| Geode source | Why it stays |
|---|---|
| `src/audit/db_adapter.zig:183` and `src/audit/db_adapter.zig:187` | This is the Geode database adapter, not portable audit-core behavior |
| `src/security/audit.zig`, `src/security/audit_formatter.zig`, `src/security/audit_sink.zig` | Legacy duplicate stack should be reconciled toward this library, not moved wholesale until normalized |

## Concrete Gaps

| Gap | Evidence | Impact | Required fix |
|---|---|---|---|
| Build-time product identity leaks into formatting/config | `src/audit/cef.zig:206`, `src/audit/config.zig:310` import `build_options` | Prevents clean standalone packaging | Replace with explicit `LibraryIdentity` or config fields passed by the consumer |
| Geode DB adapter is mixed into the same package tree | `src/audit/db_adapter.zig:183` | Blurs public boundary | Split adapter into a Geode-only package after core extraction |
| Duplicate audit stack exists under `src/security` | `src/security/audit*.zig` | Raises ownership/API ambiguity | Choose `src/audit/*` as the canonical source and delete or wrap the older path |
| External dependencies are implicit today | `src/audit/syslog.zig` and `src/audit/logger.zig` rely on repo-level module wiring | Harder to package | Make `json`, `slog`, and `dns` explicit package dependencies |

## Tests And Benchmarks To Carry Over

Move or recreate these tests in this repo:

| Geode test | Coverage provided |
|---|---|
| `tests/test_audit_integration.zig:11`, `:59`, `:130`, `:208`, `:270`, `:334` | End-to-end logger/config/sink integration |
| `tests/test_transports.zig:11`, `:70`, `:83`, `:165`, `:225`, `:233`, `:247` | Syslog transport behaviors |
| `tests/test_cef.zig:10`, `:59`, `:66`, `:117` | CEF formatting correctness |
| `tests/test_filters.zig:8`, `:35`, `:52`, `:65`, `:78`, `:92`, `:104`, `:115`, `:126`, `:225` | Redaction and sensitive-value detection |
| `src/audit/file_sink.zig:241` | Rotation behavior unit test |
| `src/audit/logger.zig:279` | Logger unit behavior |
| `src/audit/db_adapter.zig:275` | Keep in Geode as adapter-level coverage, not library coverage |

Benchmarks identified:

- No dedicated standalone audit benchmark was found in Geode. The extraction should start with correctness/integration parity rather than synthetic throughput targets.

## Proposed Public API

Initial public surface should be centered on:

- `AuditEvent`
- `Config`
- `AuditLogger`
- `FileSink`
- `SyslogSender`
- `RedactionToken`
- `filterAndRedactMetadata`
- `Clock` / `IdGen`
- `formatCef`

Everything related to Geode persistence or Geode-specific event schemas should remain adapter code.

## Extraction Plan

1. Copy `src/audit/*` except `db_adapter.zig` into this repo and make one package root.
2. Replace `build_options` references with explicit runtime/build config.
3. Bring over the transport, filter, CEF, and logger tests listed above.
4. Add a minimal example showing file sink + syslog sink fan-out.
5. Update Geode to depend on this repo for the core package and keep only the DB adapter locally.

## Acceptance Criteria

- This repo builds and tests without the Geode tree present.
- No `@import("build_options")` remains in the extracted library.
- Geode keeps `db_adapter.zig` locally and imports this library for the core audit surface.
- Legacy audit code under `src/security` no longer defines a competing public surface.
