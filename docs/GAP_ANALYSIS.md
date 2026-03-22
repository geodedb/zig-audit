# GAP Analysis

Last updated: 2026-03-22

Repository status: core audit modules extracted from Geode; all unit and integration tests passing.

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

| Gap | Status | Resolution |
|---|---|---|
| Build-time product identity leaks into formatting/config | **Closed** | Replaced `@import("build_options")` with explicit `CefIdentityConfig` fields passed by the consumer. `config.loadTestConfig` uses `root.version` constant. |
| Geode DB adapter is mixed into the same package tree | **Won't Do** | `db_adapter.zig` remains in Geode by design. This library does not include it. Geode should import this library and keep only the adapter locally. |
| Duplicate audit stack exists under `src/security` | **Won't Do** | This is a Geode-side reconciliation task. The canonical source is now this library; Geode should redirect `src/security/audit*.zig` to import from here. |
| External dependencies are implicit today | **Closed** | `dns` is now an explicit dependency in `build.zig.zon`. `slog` replaced with `std.log` (library-internal logging). `json` replaced with `std.json` (struct serialization). |
| TLS syslog transport requires external TLS bindings | **Blocked** | `std.crypto.tls.Client` is not yet stable for generic stream wrapping in Zig 0.15. `sendTls` returns `error.TlsNotImplemented` with a log message recommending stunnel or TCP. UDP and TCP transports work. |

## Tests And Benchmarks Carried Over

| Geode test | Status |
|---|---|
| `tests/test_audit_integration.zig` Cases 1, 2, 4, 5, 6 | **Ported** to `tests/integration.zig` (Case 3 uses `db_adapter`, excluded) |
| `tests/test_transports.zig` all cases | **Ported** to `tests/test_transports.zig` |
| `tests/test_cef.zig` all cases | **Ported** to `tests/test_cef.zig` |
| `tests/test_filters.zig` all cases | **Ported** to `tests/test_filters.zig` |
| `src/audit/file_sink.zig:241` (rotation unit test) | **Ported** (in-source test in `src/file_sink.zig`) |
| `src/audit/logger.zig:279` (logger unit test) | **Ported** (in-source test in `src/logger.zig`) |
| `src/audit/db_adapter.zig:275` | **Excluded** (stays in Geode) |
| `src/audit/syslog.zig` TLS/pool/ring buffer tests | **Ported** (in-source tests in `src/syslog.zig`) |

## Public API

Exported from `src/root.zig`:

- `AuditEvent` (events)
- `Config`, `CefIdentityConfig`, `ServiceConfig`, `FiltersConfig`, `SinksConfig` (config)
- `AuditLogger`, `buildAuditLogger` (logger)
- `FileSink` (file_sink)
- `SyslogSender`, `MockSyslogSender` (syslog)
- `RedactionToken`, `filterAndRedactMetadata` (filters)
- `Clock`, `SystemClock`, `FixedClock` (time)
- `IdGen`, `SystemIdGen`, `FixedIdGen` (time)
- `formatCef`, `escapeCefString` (cef)

## Acceptance Criteria

- [x] This repo builds and tests without the Geode tree present.
- [x] No `@import("build_options")` remains in the extracted library.
- [ ] Geode keeps `db_adapter.zig` locally and imports this library for the core audit surface. *(Geode-side task)*
- [ ] Legacy audit code under `src/security` no longer defines a competing public surface. *(Geode-side task)*
