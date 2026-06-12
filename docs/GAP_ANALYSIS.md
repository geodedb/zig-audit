# GAP Analysis

Last updated: 2026-06-12

Repository status: 158 tests / 157 pass / 1 otel skip (pre-existing, non-security); ReleaseSafe and ReleaseFast green; pre-commit clean; otel-enabled build green.

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

## Open Gaps

### GAP-005: TLS syslog transport

- **Status: Blocked**
- **Issue:** [#25](https://gitlab.com/devnw/zig/audit/-/issues/25)
- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** AUDIT-REQ-006
- **Current state (evidence):**
  - `src/syslog.zig:225-236` -- `sendTls` returns `error.TlsNotImplemented` with a log message recommending stunnel or TCP
  - `std.crypto.tls.Client` is not yet stable for generic stream wrapping in Zig 0.15
- **Why this is a gap:** UDP and TCP transports work, but TLS transport is non-functional
- **Impact/Risk:** Consumers needing encrypted syslog must use external tunnels (stunnel)
- **Recommended fix:** Wait for std.crypto.tls stabilization or add external TLS bindings
- **Acceptance criteria:** `sendTls` successfully sends a message over a TLS-wrapped TCP connection
- **Blocker:** Zig stdlib `std.crypto.tls.Client` is not yet stable for generic stream wrapping
- **Unblock steps:** Monitor Zig stdlib TLS stabilization; implement when API is stable, or evaluate external TLS bindings (e.g., zig-bearssl)

### GAP-029: DNS dependency pinned to commit hash, not tagged release

- **Status: Open (blocked -- cross-repo)**
- **Issue:** [#24](https://gitlab.com/devnw/zig/audit/-/issues/24)
- **Category:** Supply Chain
- **Severity:** Low
- **Requirement source:** AUDIT-PKG-001
- **Current state (evidence):**
  - `build.zig.zon:8` -- `git+https://gitlab.com/devnw/zig/dns.git#976fedf07befad3724fa66092677b9e5242a58fc`
  - No tag reference in the URL
- **Why this is a gap:** Harder to audit version changes and track upstream releases
- **Impact/Risk:** Consumers cannot easily determine DNS library version
- **Recommended fix:** Tag a release in the dns repo; reference the tag in build.zig.zon
- **Acceptance criteria:** DNS dependency references a tagged release or commit hash is documented with version
- **Blocker:** Requires tagging a release in the `gitlab.com/devnw/zig/dns` repository
- **Unblock steps:** Create a tagged release (e.g., `v0.1.0`) in the DNS library repo; update `build.zig.zon` here to reference it

### GAP-045: dependency ref/version-hash drift in build.zig.zon (dns, otel)

- **Status: Open (blocked -- cross-repo)**
- **Issue:** [#64](https://gitlab.com/devnw/zig/audit/-/issues/64)
- **Category:** Supply Chain
- **Severity:** Low
- **Current state (evidence):**
  - `build.zig.zon:7-9` -- `dns ?ref=v0.1.9` vs `dns-0.1.8` content hash label; otel shows the same class of drift
  - Content is cryptographically pinned by `.hash`; this is an auditability gap, not an integrity break
- **Why this is a gap:** Makes it harder to audit which version is in use
- **Blocker:** Requires tagged releases in `devnw/zig/dns` and the otel dependency repo
- **Unblock steps:** Tag correct releases in both upstream repos; update build.zig.zon refs

## Open Gaps -- Deferred Performance / Quality Items

Items deferred from the 2026-06-11 audit cycle. Full context in PERF_GAP_ANALYSIS.md and QUALITY_GAP_ANALYSIS.md.

- **PR-002** (P3) getEventName linear mem.eql chain per CEF format -- deferred -- [#61](https://gitlab.com/devnw/zig/audit/-/issues/61)
- **PR-003** (P2) redaction re-scans every string through 5 sequential detectors -- deferred -- [#65](https://gitlab.com/devnw/zig/audit/-/issues/65)
- **PR-004** (P1) no per-event arena; ~70-80 alloc/free pairs per audit() -- deferred -- [#68](https://gitlab.com/devnw/zig/audit/-/issues/68)
- **PR-007** (P1) TCP syslog 2 send syscalls per record (writev/iovec not yet done) -- open -- [#78](https://gitlab.com/devnw/zig/audit/-/issues/78)
- **PR-009** (P1) BoundedChannel single-mutex MPSC contention (gated on MP bench data; D6 partial done) -- open -- [#82](https://gitlab.com/devnw/zig/audit/-/issues/82)
- **QR-008** (Low) implicit anyerror across public surface -- deferred (API design) -- [#116](https://gitlab.com/devnw/zig/audit/-/issues/116)
- **QR-018** (Low) syslog Linux-only portability (documented in README) -- open -- [#114](https://gitlab.com/devnw/zig/audit/-/issues/114)

## Open Gaps -- 2026-06-12 New Item

- **NEW-001** buffered batch tail discarded without per-line warning on failed mid-batch reopen -- add fault-injection test -- Low -- [#121](https://gitlab.com/devnw/zig/audit/-/issues/121)
  - log.warn added in commit 9391d12 (`file_sink.zig` flushBuffer); remaining ask is a fault-injection test

## Resolved Gaps

All resolved gaps (35 items from the 2026-03-22 and 2026-06-12 cycles) have been moved to [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

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
- `BoundedChannel` (channel)

## Acceptance Criteria

- [x] This repo builds and tests without the Geode tree present.
- [x] No `@import("build_options")` remains in the extracted library.
- [ ] Geode keeps `db_adapter.zig` locally and imports this library for the core audit surface. *(Geode-side task)*
- [ ] Legacy audit code under `src/security` no longer defines a competing public surface. *(Geode-side task)*
