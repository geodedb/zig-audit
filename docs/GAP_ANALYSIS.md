# GAP Analysis

Last updated: 2026-06-11

Repository status: core audit modules extracted from Geode; all unit and integration tests passing (102/102).

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
- **Issue:** No platform issue -- blocked on Zig stdlib
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

> **GAP-020** (fsync per event) and **GAP-021** (new socket per syslog message) were verified fixed in the 2026-06-11 audit and have been moved to [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md). Evidence: `src/config.zig:88-108` (SyncMode), `src/syslog.zig:107-114,235-247` (persistent sockets + DNS cache).

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

## Open Gaps -- 2026-06-11 Audit (GAP-040..074 master series)

Findings from the full audit and appsec review of 2026-06-11 (`docs/APPSEC_REVIEW_2026-06-11.md`). Appsec aliases in parentheses. One line each: ID, title, severity, issue.

- **GAP-040** (A1) config `@intCast` panic/truncation on malformed integer fields -- Medium -- [#57](https://gitlab.com/devnw/zig/audit/-/issues/57)
- **GAP-041** (A2) file-sink drops audit records silently under backpressure (no counter) -- Medium -- [#58](https://gitlab.com/devnw/zig/audit/-/issues/58)
- **GAP-042** (A3) control characters unescaped in CEF/syslog output -- Medium -- [#60](https://gitlab.com/devnw/zig/audit/-/issues/60)
- **GAP-043** (A4) path-traversal mitigation incomplete (absolute/symlink bypass; residual S9) -- Medium -- [#62](https://gitlab.com/devnw/zig/audit/-/issues/62)
- **GAP-044** (A5) `formatRfc3339` panics on negative timestamp -- Low -- [#63](https://gitlab.com/devnw/zig/audit/-/issues/63)
- **GAP-045** (A6) dependency ref/version-hash drift in `build.zig.zon` (dns, otel) -- Low -- [#64](https://gitlab.com/devnw/zig/audit/-/issues/64)
- **GAP-046** (A7) event `ts_unix_ms` never rendered; output timestamp is worker-thread "now" -- Low -- [#66](https://gitlab.com/devnw/zig/audit/-/issues/66)
- **GAP-047** (A8) `validate()` does not reject control characters in core fields -- Low -- [#67](https://gitlab.com/devnw/zig/audit/-/issues/67)
- **GAP-048** (NEW-PERF-004) `cloneJsonValue` missing `errdefer` on partial clone (OOM leak) -- Medium -- [#69](https://gitlab.com/devnw/zig/audit/-/issues/69)
- **GAP-049** (NEW-PERF-005/PERF-005) metadata deep-copied 4x through the pipeline -- Medium -- [#70](https://gitlab.com/devnw/zig/audit/-/issues/70)
- **GAP-050** (NEW-Q-001) `PiiMode.hash` unhandled, silently degrades to no-op -- High -- [#72](https://gitlab.com/devnw/zig/audit/-/issues/72)
- **GAP-051** (NEW-PERF-001) TCP length-prefix heap allocation per syslog send -- Low -- [#73](https://gitlab.com/devnw/zig/audit/-/issues/73)
- **GAP-052** (NEW-PERF-002) double CEF escaping of `actor_id`/`request_id` -- Low -- [#75](https://gitlab.com/devnw/zig/audit/-/issues/75)
- **GAP-053** (NEW-PERF-003) `ObjectMap` built without capacity hint -- Low -- [#76](https://gitlab.com/devnw/zig/audit/-/issues/76)
- **GAP-054** (PERF-014 residual) `detectValueType` called twice per value -- Low -- [#77](https://gitlab.com/devnw/zig/audit/-/issues/77)
- **GAP-055** (PERF-008) constant JSON key string heap-duped per line -- Low -- [#79](https://gitlab.com/devnw/zig/audit/-/issues/79)
- **GAP-056** (PERF-009 residual) serialize-to-measure in `estimateEventSize` -- Low -- [#81](https://gitlab.com/devnw/zig/audit/-/issues/81)
- **GAP-057** (PERF-012) no streaming JSON writer in file sink -- Low -- [#83](https://gitlab.com/devnw/zig/audit/-/issues/83)
- **GAP-058** (NEW-Q-004) `audit()` is 129 lines -- Low -- [#84](https://gitlab.com/devnw/zig/audit/-/issues/84)
- **GAP-059** (NEW-Q-005) `parseConfig` is 112 lines -- Low -- [#85](https://gitlab.com/devnw/zig/audit/-/issues/85)
- **GAP-060** (NEW-Q-006) complex redaction control flow -- Low -- [#87](https://gitlab.com/devnw/zig/audit/-/issues/87)
- **GAP-061** (NEW-Q-007) unreachable PEM branch in filters -- Low -- [#88](https://gitlab.com/devnw/zig/audit/-/issues/88)
- **GAP-062** (NEW-Q-008/009) unused `pub` helpers exported -- Low -- [#90](https://gitlab.com/devnw/zig/audit/-/issues/90)
- **GAP-063** (NEW-SEC-001) umask race before `setPermissions(0o640)` -- Medium -- [#92](https://gitlab.com/devnw/zig/audit/-/issues/92)
- **GAP-064** (NEW-SEC-002/003) CI components + pre-commit hooks pinned to mutable tags -- Medium -- [#93](https://gitlab.com/devnw/zig/audit/-/issues/93)
- **GAP-065** (NEW-SEC-004) zig toolchain single-origin trust -- Low -- [#94](https://gitlab.com/devnw/zig/audit/-/issues/94)
- **GAP-066** (NEW-SEC-005) `pkg_hash` path-join unsanitized -- Low -- [#95](https://gitlab.com/devnw/zig/audit/-/issues/95)
- **GAP-067** (NEW-SEC-006) `parse_target` unhandled `ValueError` -- Low -- [#96](https://gitlab.com/devnw/zig/audit/-/issues/96)
- **GAP-068** (NEW-SEC-007) `rewrite_pin` no quoting guard -- Low -- [#97](https://gitlab.com/devnw/zig/audit/-/issues/97)
- **GAP-069** (NEW-SEC-008) `integration.zig` missing from gitleaks allowlist -- Low -- [#98](https://gitlab.com/devnw/zig/audit/-/issues/98)
- **GAP-070** (NEW-CI-001/002) no CI cache (zig binary + `.zig-cache`) -- Low -- [#99](https://gitlab.com/devnw/zig/audit/-/issues/99)
- **GAP-071** (NEW-CI-003/004) no ruff/typecheck CI gate for scripts -- Low -- [#100](https://gitlab.com/devnw/zig/audit/-/issues/100)
- **GAP-072** (Q11) `requestId` catch returns empty string on OOM -- Low -- [#101](https://gitlab.com/devnw/zig/audit/-/issues/101)
- **GAP-073** (Q19) `requestId` vtable still present though doc says removed -- Low -- [#102](https://gitlab.com/devnw/zig/audit/-/issues/102)
- **GAP-074** (E) version drift `root.zig` 0.1.0 vs zon 0.1.6 -- Low -- [#103](https://gitlab.com/devnw/zig/audit/-/issues/103)
- **GAP-DD1** (DD) design decision: `sync_mode` default `.per_event` vs `.periodic` (product decision, not a defect) -- Low -- [#104](https://gitlab.com/devnw/zig/audit/-/issues/104)

## Open Gaps -- 2026-06-11 Deep Quality Review (QR series, Critical/High + tracked Mediums/Lows)

Deep manual quality review Criticals and High plus tracked Medium/Low correctness, docs, and test-hygiene findings. (The QR-*/PR-* deep-review series and the QUALITY/PERF gap docs are otherwise maintained separately.)

- **QR-001** use-after-return: `buildAuditLogger` returns dangling stack pointers (SystemClock/SystemIdGen) -- Critical -- [#105](https://gitlab.com/devnw/zig/audit/-/issues/105)
- **QR-002** double-free/UAF when metadata is non-object -- Critical -- [#106](https://gitlab.com/devnw/zig/audit/-/issues/106)
- **QR-003** truncation path frees string literals -- Critical -- [#107](https://gitlab.com/devnw/zig/audit/-/issues/107)
- **QR-004** Config pass-by-value double-free trap; ownership undocumented -- High -- [#108](https://gitlab.com/devnw/zig/audit/-/issues/108)
- **QR-005** `span_durable` reports durable=true even when both sinks dropped -- Medium -- [#109](https://gitlab.com/devnw/zig/audit/-/issues/109)
- **QR-011** `isSensitiveKey` treats keys >256 bytes as not sensitive (redaction bypass) -- Medium -- [#110](https://gitlab.com/devnw/zig/audit/-/issues/110)
- **QR-012** missing negative/boundary tests (channel-full, truncation, non-object metadata, `buildAuditLogger`) -- Medium -- [#111](https://gitlab.com/devnw/zig/audit/-/issues/111)
- **QR-015** SECURITY.md claims No-UB / compile-time memory safety, contradicted by findings -- Medium -- [#112](https://gitlab.com/devnw/zig/audit/-/issues/112)
- **QR-016** README claims Zig 0.15.1+, build requires 0.16.0 -- Medium -- [#113](https://gitlab.com/devnw/zig/audit/-/issues/113)
- **QR-018** README claims cross-platform but syslog is Linux-only -- Low -- [#114](https://gitlab.com/devnw/zig/audit/-/issues/114)
- **QR-007** RingBuffer dead code exported as public API -- Low -- [#115](https://gitlab.com/devnw/zig/audit/-/issues/115)
- **QR-008** implicit `anyerror` across public surface -- Low -- [#116](https://gitlab.com/devnw/zig/audit/-/issues/116)
- **QR-009** rotation size accounting off-by-one + stale size after failed rename -- Low -- [#117](https://gitlab.com/devnw/zig/audit/-/issues/117)
- **QR-010** `resolveOrCached` i128->i64 `@intCast` -- Low -- [#118](https://gitlab.com/devnw/zig/audit/-/issues/118)
- **QR-013** integration tests pass even when nothing written -- Low -- [#119](https://gitlab.com/devnw/zig/audit/-/issues/119)
- **QR-014** shared mutable tmpdir across test files -- Low -- [#120](https://gitlab.com/devnw/zig/audit/-/issues/120)

## Resolved Gaps

All resolved gaps (29 items) have been moved to [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

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
