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

## Open Gaps

### GAP-005: TLS syslog transport

- **Issue:** Blocked (no platform issue -- blocked on Zig stdlib)
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

### GAP-006: CEF escape functions are no-ops -- log injection risk

- **Status: RESOLVED**
- **Issue:** [#1](https://gitlab.com/devnw/zig/audit/-/issues/1)
- **Category:** Security
- **Severity:** Critical
- **Requirement source:** AUDIT-REQ-004 (CEF formatting)
- **Current state (evidence):**
  - `src/cef.zig:152-162` -- `escapeHeader`, `escapeValue`, `escapeKey` all return input unchanged (identity functions)
  - `src/cef.zig:164-180` -- A correct `escapeCefString` function exists but is never called by `formatCef`
  - `src/cef.zig:31-67` -- `formatCef` passes user-controlled fields through no-op escapes
- **Why this is a gap:** CEF spec requires escaping `|` in headers and `=`/newlines in extensions. Without escaping, an attacker controlling `actor_id` or metadata values can inject arbitrary CEF fields or forge syslog lines
- **Impact/Risk:** Log injection enables audit trail tampering and SIEM confusion
- **Recommended fix:** Replace no-op functions with calls to existing `escapeCefString`; add injection test cases
- **Acceptance criteria:** `escapeHeader` escapes `\` and `|`; `escapeValue` escapes `\`, `=`, newlines; tests with `|` and `\n` in fields pass
- **Resolution:**
  - Replaced three no-op escape functions with allocating implementations that delegate to `escapeCefString`
  - Fixed bug in `escapeCefString` where `=` was incorrectly escaped in header mode (CEF spec: `=` is only escaped in extensions)
  - Updated all call sites in `formatCef`, `addMetadataExtensions`, and `addGenericExtension` to pass allocator and handle memory
  - Added unit tests in `src/cef.zig` for header escaping, extension value escaping, and empty/clean input
  - Added integration tests in `tests/test_cef.zig` for header pipe/backslash escaping, extension equals/newline escaping, and adversarial full-pipeline test
  - All tests pass with `zig build test-all`

### GAP-007: pii_mode and pci_mode config flags parsed but never enforced

- **Issue:** [#2](https://gitlab.com/devnw/zig/audit/-/issues/2)
- **Category:** Security
- **Severity:** High
- **Requirement source:** AUDIT-REQ-002 (metadata filtering and redaction)
- **Current state (evidence):**
  - `src/config.zig:118-124` -- `FiltersConfig` declares `pii_mode: PiiMode` and `pci_mode: bool`
  - `src/config.zig:56-67` -- `PiiMode` enum with `off`, `mask`, `hash` variants
  - `src/filters.zig:245-318` -- `filterAndRedactMetadata` and `shouldFilterField` never read `.pii_mode` or `.pci_mode`
- **Why this is a gap:** Consumers who configure PII/PCI modes get no additional protection
- **Impact/Risk:** False sense of security for consumers relying on these config flags
- **Recommended fix:** Wire `pii_mode` into value-based detection; wire `pci_mode` into PAN scanning on all string values
- **Acceptance criteria:** `pii_mode: "mask"` masks email/phone values; `pci_mode: true` scans all strings for PANs; tests for each mode

### GAP-008: Metadata redaction does not recurse into nested objects/arrays

- **Status: RESOLVED**
- **Issue:** [#3](https://gitlab.com/devnw/zig/audit/-/issues/3)
- **Category:** Security
- **Severity:** High
- **Requirement source:** AUDIT-REQ-002 (metadata filtering and redaction)
- **Current state (evidence):**
  - `src/filters.zig:250-282` -- `filterAndRedactMetadata` only iterates top-level keys
  - `src/filters.zig:281` -- `else => metadata` returns non-object values unchanged
  - Nested `{"user": {"password": "secret123"}}` passes inner `password` key unredacted
- **Why this is a gap:** Sensitive data in nested metadata objects bypasses redaction entirely
- **Impact/Risk:** Common audit event patterns (request bodies, user profiles) contain nested sensitive data
- **Recommended fix:** Make `filterAndRedactMetadata` recursive with depth limit; handle arrays
- **Acceptance criteria:** Nested object keys matching sensitive patterns are redacted; array elements with sensitive keys redacted; depth bounded
- **Resolution:**
  - Refactored `filterAndRedactMetadata` into a recursive implementation with `max_redaction_depth=10`
  - Added `redactValueRecursive` to process allowed values: recurses into nested objects, scans array elements for sensitive values (PAN, JWT, email, phone, PEM keys), and applies value-type detection on strings
  - Fixed silent field drop bug: when `shouldFilterField` returns `.redact` but `isSensitiveKey` returns null, the field now gets a generic `[REDACTED]` token instead of being silently omitted
  - Added 3 tests: recursive nested object redaction, array element value-type scanning, generic redaction fallback for deny-pattern-only matches
  - Updated existing "metadata filtering and redaction" test and "integration: default deny filtering" test to match corrected behavior

### GAP-009: CI pipeline does not run external test files

- **Status: Resolved**
- **Issue:** [#4](https://gitlab.com/devnw/zig/audit/-/issues/4)
- **Category:** CI-CD
- **Severity:** High
- **Requirement source:** AUDIT-TEST-001 through AUDIT-TEST-003
- **Current state (evidence):**
  - `.gitlab-ci.yml:54-63` -- `test` job now runs `zig build test-all --summary all` (all five test targets)
  - `.gitlab-ci.yml:66-73` -- `test-integration` job retained for separate reporting
- **Resolution:** Changed CI `test` job from `zig build test` to `zig build test-all --summary all`, which runs unit, integration, CEF, filter, and transport tests in one command
- **Acceptance criteria:** CI runs all five test targets; pipeline fails if any external test fails

### GAP-010: Redaction bypass via unrecognized key names

- **Status: RESOLVED**
- **Issue:** [#5](https://gitlab.com/devnw/zig/audit/-/issues/5)
- **Category:** Security
- **Severity:** High
- **Requirement source:** AUDIT-REQ-002 (metadata filtering and redaction)
- **Current state (evidence):**
  - `src/filters.zig:41-87` -- `isSensitiveKey` checks fixed substring list
  - Missing patterns: `secret`, `authorization`, `bearer`, `credential`, `access_key`, `client_secret`, `connection_string`, `database_url`
  - Key `"db_secret"` or `"auth_header"` passes through unredacted
- **Why this is a gap:** Common sensitive key naming conventions are not covered
- **Impact/Risk:** Sensitive values under non-matching key names leak into audit logs
- **Recommended fix:** Add missing patterns; consider making the list configurable
- **Acceptance criteria:** `isSensitiveKey("db_secret")`, `isSensitiveKey("authorization")`, etc. return redaction tokens
- **Resolution:**
  - Added 7 new patterns to `isSensitiveKey` in `src/filters.zig`:
    - `"secret"` -> `.token`, `"credential"` -> `.token`, `"bearer"` -> `.token`
    - `"authorization"` -> `.token`, `"access_key"` -> `.token`
    - `"passphrase"` -> `.password`, `"pin"` -> `.card`
  - Added "expanded sensitive key detection" test verifying all new patterns including case insensitivity
  - `isSensitiveKey("db_secret")`, `isSensitiveKey("authorization")`, `isSensitiveKey("bearer_token")`, etc. now return correct redaction tokens

### GAP-011: Plaintext syslog with no encryption warning to consumers

- **Issue:** [#6](https://gitlab.com/devnw/zig/audit/-/issues/6)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** AUDIT-REQ-006
- **Current state (evidence):**
  - `src/syslog.zig:203-209` -- `sendUdp` sends plaintext with no warning
  - `src/syslog.zig:211-223` -- `sendTcp` sends plaintext with no warning
  - No documentation warns about plaintext transport
- **Why this is a gap:** Audit data traverses the network unencrypted with no consumer awareness
- **Impact/Risk:** Data exposure on shared or untrusted networks
- **Recommended fix:** Log a warning on first UDP/TCP send; document the limitation
- **Acceptance criteria:** Warning logged; documentation updated; warning suppressible via config

### GAP-012: README claims Zero Dependencies -- factually incorrect

- **Issue:** [#7](https://gitlab.com/devnw/zig/audit/-/issues/7)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** AUDIT-PKG-001
- **Current state (evidence):**
  - `README.md:10` -- "Zero Dependencies: Pure Zig standard library only"
  - `build.zig.zon:6-9` -- `dns` dependency declared
  - `src/syslog.zig:14` -- `const dns = @import("dns");`
- **Why this is a gap:** README factually contradicts the build manifest
- **Impact/Risk:** Misleads consumers about dependency footprint and supply chain
- **Recommended fix:** Update README to state "Minimal Dependencies: One external package (DNS resolution)"
- **Acceptance criteria:** README no longer claims zero dependencies; dns dependency is listed
- **Status: Resolved**
- **Resolution:** Changed "Zero Dependencies: Pure Zig standard library only" to "Minimal Dependencies: Zig standard library plus a small DNS resolution library"

### GAP-013: README Quick Start calls non-existent audit.init() function

- **Issue:** [#8](https://gitlab.com/devnw/zig/audit/-/issues/8)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** Documentation requirements
- **Current state (evidence):**
  - `README.md:47` -- `try audit.init(.{ .debug = true });`
  - `src/root.zig:36-61` -- Public API has no `init` function
  - `src/root.zig:16-28` -- Doc comment shows correct usage pattern
- **Why this is a gap:** Quick Start code does not compile against the actual API
- **Impact/Risk:** New users cannot follow the Quick Start
- **Recommended fix:** Replace Quick Start with pattern from `src/root.zig` doc comments
- **Acceptance criteria:** README Quick Start compiles against the actual public API

### GAP-014: docs/README.md links to 5 non-existent documentation pages

- **Issue:** [#9](https://gitlab.com/devnw/zig/audit/-/issues/9)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** Documentation requirements
- **Current state (evidence):**
  - `docs/README.md:9-13` -- Links to `getting-started.md`, `api-reference.md`, `examples.md`, `architecture.md`, `faq.md`
  - None of these files exist in `docs/`
- **Why this is a gap:** Broken documentation links
- **Impact/Risk:** Erodes documentation trust
- **Recommended fix:** Create the linked pages or remove dead links
- **Acceptance criteria:** All links in `docs/README.md` resolve to existing files

### GAP-015: No file logging or syslog usage examples

- **Issue:** [#10](https://gitlab.com/devnw/zig/audit/-/issues/10)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** `docs/REQUIREMENTS.md:41-42` (DOC-001, DOC-002)
- **Current state (evidence):**
  - `docs/REQUIREMENTS.md:41-42` -- "Provide one example for local file logging. Provide one example for syslog emission."
  - `examples/basic.zig:11-24` -- Placeholder with no audit library usage
  - No other example files exist
- **Why this is a gap:** Required examples do not exist
- **Impact/Risk:** Consumers have no reference implementation for file or syslog sinks
- **Recommended fix:** Create `examples/file_logging.zig` and `examples/syslog_example.zig`; wire into build.zig
- **Acceptance criteria:** File logging and syslog examples exist, compile, and are wired into build.zig

### GAP-016: PRNG seeded from microTimestamp -- predictable trace/span IDs

- **Issue:** [#11](https://gitlab.com/devnw/zig/audit/-/issues/11)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** AUDIT-REQ-003 (clock and ID abstractions)
- **Current state (evidence):**
  - `src/time.zig:137-139` -- `std.Random.DefaultPrng.init(@intCast(std.time.microTimestamp()))`
  - `src/time.zig:146-157` -- `traceIdImpl` and `spanIdImpl` use this PRNG
- **Why this is a gap:** Low-entropy seed makes IDs predictable if startup time is approximately known
- **Impact/Risk:** Predictable trace/span IDs could allow audit trail correlation or forgery
- **Recommended fix:** Use `std.crypto.random` (OS entropy) instead of timestamp-seeded PRNG
- **Acceptance criteria:** `SystemIdGen` uses OS entropy; IDs not predictable from startup time; `FixedIdGen` still works for tests
- **Status: Resolved**
- **Resolution:** Replaced `std.time.microTimestamp()` seed with `std.crypto.random.bytes()` for OS-sourced entropy; `FixedIdGen` unchanged

### GAP-017: No AuditEvent field validation

- **Issue:** [#12](https://gitlab.com/devnw/zig/audit/-/issues/12)
- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** AUDIT-REQ-001 (AuditEvent model)
- **Current state (evidence):**
  - `src/events.zig:62-79` -- `init()` sets `category = ""`, `action = ""`, `actor_id = ""`
  - `src/cef.zig:16` -- Empty fields produce signature_id `"."` in CEF
  - `src/logger.zig:70-143` -- `audit()` does not validate before processing
- **Why this is a gap:** Empty required fields produce malformed CEF messages
- **Impact/Risk:** SIEM parsers receive invalid CEF with empty fields
- **Recommended fix:** Add `validate()` method; call it in `AuditLogger.audit()`
- **Acceptance criteria:** Empty category/action/actor_id returns validation error; `audit()` calls validate

### GAP-018: Config parser uses force-unwrap -- panics on malformed JSON

- **Issue:** [#13](https://gitlab.com/devnw/zig/audit/-/issues/13)
- **Category:** Bug
- **Severity:** Medium
- **Requirement source:** Robustness requirement
- **Current state (evidence):**
  - `src/config.zig:174-263` -- `parseConfig` uses `.?` (force-unwrap) ~20 times
  - `src/config.zig:185-189` -- `service_obj.get("name").?.string` panics if key missing
  - `src/config.zig:194-211` -- Multiple `.?` unwraps on identity and sink config
- **Why this is a gap:** Missing or wrong-type JSON fields cause unreachable panic instead of error
- **Impact/Risk:** Config typos crash the entire process in production
- **Recommended fix:** Replace `.?` with `orelse return error.MissingField`; add type checking
- **Acceptance criteria:** Missing keys return error; wrong types return error; tests with partial/malformed config pass
- **Status: Resolved**
- **Resolution:** Replaced all ~20 `.?` force-unwraps with typed helper functions (`jsonString`, `jsonInteger`, `jsonBool`, `jsonObject`, `jsonArray`) that return `error.InvalidConfig` on missing/wrong-type fields. Added 8 inline tests for missing version, invalid version type, unsupported version, missing service, missing service.name, wrong type for service.name, and valid complete config parsing.

### GAP-019: freeJsonValue and cloneJsonValue duplicated across 4 files

- **Issue:** [#14](https://gitlab.com/devnw/zig/audit/-/issues/14)
- **Category:** Code Quality
- **Severity:** Low
- **Requirement source:** Code maintainability
- **Current state (evidence):**
  - `src/events.zig:87-108` and `src/events.zig:140-166` -- `freeJsonValue` and `cloneJsonValue`
  - `src/file_sink.zig:99-120` and `src/file_sink.zig:189-215` -- duplicate copies
  - `src/filters.zig:320-346` -- `cloneJsonValue` duplicate
  - `src/logger.zig:177-203` and `src/logger.zig:205-226` -- duplicate copies
- **Why this is a gap:** Four identical copies of the same logic; bug fixes must be replicated
- **Impact/Risk:** Maintenance burden; risk of implementation drift
- **Recommended fix:** Extract into shared `src/json_util.zig` module
- **Acceptance criteria:** Single implementation; all call sites import from shared module; tests pass
- **Status: RESOLVED**
- **Resolution:**
  - Created `src/json_util.zig` with shared `freeJsonValue` and `cloneJsonValue` functions
  - Removed local duplicates from `src/events.zig`, `src/filters.zig`, `src/file_sink.zig`, `src/logger.zig`
  - Removed local `freeJsonValue` from `tests/test_filters.zig`
  - Re-exported `json_util` through `src/root.zig` for external test access
  - Added unit tests for scalars, strings, nested objects, and arrays in `src/json_util.zig`
  - All 62 tests pass with `zig build test-all`

### GAP-020: fsync per event in file_sink

- **Issue:** [#15](https://gitlab.com/devnw/zig/audit/-/issues/15)
- **Category:** Performance
- **Severity:** Low
- **Requirement source:** AUDIT-REQ-005 (file sink)
- **Current state (evidence):**
  - `src/file_sink.zig:57` -- `try file.sync();` called per event
  - `src/file_sink.zig:94` -- `try file.sync();` called per error write
  - No batching or configurable flush interval
- **Why this is a gap:** fsync per event creates I/O latency under high throughput
- **Impact/Risk:** Performance degradation for high-volume audit services
- **Recommended fix:** Add configurable `flush_interval_ms` or `flush_every_n`; default to periodic fsync
- **Acceptance criteria:** Configurable flush; `sync_per_event: true` option preserves current behavior

### GAP-021: New socket per UDP/TCP syslog message -- no connection reuse

- **Issue:** [#16](https://gitlab.com/devnw/zig/audit/-/issues/16)
- **Category:** Performance
- **Severity:** Low
- **Requirement source:** AUDIT-REQ-006 (syslog transport)
- **Current state (evidence):**
  - `src/syslog.zig:203-209` -- `sendUdp`: socket created and closed per message
  - `src/syslog.zig:211-223` -- `sendTcp`: socket created, connected, closed per message
  - DNS resolution also per message via `resolveHostToAddress`
- **Why this is a gap:** Socket creation and DNS resolution overhead per message
- **Impact/Risk:** FD exhaustion or DNS rate limiting under high throughput
- **Recommended fix:** Maintain persistent sockets; reconnect on error; cache DNS
- **Acceptance criteria:** TCP/UDP connections reused; DNS cached; reconnection handles errors

### GAP-022: JSON round-trip in AuditEvent.clone()

- **Issue:** [#17](https://gitlab.com/devnw/zig/audit/-/issues/17)
- **Category:** Performance
- **Severity:** Low
- **Requirement source:** AUDIT-REQ-001 (AuditEvent model)
- **Current state (evidence):**
  - `src/events.zig:128-135` -- Round-trip: `Stringify.valueAlloc` then `parseFromSlice` then `cloneJsonValue`
  - `src/events.zig:140-166` -- Direct `cloneJsonValue` exists and could be called directly
- **Why this is a gap:** Three allocations where one would suffice
- **Impact/Risk:** Triples memory allocation pressure for metadata cloning on every `audit()` call
- **Recommended fix:** Replace round-trip with direct `cloneJsonValue(allocator, metadata)` call
- **Acceptance criteria:** `clone()` uses direct clone; no intermediate serialization; tests pass
- **Status: RESOLVED**
- **Resolution:**
  - Replaced the three-step round-trip (serialize -> parse -> clone) in `AuditEvent.clone()` with a single `json_util.cloneJsonValue(allocator, metadata)` call
  - Eliminates intermediate JSON string allocation and re-parsing
  - All 62 tests pass with `zig build test-all`

### GAP-023: Silent ring buffer overflow -- no alerting

- **Issue:** [#18](https://gitlab.com/devnw/zig/audit/-/issues/18)
- **Category:** Observability
- **Severity:** Medium
- **Requirement source:** Operational visibility
- **Current state (evidence):**
  - `src/syslog.zig:128-133` -- Full queue silently drops oldest message
  - No counter tracks dropped messages
  - No warning logged on overflow
- **Why this is a gap:** Audit event loss is undetectable
- **Impact/Risk:** Silent loss of audit records in compliance context
- **Recommended fix:** Add `dropped_count` counter; log warning on overflow; expose counter
- **Acceptance criteria:** Counter incremented on overflow; warning logged; counter accessible; test verifies

### GAP-024: CODEOWNERS placeholder @your-username

- **Issue:** [#19](https://gitlab.com/devnw/zig/audit/-/issues/19)
- **Category:** Config
- **Severity:** Low
- **Requirement source:** Repository governance
- **Current state (evidence):**
  - `CODEOWNERS:3` -- `* @your-username`
- **Why this is a gap:** Code review assignments do not route to real owners
- **Impact/Risk:** MR approval rules referencing CODEOWNERS are ineffective
- **Recommended fix:** Replace `@your-username` with actual maintainer handle
- **Acceptance criteria:** CODEOWNERS contains valid GitLab username(s) or group(s)
- **Status: Resolved**
- **Resolution:** Replaced `@your-username` with `@benjiv`

### GAP-025: CHANGELOG placeholder YYYY-MM-DD

- **Issue:** [#20](https://gitlab.com/devnw/zig/audit/-/issues/20)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** Release documentation
- **Current state (evidence):**
  - `CHANGELOG.md:18` -- `## [0.1.0] - YYYY-MM-DD`
- **Why this is a gap:** Placeholder date in published changelog
- **Impact/Risk:** Looks unfinished to consumers
- **Recommended fix:** Set actual release date or remove section until release
- **Acceptance criteria:** CHANGELOG has no placeholder dates
- **Status: Resolved**
- **Resolution:** Replaced `YYYY-MM-DD` with `2026-03-22`; updated boilerplate entries with actual 0.1.0 extraction feature descriptions

### GAP-026: Dead code -- unused functions never called

- **Issue:** [#21](https://gitlab.com/devnw/zig/audit/-/issues/21)
- **Category:** Code Quality
- **Severity:** Low
- **Requirement source:** Code maintainability
- **Current state (evidence):**
  - `src/syslog.zig:238-253` -- `releasePooledConnection` unreachable (TLS returns error)
  - `src/syslog.zig:255-271` -- `verifyCertificatePin` never called
- **Why this is a gap:** Dead code increases maintenance surface
- **Impact/Risk:** Confusion for maintainers; unnecessary code coverage gaps
- **Recommended fix:** Mark with `// TODO(tls)` or remove until TLS lands (GAP-005)
- **Acceptance criteria:** Dead code removed or clearly marked as pending TLS

### GAP-027: TLS pool struct fields allocated but unused

- **Issue:** [#22](https://gitlab.com/devnw/zig/audit/-/issues/22)
- **Category:** Code Quality
- **Severity:** Low
- **Requirement source:** Code maintainability
- **Current state (evidence):**
  - `src/syslog.zig:59-60` -- `tls_pool` and `pool_mutex` allocated on every SyslogSender instance
  - `src/syslog.zig:70-73` -- Pool initialized even for UDP/TCP
  - `src/config.zig:100-101` -- `pool_size` and `idle_timeout_ms` never read
- **Why this is a gap:** Wasted memory; confuses maintainers
- **Impact/Risk:** Minor memory waste per SyslogSender instance
- **Recommended fix:** Gate behind `protocol == .tls` or remove until TLS lands
- **Acceptance criteria:** TLS pool fields not allocated for UDP/TCP; or removed pending TLS

### GAP-028: examples/basic.zig is placeholder not wired into build

- **Issue:** [#23](https://gitlab.com/devnw/zig/audit/-/issues/23)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** Documentation requirements
- **Current state (evidence):**
  - `examples/basic.zig:11-24` -- Prints "Example completed successfully!" without using audit library
  - `build.zig` -- No example build step defined
  - Example code is commented out
- **Why this is a gap:** Placeholder example does not demonstrate the library; may rot
- **Impact/Risk:** Example does not compile against actual API
- **Recommended fix:** Update to use audit library; add example build step in build.zig
- **Acceptance criteria:** Example imports and uses audit library; compiles as part of build.zig; CI verifies

### GAP-029: DNS dependency pinned to commit hash, not tagged release

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
