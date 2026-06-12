# Gap Closure Completion Report

Date: 2026-03-22
Repository: `gitlab.com/devnw/zig/audit`
Branch: `main`
Commits: 45c2e45, 87c5e8f, df01e98

## GAP_ANALYSIS Status

| File | Closed | Blocked | Won't Do | Remaining Open | Total |
|------|--------|---------|----------|----------------|-------|
| GAP_ANALYSIS.md | 21 | 2 (GAP-005, GAP-029) | 2 (GAP-002, GAP-003) | 2 (GAP-020, GAP-021) | 27 |
| SECURITY_GAP_ANALYSIS.md | 9 (S1-S8, S10) | 0 | 0 | 5 (S9, SC-1, S11, S12*, S13) | 14 |
| QUALITY_GAP_ANALYSIS.md | 12 | 0 | 0 | 9 | 21 |
| PERF_GAP_ANALYSIS.md | 2 (PERF-004, PERF-019) | 0 | 0 | 17 | 19 |

*S12 is moot -- the dead code containing the cast was removed via GAP-026/GAP-027.*

**Overall:** 21 GAP items closed, 2 blocked, 2 won't do, 4 deferred open out of 29 total GAP items.

## Closed Items

| Gap-ID | Issue | Title | Evidence |
|--------|-------|-------|----------|
| GAP-006 | #1 | CEF escape functions are no-ops | `src/cef.zig:152-180`, `tests/test_cef.zig`, 8 new tests |
| GAP-007 | #2 | pii_mode/pci_mode parsed but never enforced | `src/filters.zig` (detectValueTypeFiltered, redactOrMaskValue) |
| GAP-008 | #3 | Metadata redaction does not recurse | `src/filters.zig` (filterAndRedactMetadata recursive, max_depth=10), 3 new tests |
| GAP-009 | #4 | CI does not run external test files | `.gitlab-ci.yml:54-63` (test-all target) |
| GAP-010 | #5 | Redaction bypass via unrecognized keys | `src/filters.zig:41-87` (7 new patterns), new test |
| GAP-011 | #6 | Plaintext syslog with no warning | `src/syslog.zig` (init-time warning) |
| GAP-012 | #7 | README claims Zero Dependencies | `README.md:10` ("Minimal Dependencies") |
| GAP-013 | #8 | README Quick Start calls non-existent API | `README.md` Quick Start section |
| GAP-014 | #9 | Broken doc links | `docs/` directory (real files created) |
| GAP-015 | #10 | No usage examples | `examples/basic.zig` (working example) |
| GAP-016 | #11 | Predictable PRNG seed | `src/time.zig:137-139` (std.crypto.random) |
| GAP-017 | #12 | No AuditEvent field validation | `src/events.zig` (validate method), 7 tests |
| GAP-018 | #13 | Config parser force-unwrap panics | `src/config.zig` (typed helpers), 8 inline tests |
| GAP-019 | #14 | JSON util duplicated across 4 files | `src/json_util.zig` (~170 LOC deduplication) |
| GAP-022 | #17 | JSON round-trip in clone() | `src/events.zig` (direct cloneJsonValue) |
| GAP-023 | #18 | Silent ring buffer overflow | `src/syslog.zig` (dropped_count + warning) |
| GAP-024 | #19 | CODEOWNERS placeholder | `CODEOWNERS:3` (@benjiv) |
| GAP-025 | #20 | CHANGELOG placeholder | `CHANGELOG.md` (2026-03-22) |
| GAP-026 | #21 | Dead code (unused functions) | `src/syslog.zig`, `src/events.zig` (functions removed) |
| GAP-027 | #22 | TLS pool fields unused | `src/syslog.zig` (fields removed) |
| GAP-028 | #23 | Placeholder example not wired | `examples/basic.zig`, `build.zig` (example step) |

## Won't Do Items

| Gap-ID | File | Title | Reason |
|--------|------|-------|--------|
| GAP-002 | GAP_ANALYSIS_RESOLVED.md | Geode DB adapter in package tree | Geode-side task; db_adapter.zig stays in Geode by design |
| GAP-003 | GAP_ANALYSIS_RESOLVED.md | Duplicate audit stack under src/security | Geode-side reconciliation task |

## Blocked Items

| Gap-ID | Issue | Title | Blocker | Unblock Steps |
|--------|-------|-------|---------|---------------|
| GAP-005 | (none) | TLS syslog transport | Zig stdlib `std.crypto.tls.Client` not stable | Monitor Zig stdlib TLS stabilization; evaluate zig-bearssl as alternative |
| GAP-029 | #24 | DNS dependency pinned to commit | Requires tagging release in `devnw/zig/dns` repo | Create tagged release in DNS repo; update build.zig.zon |

## Open (Deferred) Items

| Gap-ID | Issue | Title | Reason |
|--------|-------|-------|--------|
| GAP-020 | #15 | fsync per event in file_sink | Low priority performance; address when throughput requirements materialize |
| GAP-021 | #16 | Socket per syslog message | Low priority performance; address when throughput requirements materialize |

## Tests Executed

| Command | Result |
|---------|--------|
| `zig build test-all --summary all` | PASS (81/81 tests, 13/13 build steps) |

## Security Notes

- **All Critical and High severity security findings resolved** (S1 through S6, S10)
- CEF log injection (S1/GAP-006) fixed with proper escaping; adversarial test added
- PII/PCI mode enforcement (S2/GAP-007) wired into filter pipeline
- Recursive metadata redaction (S3/GAP-008) prevents nested data leaks
- Plaintext transport warning (S4/GAP-011) alerts operators at init time
- Sensitive key detection (S5/GAP-010) expanded with 7 new patterns
- PRNG seed (S7/GAP-016) now uses OS entropy via std.crypto.random
- Dead TLS code removed (S6/GAP-026/GAP-027) to reduce false security surface
- Ring buffer overflow (S10/GAP-023) now tracked and warned
- Remaining open security items: S9 (path traversal, Medium), SC-1 (supply chain, Low), S11 (DNS spoofing, Low), S13 (test mock panic, Low)

## Remaining Blockers

- **GAP-005 (TLS transport):** Blocked on Zig stdlib maturity. Workaround: use stunnel or TCP with network-layer encryption. No action possible until Zig TLS stabilizes.
- **GAP-029 (DNS tag):** Requires cross-repo action in `devnw/zig/dns`. Content hash provides integrity verification in the meantime.

## Platform Issues Updated

| Gap-ID | Issue | Action |
|--------|-------|--------|
| GAP-006 | #1 | closed |
| GAP-007 | #2 | closed |
| GAP-008 | #3 | closed |
| GAP-009 | #4 | closed |
| GAP-010 | #5 | closed |
| GAP-011 | #6 | closed |
| GAP-012 | #7 | closed |
| GAP-013 | #8 | closed |
| GAP-014 | #9 | closed |
| GAP-015 | #10 | closed |
| GAP-016 | #11 | closed |
| GAP-017 | #12 | closed |
| GAP-018 | #13 | closed |
| GAP-019 | #14 | closed |
| GAP-020 | #15 | commented (deferred) |
| GAP-021 | #16 | commented (deferred) |
| GAP-022 | #17 | closed |
| GAP-023 | #18 | closed |
| GAP-024 | #19 | closed |
| GAP-025 | #20 | closed |
| GAP-026 | #21 | closed |
| GAP-027 | #22 | closed |
| GAP-028 | #23 | closed |
| GAP-029 | #24 | commented (blocked) |

---

## 2026-06-12 Remediation Cycle Close-Out

Date: 2026-06-12
Repository: `gitlab.com/devnw/zig/audit`
Branch: `fix/audit-remediation-2026-06-11`
Commit range (main..HEAD): afcd0bc..9391d12 (41 commits, ~5100 insertions)
Verification: docs/APPSEC_REVIEW_2026-06-12_iter2.md (iter-2 appsec re-review) + independent gap-closure verification

### GAP_ANALYSIS Status

| File | Closed | Blocked/Won't-Do | New | Remaining Open | Total This Cycle |
|------|--------|-----------------|-----|----------------|-----------------|
| GAP_ANALYSIS.md | 36 (GAP-040..074 + DD1 + QR/PR series) | 0 | 1 (#121) | 9 (GAP-005, GAP-029, GAP-045, PR-002/003/004/007/009, QR-008, QR-018) | 36 closed |
| SECURITY_GAP_ANALYSIS.md | A1-A8/GAP-040..047/GAP-050/063 + S9(resolved) | 0 | 0 | SC-1/GAP-045, S11 (open-documented) | All security Critical/High closed |
| PERF_GAP_ANALYSIS.md | PR-001/005/006/008/010(partial)/012/013 + PERF-001/005/008/009/012/014 | 0 | 0 | PR-002/003/004/007/009 | 14 resolved |
| QUALITY_GAP_ANALYSIS.md | Q11/Q16(syslog.zig split -- partial)/Q19 + QR-001..005/007/009..016 | 0 | 0 | Q16 (partial) | 20/21 resolved |

**Overall 2026-06-12 cycle:** 55 issues closed, 1 issue created (#121), 9 issues left open, 1 partial (Q16/syslog.zig decomposition).

### Gate Results

| Command | Result |
|---------|--------|
| `zig build test-all --summary all` | PASS (158 tests, 157 pass, 1 otel skip -- pre-existing N1) |
| `zig build test -Doptimize=ReleaseSafe` | PASS |
| `zig build test -Doptimize=ReleaseFast` | PASS |
| `zig build test -Dwith_otel=true` | 1 FAIL (pre-existing N1 -- `observability.enabled` hardcoded false, commit a1f5c10, not this branch) |
| `pre-commit run --all-files` | PASS (markdownlint, gitleaks, ruff, pyright) |

### Performance Headline Numbers (post-remediation baseline)

| Metric | Before | After |
|--------|--------|-------|
| File sink throughput (10K events) | ~3,004 ops/sec | ~32,717 ops/sec |
| Per-event allocations | ~70-80 alloc/free pairs | Significantly reduced (streaming + single-copy pipeline) |
| File sink write syscalls | 2 per record | 1 per record + batch flush |
| Metadata pipeline copies | 3-4 deep copies | 1 (single-copy + move) |

### Closed Items (this cycle)

| Gap-ID | Issue | Title | Evidence |
|--------|-------|-------|----------|
| GAP-040 | #57 | config @intCast panic/truncation | `config.zig:239-242`, tests `:679-732` |
| GAP-041 | #58 | file-sink silent drops | `file_sink.zig:39,96-105`, tests `:1386-1435` |
| GAP-042 | #60 | control chars in CEF/syslog | `cef.zig:247-291`, tests `test_cef.zig:331-343` |
| GAP-043 | #62 | path-traversal mitigation | `file_sink.zig:420-466`, `config.zig:117-131`, tests `:1214-1384` |
| GAP-044 | #63 | formatRfc3339 negative timestamp | `time.zig:51-57`, tests `:288-305` |
| GAP-046 | #66 | ts_unix_ms never rendered | `file_sink.zig:313-316`, `cef.zig:27-30`, `syslog.zig:200-203` |
| GAP-047 | #67 | validate() missing control-char check | `events.zig:118-132`, tests `:282-315` |
| GAP-048 | #69 | cloneJsonValue partial-clone OOM leak | `json_util.zig:54-89`, test `:162-203` |
| GAP-049 | #70 | metadata deep-copied 4x | `logger.zig:125,254-276`, `file_sink.zig:308-372` |
| GAP-050 | #72 | PiiMode.hash unhandled | `filters.zig:286-314,432-438`, tests `test_filters.zig:1041-1099` |
| GAP-051 | #73 | TCP prefix heap alloc | `syslog.zig:329-332` |
| GAP-052 | #75 | double CEF escaping | `cef.zig` + `syslog.zig` rewrite |
| GAP-053 | #76 | ObjectMap without capacity hint | `file_sink.zig:308-372` (eliminated) |
| GAP-054 | #77 | detectValueType called twice | `filters.zig` (commit 57852e2) |
| GAP-055 | #79 | constant JSON key heap-dupe | `file_sink.zig:308-372` |
| GAP-056 | #81 | serialize-to-measure pass | `file_sink.zig` counting writer |
| GAP-057 | #83 | no streaming JSON writer | `file_sink.zig:323-367` |
| GAP-058 | #84 | audit() 129 lines | `logger.zig` (commit 716e34b) |
| GAP-059 | #85 | parseConfig 112 lines | `config.zig` (commit 716e34b) |
| GAP-060 | #87 | complex redaction control flow | `filters.zig` (commit 716e34b) |
| GAP-061 | #88 | unreachable PEM branch | `filters.zig:550-562` |
| GAP-062 | #90 | unused pub helpers | `root.zig` (commits cb07dae + 716e34b) |
| GAP-063 | #92 | umask race before setPermissions | `file_sink.zig:509-528`, test `:1180-1212` |
| GAP-064 | #93 | CI components pinned to mutable tags | `.gitlab-ci.yml`, `.pre-commit-config.yaml` |
| GAP-065 | #94 | zig toolchain single-origin trust | `.gitlab-ci.yml` |
| GAP-066 | #95 | pkg_hash path-join unsanitized | `scripts/sync_diamond_deps.py:80` |
| GAP-067 | #96 | parse_target unhandled ValueError | `scripts/sync_diamond_deps.py` |
| GAP-068 | #97 | rewrite_pin no quoting guard | `scripts/sync_diamond_deps.py` |
| GAP-069 | #98 | integration.zig missing gitleaks allowlist | `.gitleaks.toml` |
| GAP-070 | #99 | no CI cache | `.gitlab-ci.yml` |
| GAP-071 | #100 | no ruff/typecheck CI gate | `.gitlab-ci.yml` |
| GAP-072 | #101 | requestId OOM swallowing | `time.zig:124-127` (vtable removed) |
| GAP-073 | #102 | requestId vtable still present | `time.zig:124-127` (vtable removed) |
| GAP-074 | #103 | version drift root.zig vs zon | `root.zig:39`, `build.zig:29` |
| GAP-DD1 | #104 | sync_mode default (design decision) | `config.zig` (commit 84c976d) |
| QR-001 | #105 | use-after-return buildAuditLogger | `logger.zig:29-30,80-85,347-360` |
| QR-002 | #106 | double-free non-object metadata | `filters.zig:398` |
| QR-003 | #107 | truncation path frees string literals | `logger.zig:158-179` |
| QR-004 | #108 | Config pass-by-value double-free | `logger.zig` |
| QR-005 | #109 | span_durable true even on drops | `logger.zig:185-215` |
| QR-007 | #115 | RingBuffer dead code in public API | `root.zig` |
| QR-009 | #117 | rotation size off-by-one | `file_sink.zig:259-263` |
| QR-010 | #118 | i128->i64 @intCast in DNS cache | `syslog.zig:253-254` |
| QR-011 | #110 | isSensitiveKey fails on long keys | `filters.zig:56-117` |
| QR-012 | #111 | missing negative/boundary tests | multiple test locations |
| QR-013 | #119 | redaction tests pass on nothing written | `tests/integration.zig:126-133` |
| QR-014 | #120 | shared mutable tmpdir | `src/file_sink.zig` |
| QR-015 | #112 | SECURITY.md false claims | `SECURITY.md` |
| QR-016 | #113 | README wrong Zig version | `README.md` |
| PR-001 | #59 | ObjectMap rebuild | `file_sink.zig:293-367` |
| PR-005 | #71 | escapeCefString always allocates | `cef.zig` |
| PR-006 | #74 | unbuffered file writes | `file_sink.zig` |
| PR-008 | #80 | RFC3339 formatted 3x per event | `syslog.zig:200-207` |
| PR-010 | #86 | false sharing (partial, remainder in #82) | `channel.zig:33-42,72-79` |
| PR-012 | #89 | 1 item per receive() | `file_sink.zig` batch drain |
| PR-013 | #91 | no multi-producer benchmark | `benchmarks/` |
| PERF-001 | #39 | triple JSON serialization | `logger.zig:254-276`, `file_sink.zig:308-372` |

### Issues Left Open

| Issue | Gap-ID | Reason |
|-------|--------|--------|
| #24 | GAP-029 | Cross-repo blocked (dns repo tagging) |
| #25 | GAP-005 | TLS blocked on Zig stdlib |
| #61 | PR-002 | Deferred (micro-opt) |
| #64 | GAP-045 | Cross-repo blocked |
| #65 | PR-003 | Deferred |
| #68 | PR-004 | Deferred |
| #78 | PR-007 | Heap alloc done (GAP-051); writev/iovec not yet done |
| #82 | PR-009 | Gated on MP bench data; D6 partial done |
| #114 | QR-018 | Syslog portability (documented) |
| #116 | QR-008 | Deferred (explicit error sets, API design) |

### New Issue Created

| Issue | Title | Labels |
|-------|-------|--------|
| #121 | Buffered batch tail discarded without per-line warning on failed mid-batch reopen -- add fault-injection test | gap, type::quality, priority::low |

### Security Notes

- **Every A1-A8 finding (OWASP Top 10:2025) and every security-relevant critical is genuinely closed** in current code, confirmed by code citation and green default-build test matrix.
- Single-copy metadata pipeline verified memory-safe: no cross-thread aliasing, no double-free across sink fan-out.
- Empty-transition channel signaling verified correct under documented single-consumer invariant.
- PEM-under-sensitive-key drops the whole event (fail-closed).
- Streaming JSON serialization injection-safe (std.json.Stringify escapes control bytes in string values natively).
- No new security vulnerabilities introduced by the ~30-commit remediation.
- Pre-existing N1 (-Dwith_otel=true seam test failure) confirmed non-security, not from this branch.
- No live secrets found; no emergency rotation required.

### Remaining Blockers

- **GAP-005 (TLS transport):** Blocked on Zig stdlib TLS maturity. Workaround: stunnel/TCP with network-layer encryption.
- **GAP-029 / GAP-045 (DNS/otel ref drift):** Cross-repo action required. Content hashes provide integrity verification in the meantime.
- **PR-007 (#78):** Heap alloc eliminated (GAP-051 done); writev/iovec single-syscall to be done in a future cycle.

### Platform Issues Updated

| Gap-ID | Issue | Action |
|--------|-------|--------|
| GAP-040 | #57 | closed |
| GAP-041 | #58 | closed |
| GAP-042 | #60 | closed |
| GAP-043 | #62 | closed |
| GAP-044 | #63 | closed |
| GAP-046 | #66 | closed |
| GAP-047 | #67 | closed |
| GAP-048 | #69 | closed |
| GAP-049 | #70 | closed |
| GAP-050 | #72 | closed |
| GAP-051 | #73 | closed |
| GAP-052 | #75 | closed |
| GAP-053 | #76 | closed |
| GAP-054 | #77 | closed |
| GAP-055 | #79 | closed |
| GAP-056 | #81 | closed |
| GAP-057 | #83 | closed |
| GAP-058 | #84 | closed |
| GAP-059 | #85 | closed |
| GAP-060 | #87 | closed |
| GAP-061 | #88 | closed |
| GAP-062 | #90 | closed |
| GAP-063 | #92 | closed |
| GAP-064 | #93 | closed |
| GAP-065 | #94 | closed |
| GAP-066 | #95 | closed |
| GAP-067 | #96 | closed |
| GAP-068 | #97 | closed |
| GAP-069 | #98 | closed |
| GAP-070 | #99 | closed |
| GAP-071 | #100 | closed |
| GAP-072 | #101 | closed |
| GAP-073 | #102 | closed |
| GAP-074 | #103 | closed |
| GAP-DD1 | #104 | closed (design decision) |
| QR-001 | #105 | closed |
| QR-002 | #106 | closed |
| QR-003 | #107 | closed |
| QR-004 | #108 | closed |
| QR-005 | #109 | closed |
| QR-007 | #115 | closed |
| QR-009 | #117 | closed |
| QR-010 | #118 | closed |
| QR-011 | #110 | closed |
| QR-012 | #111 | closed |
| QR-013 | #119 | closed |
| QR-014 | #120 | closed |
| QR-015 | #112 | closed |
| QR-016 | #113 | closed |
| PR-001 | #59 | closed |
| PR-005 | #71 | closed |
| PR-006 | #74 | closed |
| PR-007 | #78 | commented (open -- 2-syscall pattern remains; writev deferred) |
| PR-008 | #80 | closed |
| PR-009 | #82 | commented (D6 partial done; gated on MP bench data) |
| PR-010 | #86 | closed (partial; remainder in #82) |
| PR-012 | #89 | closed |
| PR-013 | #91 | closed |
| PERF-001 | #39 | closed |
| NEW-001 | #121 | created (new issue) |
