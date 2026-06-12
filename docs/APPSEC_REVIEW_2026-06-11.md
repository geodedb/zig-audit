# Application Security Review — devnw/zig/audit

**Date:** 2026-06-11
**Reviewer:** Claude (defensive appsec code review)
**Repository:** `gitlab.com/devnw/zig/audit` (working tree at `/home/benji/src/gl/gitlab.com/devnw/zig/audit`)
**Standards:** OWASP Top 10:2025, CIS Controls v8.1.2
**Toolchain verified:** Zig 0.16.0 (used to reproduce panics/UB empirically)

---

## 1. Scope & Assumptions

**In scope (read directly from disk):** all of `src/` (`logger.zig`, `filters.zig`, `channel.zig`, `ring_buffer.zig`, `cef.zig`, `json_util.zig`, `time.zig`, `observability*.zig`, `sync.zig`, `root.zig`, `file_sink.zig`, `config.zig`, `syslog.zig`, `events.zig`), `build.zig`, `build.zig.zon`, `scripts/*.py` + `*.sh`, `.gitlab-ci.yml`, `.pre-commit-config.yaml`, `tests/`, `benchmarks/`, `examples/`, and the prior gap-analysis docs under `docs/`.

**Assumptions / trust model:**

- This is a **library** consumed by host applications. There is no network listener, no authn/authz of its own. Threats come from: (a) attacker-controlled **event field values** and **metadata** passed by the host app, (b) operator-controlled **config files**, (c) the **network path** to the syslog server, (d) **supply chain** (pinned deps, CI).
- "Attacker-controlled" = data the host application forwards into an `AuditEvent` (e.g., a username, source IP, request metadata derived from an untrusted request).
- Reproductions were run in Debug and `ReleaseSafe`/`ReleaseFast` (the optimization modes the CI matrix builds) using Zig 0.16.0.

**Prior-review reconciliation:** Claimed resolutions of S1–S8, S10 in `docs/SECURITY_GAP_ANALYSIS.md` were verified. **S1 (CEF escape no-ops), S2/S3/S5 (redaction modes + recursion), S6 (TLS rejected at init), S7 (secure PRNG seed), S8 (event validation), S10 (syslog drop counter)** are genuinely fixed in code — confirmed, not re-reported. New findings below are either net-new or **residual gaps** in a claimed-resolved item, with code evidence that the residual holds.

---

## 2. Executive Summary

- The codebase is in materially better shape than the prior review's baseline: all Critical/High items from `SECURITY_GAP_ANALYSIS.md` are genuinely resolved in code (CEF escaping is wired in, redaction recurses and honors `pii_mode`/`pci_mode`, TLS is rejected at init, the PRNG seed is secure, events are validated). Good defensive design is present (single-consumer channels, depth-bounded redaction, `default-deny` filtering, restrictive `0o640` file perms).
- The most material **new** issue is **unvalidated integer coercion in `config.loadConfig`** (`@intCast` on JSON integers). A malformed config **panics under Debug/ReleaseSafe (DoS)** and, worse, **silently truncates under ReleaseFast** (e.g. `port: 99999` → `34463`), causing the audit transport to connect to an unintended port with no error. Reproduced live. This is both an availability and an audit-integrity problem and is rated **Medium-High**.
- **Audit-trail integrity under backpressure is incomplete.** The file sink drops records silently when its channel is full: `FileSink.write` returns success, increments no counter, and exposes no metric (only a per-event `log.warn`). The syslog sender's drop counter (GAP-023) was **not mirrored to the file sink**. A caller cannot detect file-sink audit loss. **Medium.**
- **CEF/syslog escaping does not neutralize control characters** other than `\n`/`\r`. NUL, TAB, BEL, DEL, and other C0 bytes in attacker-controlled fields pass through verbatim into the RFC 5424 line (reproduced). This is a residual of the log-injection class (S1 fixed delimiters, not control bytes). **Low-Medium.**
- **Path-traversal mitigation is incomplete (residual S9).** `FileSink.openCurrentFile` rejects only the `".."` substring; **absolute paths** (`/etc/cron.d/x`) and symlinked directories still escape any intended base. The prior fix guidance ("resolve to absolute, verify against an allowed base") was not implemented. **Medium.**
- A **supply-chain auditability smell**: the `dns` dependency requests `?ref=v0.1.9` but its recorded content `.hash` self-labels `dns-0.1.8-...`. Content integrity is still cryptographically pinned, but the ref/version mismatch is exactly the drift the repo's own diamond-detector is meant to catch. **Low.**
- Scripts (`scripts/*.py`, `*.sh`) and CI are clean of command injection / `curl|sh`-into-shell patterns: all subprocess calls are list-form (no `shell=True`), CI pins components by tag and SHA-256-verifies the Zig toolchain. No real secrets found.

Overall confidence: **High** for the reproduced findings (config coercion, control chars, timestamp panic), **High** for the code-evidence findings (file-sink drop, path traversal residual, supply-chain pin).

---

## 3. Findings Table

| ID | Title | Severity | OWASP 2025 / CIS / CWE | Location |
|----|-------|----------|------------------------|----------|
| A1 | Unvalidated integer coercion in config parsing → DoS panic (ReleaseSafe) / silent truncation (ReleaseFast) | **Medium** | A10 Mishandling of Exceptional Conditions / A06 Insecure Design; CIS 16.10/16.11; CWE-190, CWE-20, CWE-704 | `src/config.zig:242,272,278,279,291` |
| A2 | File-sink audit records dropped silently under backpressure (no counter, no signal to caller) | **Medium** | A09 Logging & Alerting Failures / A06; CIS 8.2/8.11; CWE-778, CWE-392 | `src/file_sink.zig:82-86,89-106` |
| A3 | Control characters (NUL/TAB/BEL/DEL/C0) not escaped in CEF/syslog output → log injection / parser corruption | **Low-Medium** | A05 Injection / A09; CIS 8.3; CWE-117, CWE-93, CWE-158 | `src/cef.zig:218-234` |
| A4 | Path-traversal mitigation incomplete: absolute paths & symlinks bypass the `".."` check (residual S9) | **Medium** | A01 Broken Access Control; CIS 3.3; CWE-22, CWE-73, CWE-59 | `src/file_sink.zig:264-288` |
| A5 | `formatRfc3339` panics on negative timestamp (public API, integer cast to unsigned) | **Low** | A10 Mishandling of Exceptional Conditions; CWE-190, CWE-248 | `src/time.zig:43-45` |
| A6 | Dependency ref/version-hash mismatch in `build.zig.zon` (`?ref=v0.1.9` vs `dns-0.1.8` hash) | **Low** | A03 Software Supply Chain Failures; CIS 2.4/16.6; CWE-1104, CWE-829 | `build.zig.zon:7-10` |
| A7 | Event's own `ts_unix_ms` never rendered; output timestamp is worker-thread "now" (recorded-time drift) | **Low (Info)** | A09 Logging Failures; CWE-1059 | `src/logger.zig:112-113`; `src/cef.zig:31`; `src/file_sink.zig:173` |
| A8 | `AuditEvent.validate()` does not reject control characters in core fields | **Low** | A05 Injection / A03; CWE-20 | `src/events.zig:75-101` |

---

## 4. Finding Details

### A1 — Unvalidated integer coercion in `config.loadConfig` (DoS / silent truncation) — Medium

**Description.** The JSON config parser reads integer fields with `@intCast` directly from `i64` JSON integers into narrower or unsigned targets without range checking. Every other malformed-input case in this parser returns a clean `error.InvalidConfig`, so the missing range check is an inconsistency that turns operator/attacker-influenced config into a crash (safe builds) or a silent wrong value (fast builds).

**Evidence (`src/config.zig`):**

- `.pid = @as(u32, @intCast(try jsonInteger(service_obj, "pid")))` — line 242
- `.max_bytes = @as(u64, @intCast(try jsonInteger(file_obj, "max_bytes")))` — line 278
- `.backup_count = @as(u32, @intCast(try jsonInteger(file_obj, "backup_count")))` — line 279
- `.port = @as(u16, @intCast(try jsonInteger(syslog_obj, "port")))` — line 291
- `sync_interval` (line 272) and `version` (line 231) share the pattern.

**Reproduced (Zig 0.16.0, `loadConfig` with `"port": 99999`):**

- Debug / **ReleaseSafe** → `thread … panic: integer does not fit in destination type` at `config.zig:291` → process abort (DoS).
- **ReleaseFast** → parses "successfully" with `port=34463` (99999 mod 65536) — **silent misconfiguration**: the syslog sink would target the wrong port with no error surfaced.

**Attack path / failure mode.** The CI matrix builds and ships `ReleaseSafe` and `ReleaseFast`. A malformed `audit.json` (operator typo, a value derived from a partially attacker-influenced source, or a negative number) either crashes the host process at startup, or in ReleaseFast silently sends the audit stream to an unintended destination port / mis-sizes rotation (`max_bytes`) / mis-sets `backup_count`. For an audit subsystem, silently changing where records go is an integrity failure, not just a robustness bug. This also directly contradicts SECURITY.md's claim of "No Undefined Behavior."

**Remediation.** Replace each `@intCast` with `std.math.cast(T, value) orelse return error.InvalidConfig` (and bound `port` to 1–65535, `pid`/`max_bytes`/`backup_count`/`sync_interval` to non-negative). Add unit tests for out-of-range and negative values for each numeric field, asserting `error.InvalidConfig` (never a panic). Re-affirm the no-UB claim only after this is closed.

---

### A2 — File-sink audit records dropped silently under backpressure — Medium

**Description.** GAP-023 added a `dropped_count` atomic and a one-shot warning to `SyslogSender` (`src/syslog.zig:105,195-200,203-205`). The **file sink was not given the same treatment.** When the file sink's bounded channel is full, the record is freed and the function returns success.

**Evidence (`src/file_sink.zig:82-86`):**

```zig
if (!self.ch.trySend(json_line)) {
    log.warn("file sink channel full; dropping audit event", .{});
    self.allocator.free(json_line);
}
```

`write` returns `!void` and yields success on this path; the same is true for `writeError` (lines 102-105). There is **no counter** and **no accessor** (`grep` confirms `dropped` exists only in `syslog.zig`). In `AuditLogger.audit` (`src/logger.zig:188-192`) the file-sink call only captures real errors, so a drop is invisible to the caller and to `span_durable`.

**Failure mode.** Under burst load or slow disk, the 10 000-entry file-sink channel fills and audit records are discarded. The host application cannot detect the loss (no return error, no queryable counter), and the per-event `log.warn` both fails to quantify loss and risks log-spam amplification (one stderr line per dropped record). An attacker who can generate audit volume (e.g. a flood of auth events) can deliberately induce file-sink gaps to bury reconnaissance entries — the same threat model that motivated GAP-023 for syslog, left open for the file sink.

**Remediation.** Mirror GAP-023 in `FileSink`: add `dropped_count: std.atomic.Value(u64)`, increment on each drop, log on first drop and rate-limited thereafter, and expose `getDroppedCount()`. Have `audit()` surface non-zero drops (e.g. set `span_durable = false` or return a soft error) so callers can alert. Consider a configurable backpressure policy (block vs drop) for deployments that must not lose records.

---

### A3 — Control characters not escaped in CEF/syslog output — Low-Medium

**Description.** S1 (delimiter escaping) is fixed: `escapeCefString` now escapes `\`, `|` (headers), `=` (extensions), and converts `\n`/`\r`. But it does **not** neutralize other control characters. The `else => try result.append(allocator, c)` branch passes every other byte through verbatim.

**Evidence (`src/cef.zig:222-230`):** the `switch (c)` handles only `\\`, `|`, `=`, `\n`, `\r`; all other bytes fall through unchanged.

**Reproduced.** Feeding extension value `"user\x00\x09\x07\x7Fname"` to `escapeCefString(..., false)` returned the **identical bytes** (NUL, TAB, BEL, DEL all survived; `passthrough=true`). These flow from attacker-controlled `AuditEvent` fields (`actor_id`, `source_ip`, metadata values) through `formatCef` into the RFC 5424 line in `formatRfc5424` (`src/syslog.zig:355`) and over UDP/TCP.

**Attack path.** An embedded **NUL** can truncate downstream C-string-based syslog/SIEM parsers (record-splitting / partial parse); **BEL/ESC** can drive terminal escape sequences if logs are catted to a console; **TAB/other C0** can corrupt column-delimited SIEM ingestion. Newline-based record injection is already closed by S1, so this is a narrower but real residual. (The JSON file sink is safe here — `std.json.Stringify` escapes control bytes in string values.)

**Remediation.** In `escapeCefString`, escape all bytes `< 0x20` and `0x7F` (and ideally validate UTF-8), e.g. emit `\xNN` or strip them. Add a unit test asserting no raw byte `< 0x20` (other than via the `\n`/`\r` escapes) and no `0x7F` survives in output.

---

### A4 — Path-traversal mitigation incomplete (residual S9) — Medium

**Description.** S9 (file path from config not sanitized) was marked Open in the prior review. A partial mitigation was added — a `".."` substring check — but the prior fix guidance ("resolve to an absolute path and verify it does not escape an allowed base directory; reject `..` components") was only half-implemented.

**Evidence (`src/file_sink.zig:264-288`):**

```zig
fn openCurrentFile(self: *FileSink) !void {
    if (std.mem.indexOf(u8, self.config.path, "..") != null) {
        return error.PathTraversalRejected;
    }
    ...
    self.current_file = try cwd.createFile(io, self.config.path, .{ .truncate = false });
```

**Failure mode.** The check is a naive substring match. It does **not** reject **absolute paths** (`"/etc/cron.d/evil"`, `"/var/spool/..."` — no `".."` present), and it does not resolve symlinks in the directory chain (a symlinked `dir/` component escapes any intended base; TOCTOU between `createDirPath` and `createFile` is also possible). The rotation paths (`{path}.N`) inherit the same unvalidated base. Conversely it produces **false positives** on legitimate names like `my..app.log`. Net: arbitrary file creation/overwrite within the process's filesystem permissions, controlled by the config path — elevated impact if the host runs privileged. (Config is operator-level, so likelihood is moderate, but the mitigation advertises protection it doesn't fully provide.)

**Remediation.** Resolve `config.path` to a canonical absolute path (`realpath` of the parent), require it to be **under an explicit allowed base directory**, reject path components equal to `..`, and open the directory with `O_NOFOLLOW`/no-symlink semantics where available. Do not silently swallow `createDirPath` errors (line 273 logs but proceeds). Add tests for absolute-path rejection and symlink-escape rejection.

---

### A5 — `formatRfc3339` panics on negative timestamp — Low

**Description.** `formatRfc3339` casts `@divTrunc(ts_ms, 1000)` into `EpochSeconds.secs` (a `u64`) with `@intCast`, which panics on any negative value.

**Evidence (`src/time.zig:43-45`):**

```zig
const millis_u32: u32 = @intCast(@as(i64, @intCast(millis)));
const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
```

**Reproduced.** `formatRfc3339(-1000, &buf)` → `panic: integer does not fit in destination type` at `time.zig:45`.

**Reachability (important caveat).** The event's own timestamp is **not** rendered to output — all sink output uses `clock.nowRfc3339()` (see A7). So the negative-timestamp panic is **not reachable from a normal `audit()` call with attacker-controlled event data**. It is reachable via: a `FixedClock` constructed with a negative value, a (pathological) system clock before 1970, or a host application calling the **public** `formatRfc3339` / `Clock.nowRfc3339` with a negative input. Hence Low, but it is a public API that crashes on bad input.

**Remediation.** Use `std.math.cast(u64, seconds) orelse return ""` (the function already has a documented empty-string failure contract), or explicitly support pre-epoch timestamps. Add a regression test for negative and far-future inputs.

---

### A6 — Dependency ref/version-hash mismatch in `build.zig.zon` — Low

**Description.** The `dns` dependency URL requests tag `v0.1.9`, but the recorded content hash self-labels version `0.1.8`.

**Evidence (`build.zig.zon:7-10`):**

```zig
.dns = .{
    .url = "git+https://gitlab.com/devnw/zig/dns.git?ref=v0.1.9#dc2329d5355dce4097a71a762869d2d89b541dca",
    .hash = "dns-0.1.8-x4U-zaM-EQA4bavPz0btJDlS3QpjWQaEtoRREyRc-Mef",
},
```

Recent history (`chore(deps): converge tls onto v0.1.9 (GAP-0838 diamond sync)`, `bump to v0.1.6 (tagged sibling deps)`) indicates active pin churn in this area.

**Failure mode.** Zig still verifies the fetched content against the `.hash`, so this is not a content-integrity break. But the mismatch between the requested **ref label** (`v0.1.9`) and the **resolved package version** (`0.1.8`) defeats human/auditor version tracking and CVE matching — precisely the "two labels for one thing" drift the repo's own `scripts/detect_diamond_deps.py` exists to catch. Either the `v0.1.9` tag points at a tree whose `build.zig.zon` self-declares `0.1.8`, or the pin was partially updated.

**Remediation.** Re-fetch and re-pin `dns` so the ref tag and the resolved package version agree (`zig fetch <url>` and commit the emitted hash). Add a CI check (or extend the diamond detector) that flags ref/version-label disagreement, not just duplicate hashes. Mirror the existing OTel SBOM/dependency-scan coverage onto direct deps.

---

### A7 — Event `ts_unix_ms` discarded; output timestamp is worker-thread "now" — Low (Info)

**Description.** `audit()` records `event.ts_unix_ms` (using the clock only when it's 0, `src/logger.zig:112-113`) but **no formatter ever renders it.** CEF (`src/cef.zig:31`), RFC 5424 (`src/syslog.zig:353`), and the JSON file line (`src/file_sink.zig:173`) all stamp `clock.nowRfc3339()` — the current time **at format time**, which (because sinks format on background worker threads draining a channel) can be meaningfully later than when the event occurred.

**Failure mode / integrity note.** The recorded audit timestamp can drift from the true event time under load or queue backlog, and any caller-supplied event time is silently ignored. For an audit/compliance log, "time of record" diverging from "time of event" undermines forensic ordering and correlation. Not a vulnerability per se, but a logging-fidelity defect with security relevance.

**Remediation.** Render `event.ts_unix_ms` (capturing it at enqueue time on the producing thread) as the authoritative event time; optionally add a separate "logged_at" field for processing time. Once A1/A5 are fixed, this path can safely format the i128 event timestamp.

---

### A8 — `AuditEvent.validate()` does not reject control characters — Low

**Description.** S8 added `validate()` (non-empty + length ≤ 1024 for core/optional string fields), which is good. But it does not screen for control characters, which is the input-validation half of A3. The prior S8 acceptance criteria explicitly listed "string fields contain no control characters (except in metadata values)" — that criterion is unmet.

**Evidence (`src/events.zig:75-101`):** `validate` checks only emptiness and `field.len > MAX_FIELD_LEN`.

**Failure mode.** Control bytes in `category`/`action`/`actor_id`/`source_ip` reach the formatters and, combined with A3, emit unescaped control characters. Defense-in-depth: rejecting them at the boundary complements escaping at the sink.

**Remediation.** Extend `validate()` to reject C0 controls and `0x7F` in non-metadata string fields (and optionally validate `source_ip` as an IP literal). Keep escaping at the sink (A3) as the second layer.

---

## 5. Secure Design Notes (what the code does well)

- **CEF delimiter escaping is correctly implemented and wired in** (`src/cef.zig:197-234`): the prior Critical S1 (no-op escapers) is genuinely fixed; headers escape `\`/`|`, extensions escape `\`/`=`/`\n`/`\r`, with good unit coverage.
- **Redaction is depth-bounded and recursive** (`src/filters.zig:298,308-442`): nested objects/arrays are traversed, recursion capped at `max_redaction_depth = 10` to prevent stack exhaustion on adversarial nesting (closes S3), and `pii_mode`/`pci_mode` are actually consumed (closes S2/S5). `default_deny` plus key- and value-based detection (Luhn PAN, JWT, PEM, email/phone) is a sound layered model.
- **TLS is rejected at init**, not silently accepted (`src/syslog.zig:127-131`, test at 414-443) — closes S6; no false assurance of encryption.
- **PRNG seed comes from secure OS entropy** (`src/time.zig:142-151`) with a documented fallback — closes S7.
- **File permissions are restrictive** (`0o640`, `src/file_sink.zig:284-286`) and the sink uses `truncate = false` to avoid clobbering existing logs.
- **Concurrency primitives are disciplined:** `BoundedChannel` (`src/channel.zig`) is a clean mutex+condvar MPSC with explicit close-and-drain; `deinit` paths join the worker, drain, and free leftovers; `ring_buffer.zig` is clearly documented as **not** thread-safe and is not used for cross-thread queuing. The hand-rolled `Condition` (`src/sync.zig`) carefully handles spurious wakeups and signal accounting.
- **JSON memory management is centralized** (`src/json_util.zig`) with matched deep-clone/free, and `events.zig` uses thorough `errdefer` chains in `clone()`. No double-free or leak found in the `audit()` truncation/redaction path on manual trace.
- **Scripts and CI are supply-chain conscious:** all `subprocess.run(...)` calls in `scripts/*.py` are list-form (no `shell=True`, no string interpolation into a shell), the `.sh` wrapper is `set -euo pipefail`, the diamond detector exists at all, CI pins `ci-catalog` components to tags and SHA-256-verifies the Zig toolchain against the signed `index.json`, pre-commit runs shellcheck/ruff/gitleaks/detect-private-key. No `curl | sh`-into-shell, no secrets in tree (the two gitleaks hits are confirmed test fixtures).

---

## 6. Coverage Gaps & Questions

- **DNS resolver internals (`devnw/zig/dns`) were out of scope.** `resolveHostToAddress`/`resolveOrCached` (`src/syslog.zig:47-67,235-247`) trust the first A record; the DNS-spoofing risk (prior S11) is documented in README but the resolver's own parsing robustness was not reviewed here. Recommend a focused review of the `dns` dependency, especially response parsing.
- **OTel-enabled build (`-Dwith_otel=true`) was not exercised.** The disabled seam (`src/observability.zig`, `root.zig:64-67`) and build wiring were reviewed; the enabled path pulls `otel` and `observability_init.zig`. The README/comments assert a PII invariant (only `category.action` enters span attributes, `src/logger.zig:80-97`) which the code honors, but the enabled OTel exporter's own network/transport security was not assessed.
- **Shutdown-race behavior was inspected by reading, not stress-tested.** `BoundedChannel.close()` + worker `join()` looks correct, but no concurrent-shutdown fuzz/stress was run to confirm no record is lost or double-freed when `deinit()` races in-flight `audit()` calls. The integration tests cover single-threaded flows only. Recommend a TSan/stress test of concurrent `audit()` + `deinit()`.
- **`max_bytes` / rotation under concurrent producers:** rotation runs on the single worker thread (safe by design), but `checkRotation` uses `current_size` accounting that was not exhaustively validated against partial writes / write errors mid-rotation.
- **Is the host expected to call `validate()`?** `audit()` calls it (`src/logger.zig:108`), but `formatCef`/`formatRfc5424` are public and can be called directly with unvalidated events — confirm whether direct formatter use is a supported entrypoint (affects A8's blast radius).

---

## 7. Prioritized Next Actions

1. **A1 — Fix integer coercion in `config.zig`** (replace all `@intCast` on JSON integers with `std.math.cast … orelse error.InvalidConfig`, bound `port`/`pid`/`max_bytes`/`backup_count`/`version`). Highest priority: it is reproduced, affects shipped ReleaseSafe (DoS) and ReleaseFast (silent wrong-destination), and falsifies the SECURITY.md no-UB claim. ~2–4 h + tests.
2. **A4 — Complete the path-traversal control in `FileSink`** (canonicalize, enforce an allowed base, reject absolute/symlink escapes, stop swallowing `createDirPath` errors). ~1 day.
3. **A2 — Add a file-sink drop counter and surface it** (mirror GAP-023; expose `getDroppedCount`, signal `span_durable=false` on drop, rate-limit the warning). ~0.5–1 day.
4. **A3 + A8 — Neutralize control characters at the sink and reject them at validation** (escape bytes `<0x20` and `0x7F` in `escapeCefString`; extend `validate()` accordingly; add UTF-8 validation). ~0.5 day.
5. **A6 — Re-pin `dns` so ref label and resolved version agree**, and extend the diamond detector to flag ref/version-label drift. ~1–2 h (plus cross-repo coordination).
6. **A5 / A7 — Harden `formatRfc3339` against negative input** and render the event's own `ts_unix_ms` as the authoritative timestamp. ~0.5 day.
7. **Follow-ups:** stress/TSan test concurrent `audit()`+`deinit()`; commission a focused review of the `dns` dependency and the `-Dwith_otel=true` exporter path.

*No emergency secret rotation is required — no live secrets were found. None of these findings is a remotely-exploitable Critical, but A1, A2, and A4 should be closed before the next release given this library's audit-integrity mission.*
