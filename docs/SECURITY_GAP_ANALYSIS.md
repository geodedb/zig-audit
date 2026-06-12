# Security Gap Analysis

Last updated: 2026-06-11

Repository: `gitlab.com/devnw/zig/audit`
Reviewer: benjiv
Methodology: Adversarial manual code review with automated scanner cross-reference
Scope: All source files in `src/` and `build.zig.zon`

## Summary

| Severity | Open | Resolved | Total |
|----------|------|----------|-------|
| Critical | 0 | 1 (S1) | 1 |
| High | 0 | 5 (S2, S3, S4, S5, S6) | 5 |
| Medium | 2 (S9, S12*) | 3 (S7, S8, S10) | 4+1* |
| Low | 3 (SC-1, S11, S13) | 0 | 4 |
| **Total** | **5** | **9** | **14** |

*Note: S12 (`i128`-to-`i64` cast) is moot after GAP-026/GAP-027 removed the dead code containing the cast.*

*2026-06-11 update: S9 and SC-1 are superseded by GAP-043 ([#62](https://gitlab.com/devnw/zig/audit/-/issues/62)) and GAP-045 ([#64](https://gitlab.com/devnw/zig/audit/-/issues/64)) respectively (still open; tracking continues under the new Gap-IDs). S11 and S13 remain open. Eight new appsec findings (A1-A8) and additional NEW-SEC items were filed -- see the "2026-06-11 Appsec Review" section below.*

**All Critical and High severity findings from the original (2026-03-22) review are resolved.** The 2026-06-11 review filed one High security item (GAP-050, PiiMode.hash) and three Critical correctness/memory-safety items in the deep quality review (QR-001..003).

**Remaining open findings** (Medium/Low, none blocking 0.1.0 release):

1. **S9** (Medium) -- File path from config not sanitized (CWE-22). **Superseded by GAP-043** ([#62](https://gitlab.com/devnw/zig/audit/-/issues/62), open): the `".."` substring mitigation is incomplete (absolute/symlink bypass).
2. **SC-1** (Low) -- DNS dependency pin auditability. **Superseded by GAP-045** ([#64](https://gitlab.com/devnw/zig/audit/-/issues/64), open): ref/version-hash drift (`?ref=v0.1.9` vs `dns-0.1.8` hash). See also GAP-029 ([#24](https://gitlab.com/devnw/zig/audit/-/issues/24)).
3. **S11** (Low) -- DNS queries unauthenticated (documentation-only fix). **Remains open.**
4. **S13** (Low) -- `@panic` in MockSyslogSender init. **Remains open (test code only).**

**No real secrets were found.** Two gitleaks findings on test fixtures (`TEST_TRACE_ID`, `TEST_SPAN_ID`) are confirmed false positives.

### 2026-06-11 Appsec Review -- New Findings (A1-A8 -> GAP-040..047)

The 2026-06-11 appsec review (`docs/APPSEC_REVIEW_2026-06-11.md`, OWASP Top 10:2025 / CIS v8.1.2) reconfirmed all prior Critical/High items (S1-S8, S10) as genuinely fixed and surfaced eight new/residual findings, now tracked as the GAP-040..047 master series:

| Appsec ID | Title | Severity | Gap-ID | Issue |
|-----------|-------|----------|--------|-------|
| A1 | Unvalidated integer coercion in config parsing (DoS panic / silent truncation) | Medium | GAP-040 | [#57](https://gitlab.com/devnw/zig/audit/-/issues/57) |
| A2 | File-sink audit records dropped silently under backpressure (no counter) | Medium | GAP-041 | [#58](https://gitlab.com/devnw/zig/audit/-/issues/58) |
| A3 | Control characters (NUL/TAB/BEL/DEL/C0) not escaped in CEF/syslog output | Low-Medium | GAP-042 | [#60](https://gitlab.com/devnw/zig/audit/-/issues/60) |
| A4 | Path-traversal mitigation incomplete: absolute paths & symlinks bypass `".."` check (residual S9) | Medium | GAP-043 | [#62](https://gitlab.com/devnw/zig/audit/-/issues/62) |
| A5 | `formatRfc3339` panics on negative timestamp (public API) | Low | GAP-044 | [#63](https://gitlab.com/devnw/zig/audit/-/issues/63) |
| A6 | Dependency ref/version-hash mismatch in `build.zig.zon` (dns, otel) | Low | GAP-045 | [#64](https://gitlab.com/devnw/zig/audit/-/issues/64) |
| A7 | Event `ts_unix_ms` never rendered; output timestamp is worker-thread "now" | Low (Info) | GAP-046 | [#66](https://gitlab.com/devnw/zig/audit/-/issues/66) |
| A8 | `AuditEvent.validate()` does not reject control characters in core fields | Low | GAP-047 | [#67](https://gitlab.com/devnw/zig/audit/-/issues/67) |

Additional 2026-06-11 security/supply-chain findings (`NEW-SEC-*`) are tracked as GAP-050 (PiiMode.hash, High, [#72](https://gitlab.com/devnw/zig/audit/-/issues/72)), GAP-063..069 ([#92](https://gitlab.com/devnw/zig/audit/-/issues/92)-[#98](https://gitlab.com/devnw/zig/audit/-/issues/98)), and the deep-quality-review Criticals QR-001..003 (use-after-return, double-free, literal-free; [#105](https://gitlab.com/devnw/zig/audit/-/issues/105)-[#107](https://gitlab.com/devnw/zig/audit/-/issues/107)). See `docs/GAP_ANALYSIS.md` for the full series.

---

## Scoring Methodology

```
Risk Score = Impact (1-5) x Likelihood (1-5) x 4
```

- **Impact**: 5 = RCE/priv-esc/cross-tenant, 4 = PII/credential leak, 3 = data tampering, 2 = info leak, 1 = hardening
- **Likelihood**: 5 = pre-auth/trivial, 4 = remote/constrained, 3 = requires auth, 2 = rare conditions, 1 = theoretical
- **Confidence**: `confirmed` = verified via code evidence; `suspected` = pattern-matched, needs validation

**SLA targets**: Critical 7d, High 30d, Medium 90d, Low 180d

---

## Stack-Ranked Findings

| Rank | ID | Severity | Risk | Finding | Component | CWE / OWASP | Evidence | Fix | Status |
|------|----|----------|------|---------|-----------|-------------|----------|-----|--------|
| 1 | S1 | Critical | 36 | CEF escape no-ops -- log injection | `src/cef.zig` | CWE-117 / A03:2021 | `cef.zig:152-162` | Implement escaping in `escapeHeader`, `escapeValue`, `escapeKey` | **Resolved** (GAP-006) |
| 2 | S2 | High | 32 | `pii_mode`/`pci_mode` parsed, never consumed | `src/config.zig`, `src/filters.zig` | CWE-311 / PCI DSS 3.4 | `config.zig:122-123` | Wire modes into `filterAndRedactMetadata` | **Resolved** (GAP-007) |
| 3 | S3 | High | 32 | Redaction skips nested objects/arrays | `src/filters.zig` | CWE-312 / A04:2021 | `filters.zig:250-282` | Recurse `filterAndRedactMetadata` into nested values | **Resolved** (GAP-008) |
| 4 | S4 | High | 28 | Plaintext syslog UDP/TCP | `src/syslog.zig` | CWE-319 / A02:2021 | `syslog.zig:203-223` | Warn callers at init; document stunnel requirement | **Resolved** (GAP-011) |
| 5 | S5 | High | 28 | Redaction bypass via unrecognized keys | `src/filters.zig` | CWE-184, CWE-312 / A04:2021 | `filters.zig:41-87` | Support regex/glob deny patterns; default-deny unrecognized keys | **Resolved** (GAP-010) |
| 6 | S6 | High | 28 | TLS not implemented, config silently accepted | `src/syslog.zig` | CWE-295, CWE-319 / A02:2021 | `syslog.zig:225-236` | Fail loudly at init when `protocol = .tls` | **Resolved** |
| 7 | S10 | Medium | 24 | Silent ring buffer overflow drops audit events | `src/syslog.zig` | CWE-770, CWE-779 / A09:2021 | `syslog.zig:128-133` | Emit metric/log on drop; expose overflow count | **Resolved** (GAP-023) |
| 8 | S7 | Medium | 20 | PRNG seeded from `microTimestamp` | `src/time.zig` | CWE-330, CWE-338 / A02:2021 | `time.zig:138` | Seed from `std.crypto.random` or OS entropy | **Resolved** (GAP-016) |
| 9 | S8 | Medium | 20 | No `AuditEvent` field validation | `src/events.zig` | CWE-20 / A03:2021 | `events.zig:47-60` | Add `validate()` method with length and format checks | **Resolved** (GAP-017) |
| 10 | S9 | Medium | 20 | File path from config not sanitized | `src/file_sink.zig` | CWE-22 / A01:2021 | `file_sink.zig:249-254` | Reject path traversal sequences; restrict to allowed directories | Superseded by GAP-043 (#62, open) |
| 11 | SC-1 | Low | 12 | DNS dependency pinned to commit, not tag | `build.zig.zon` | CWE-829 / A06:2021 | `build.zig.zon:8-9` | Pin to a tagged release | Superseded by GAP-045 (#64, open); see also GAP-029 (#24) |
| 12 | S11 | Low | 12 | DNS queries unauthenticated | `src/syslog.zig` | CWE-350 / A07:2021 | `syslog.zig:21-41` | Document DNS spoofing risk; recommend /etc/hosts or DoH | Open |
| 13 | S12 | Low | 8 | `i128`-to-`i64` cast truncation | `src/syslog.zig` | CWE-681 / A04:2021 | `syslog.zig:249` | Use `std.math.cast` with overflow check | **Moot** (dead code removed via GAP-026/027) |
| 14 | S13 | Low | 4 | `@panic` in `MockSyslogSender` init | `src/syslog.zig` | CWE-248 / A11:2021 | `syslog.zig:282` | Return error instead of panicking | Open |

---

## Detailed Findings

### S1: CEF Escape Functions Are No-Ops -- Log Injection

**Severity:** Critical | **Risk Score:** 36 (Impact 3 x Likelihood 3 x 4) | **SLA:** 7 days
**Confidence:** `confirmed`
**CWE:** CWE-117 (Improper Output Neutralization for Logs)
**OWASP:** A03:2021 Injection
**Exploit surface:** Internet-facing (any user-controlled field flows into CEF output)

**Summary:** The three CEF escape functions (`escapeHeader`, `escapeValue`, `escapeKey`) return their input unmodified. Any pipe `|`, equals `=`, backslash `\`, or newline character in user-controlled fields (actor_id, source_ip, metadata keys/values) passes through verbatim into CEF-formatted syslog messages.

**Evidence:**

`src/cef.zig:152-162`:

```zig
fn escapeHeader(s: []const u8) []const u8 {
    return s;
}

fn escapeValue(s: []const u8) []const u8 {
    return s;
}

fn escapeKey(s: []const u8) []const u8 {
    return s;
}
```

These no-op functions are called throughout `formatCef` (lines 31-67, 75-80, 117-140) on user-controlled data including `event.action`, `event.actor_id`, `event.source_ip`, `event.session_id`, `event.request_id`, and all metadata keys and string values.

A working `escapeCefString` implementation exists at line 164-180 but is never called by the formatting functions.

**Attack scenario:** An attacker sets `actor_id` to `"jane|Evil|Product|1.0|sig|name|10|rce=true"`. The unescaped value injects additional CEF header fields into the syslog message. A downstream SIEM parses the injected fields, potentially triggering false alerts, masking real events, or exploiting SIEM-side processing vulnerabilities.

**Impact:** Log forgery, audit trail corruption, potential SIEM exploitation. Compliance frameworks (SOC2, PCI DSS 10.2) require tamper-resistant audit logs.

**Fix guidance:**

1. Replace the three no-op functions with calls to `escapeCefString` (which already exists at line 164).
2. `escapeHeader` must escape `|`, `\`, and replace newlines.
3. `escapeValue` must escape `=`, `\`, and encode `\n`/`\r`.
4. `escapeKey` must escape `=` and spaces.
5. Note: `escapeCefString` currently allocates. The internal callers pass `[]const u8` slices via `{s}` format, so the functions need to either allocate-and-defer or write escaped output directly to the extension writer.

**Acceptance criteria:**

- [ ] `escapeHeader`, `escapeValue`, and `escapeKey` produce correctly escaped output per ArcSight CEF specification.
- [ ] Unit test: input containing `|`, `=`, `\`, `\n`, `\r` produces escaped output.
- [ ] Integration test: full CEF line with adversarial input is parseable by a reference CEF parser.

**How to verify:** Construct an `AuditEvent` with `actor_id = "a]|b|c|d|e|f|10|injected=true"` and verify the CEF output contains no unescaped pipe characters in extension fields.

---

### S2: `pii_mode` and `pci_mode` Config Flags Parsed But Never Consumed

**Severity:** High | **Risk Score:** 32 (Impact 4 x Likelihood 2 x 4) | **SLA:** 30 days
**Confidence:** `confirmed`
**CWE:** CWE-311 (Missing Encryption of Sensitive Data)
**OWASP:** PCI DSS Requirement 3.4 (Render PAN unreadable)
**Exploit surface:** All audit event paths

**Summary:** The `FiltersConfig` struct accepts `pii_mode` (enum: off/mask/hash) and `pci_mode` (bool) from configuration JSON. These values are parsed and stored but never referenced by any filtering or redaction logic. A deployment configured with `"pii_mode": "hash"` and `"pci_mode": true` gets zero additional protection -- the flags are silently ignored.

**Evidence:**

`src/config.zig:118-124` -- Fields defined:

```zig
pub const FiltersConfig = struct {
    default_deny: bool,
    allow_fields: [][]const u8,
    deny_key_patterns: [][]const u8,
    pii_mode: PiiMode,
    pci_mode: bool,
};
```

`src/filters.zig:245-283` -- `filterAndRedactMetadata` receives a `*const config.FiltersConfig` but never reads `filters.pii_mode` or `filters.pci_mode`. Grep of the entire `src/` directory confirms zero references to these fields outside of config parsing and test setup.

**Attack scenario:** An operator enables `pci_mode: true` expecting PAN masking per PCI DSS 3.4. The library silently logs full card numbers in plaintext to file and syslog sinks. A PCI QSA audit discovers unmasked PANs in log files.

**Impact:** PCI DSS non-compliance, potential PII/PAN exposure in log storage, false sense of compliance.

**Fix guidance:**

1. In `filterAndRedactMetadata`, check `filters.pci_mode`. When true, scan all string values for PAN patterns (Luhn-valid 13-19 digit sequences) and replace with masked form (`****1234`).
2. In `filterAndRedactMetadata`, check `filters.pii_mode`. When `.mask`, apply `maskEmail`/`maskPhone` (both already implemented in `filters.zig:191-214`). When `.hash`, apply a one-way hash. When `.off`, skip.
3. Value-based detection functions (`isPan`, `isEmail`, `isPhone`) already exist in `filters.zig` -- wire them into the filter pipeline.

**Acceptance criteria:**

- [ ] `pci_mode: true` causes all Luhn-valid PAN values to be masked before reaching any sink.
- [ ] `pii_mode: mask` causes email and phone values to be masked using existing `maskEmail`/`maskPhone`.
- [ ] `pii_mode: hash` causes PII values to be replaced with a one-way hash.
- [ ] Unit tests confirm each mode independently.

**How to verify:** Set `pci_mode: true`, log an event with metadata `{"card_number": "4111111111111111"}`, and verify the file sink output contains `[REDACTED_PAN]` or a masked form, not the raw PAN.

---

### S3: Redaction Skips Nested Objects and Arrays

**Severity:** High | **Risk Score:** 32 (Impact 4 x Likelihood 2 x 4) | **SLA:** 30 days
**Confidence:** `confirmed`
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
**OWASP:** A04:2021 Insecure Design
**Exploit surface:** Any event with nested metadata

**Summary:** `filterAndRedactMetadata` only inspects top-level keys of the metadata object. If a sensitive value is nested inside a child object or array, it passes through unredacted. The `else => metadata` fallback on line 281 returns non-object metadata (including arrays) without any inspection.

**Evidence:**

`src/filters.zig:245-283`:

```zig
pub fn filterAndRedactMetadata(
    allocator: std.mem.Allocator,
    metadata: std.json.Value,
    filters: *const config.FiltersConfig,
) !?std.json.Value {
    return switch (metadata) {
        .object => |obj| blk: {
            // ... iterates top-level keys only ...
        },
        else => metadata,  // <-- arrays and non-objects pass through unfiltered
    };
}
```

The `shouldFilterField` function at line 285 only checks the key name and string value at the current level. When `value` is `.object` or `.array`, the function reaches line 310 (`if (value == .string)`) which is false, and falls through to `return .allow` at line 317 -- the entire nested subtree is allowed without inspection.

**Attack scenario:** An application logs `metadata: {"user": {"password": "secret123", "ssn": "123-45-6789"}}`. The top-level key `"user"` does not match any sensitive key pattern. The nested `"password"` and `"ssn"` keys are never checked. Both values appear in plaintext in the file sink and syslog output.

**Impact:** Sensitive data (passwords, PII, credentials) embedded in nested metadata structures bypasses all redaction controls.

**Fix guidance:**

1. Make `filterAndRedactMetadata` recursive: when a value is `.object`, recurse into it. When a value is `.array`, iterate elements and recurse into any objects.
2. Apply `shouldFilterField` to every key at every nesting level.
3. Apply value-based detection (`detectValueType`) to string values at every nesting level.

**Acceptance criteria:**

- [ ] Nested object keys matching sensitive patterns are redacted.
- [ ] String values inside arrays are scanned by `detectValueType`.
- [ ] Recursive depth is bounded to prevent stack overflow on adversarial input.
- [ ] Unit test: `{"outer": {"password": "secret"}}` produces `{"outer": {"password": "[REDACTED]"}}`.

**How to verify:** Log an event with metadata `{"profile": {"email": "user@example.com", "ssn": "123-45-6789"}}` and verify both nested values are redacted in all sink outputs.

---

### S4: Plaintext Syslog Over UDP/TCP

**Severity:** High | **Risk Score:** 28 (Impact 4 x Likelihood 2 x 4 = 32, adjusted to 28 per provided scoring) | **SLA:** 30 days
**Confidence:** `confirmed`
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
**OWASP:** A02:2021 Cryptographic Failures
**Exploit surface:** Network (internal or internet-facing depending on deployment)

**Summary:** The `sendUdp` and `sendTcp` functions transmit audit events -- which may contain actor IDs, source IPs, session IDs, and metadata -- over unencrypted connections. There is no warning to the caller at initialization time, and no way to enforce encryption.

**Evidence:**

`src/syslog.zig:203-223`:

```zig
fn sendUdp(self: *SyslogSender, message: []const u8) !void {
    const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(socket);
    const addr = try resolveHostToAddress(self.allocator, self.config.host, self.config.port);
    _ = try std.posix.sendto(socket, message, 0, &addr.any, addr.getOsSockLen());
}

fn sendTcp(self: *SyslogSender, message: []const u8) !void {
    const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(socket);
    const addr = try resolveHostToAddress(self.allocator, self.config.host, self.config.port);
    try std.posix.connect(socket, &addr.any, addr.getOsSockLen());
    // ... sends in plaintext ...
}
```

**Attack scenario:** An attacker with network access between the audit library and the syslog server captures UDP/TCP packets. Audit events containing user IDs, IP addresses, session tokens, and any metadata that survived (incomplete) redaction are exposed.

**Impact:** Cleartext exposure of audit trail data on the network. Compliance risk for frameworks requiring encryption in transit (SOC2 CC6.7, PCI DSS 4.1).

**Fix guidance:**

1. At `SyslogSender.init`, log a prominent warning when `protocol` is `.udp` or `.tcp` stating that transport is unencrypted.
2. Document in the library README that TLS is not yet available and stunnel or an encrypted tunnel is required for production use.
3. Consider adding a `require_encryption: bool` config flag that refuses to start when true and protocol is not TLS.

**Acceptance criteria:**

- [ ] `SyslogSender.init` emits a `std.log.warn` when protocol is UDP or TCP.
- [ ] README documents the plaintext transport limitation and stunnel recommendation.
- [ ] Optional `require_encryption` flag causes init to return an error for non-TLS protocols.

**How to verify:** Initialize a `SyslogSender` with `protocol = .tcp` and verify the warning is emitted in log output.

---

### S5: Redaction Bypass Via Unrecognized Key Names

**Severity:** High | **Risk Score:** 28 (Impact 4 x Likelihood 2 x 4 = 32, adjusted to 28 per provided scoring) | **SLA:** 30 days
**Confidence:** `confirmed`
**CWE:** CWE-184 (Incomplete List of Disallowed Inputs), CWE-312 (Cleartext Storage of Sensitive Information)
**OWASP:** A04:2021 Insecure Design
**Exploit surface:** Any event metadata path

**Summary:** `isSensitiveKey` uses a hardcoded list of substring matches (password, token, jwt, card, cvv, ssn, etc.). Any key name not containing one of these substrings passes through unredacted, even if it contains sensitive data. The `deny_key_patterns` config only supports exact substring matching, not regex or glob patterns.

**Evidence:**

`src/filters.zig:41-87`:

```zig
pub fn isSensitiveKey(allocator: std.mem.Allocator, key: []const u8) ?RedactionToken {
    const lower_key = std.ascii.allocLowerString(allocator, key) catch return null;
    defer allocator.free(lower_key);

    if (std.mem.indexOf(u8, lower_key, "password") != null or
        std.mem.indexOf(u8, lower_key, "passwd") != null) return .password;

    // ... 11 more substring checks ...

    return null;  // <-- unrecognized keys pass through
}
```

Keys like `"secret_value"`, `"auth_code"`, `"refresh_tok"`, `"bearer"`, `"credential"`, `"access_key"`, `"signing_key"`, or `"pin"` do not match any pattern and pass through unredacted.

**Attack scenario:** An application logs `metadata: {"auth_code": "abc123", "mfa_backup_codes": "[\"12345678\"]"}`. Neither key matches the hardcoded list. Both values appear in plaintext in all sinks.

**Impact:** Sensitive data under non-standard key names bypasses redaction. The incomplete deny list creates a false sense of security.

**Fix guidance:**

1. Expand the hardcoded list to include common variations: `secret`, `credential`, `bearer`, `auth_code`, `refresh`, `access_key`, `signing`, `pin`, `otp`, `mfa`, `backup_code`.
2. Support regex or glob patterns in `deny_key_patterns` config to allow deployers to extend the list.
3. When `default_deny` is true (which it is in the test config), unrecognized keys should already be redacted -- verify this path works correctly for all value types, not just strings.
4. Consider a `default_deny` + allowlist approach as the primary strategy, with the sensitive-key detection as a defense-in-depth layer.

**Acceptance criteria:**

- [ ] Expanded sensitive key list covers at least: `secret`, `credential`, `bearer`, `auth_code`, `access_key`, `signing`, `pin`, `otp`, `mfa`, `backup`.
- [ ] `deny_key_patterns` supports glob matching (e.g., `"*secret*"`, `"*key*"`).
- [ ] Unit tests confirm new patterns are detected and redacted.

**How to verify:** Log an event with `metadata: {"auth_code": "secret123"}` and verify the value is redacted.

---

### S6: TLS Not Implemented, Config Silently Accepted

**Severity:** High | **Risk Score:** 28 (Impact 4 x Likelihood 2 x 4 = 32, adjusted to 28 per provided scoring) | **SLA:** 30 days
**Confidence:** `confirmed`
**CWE:** CWE-295 (Improper Certificate Validation), CWE-319 (Cleartext Transmission of Sensitive Information)
**OWASP:** A02:2021 Cryptographic Failures
**Exploit surface:** Configuration-driven; affects any deployment requesting TLS

**Summary:** The `SyslogTlsConfig` struct defines fields for certificate pinning, CA bundle, hostname verification, and connection pooling. These are parsed and stored. But `sendTls` immediately returns `error.TlsNotImplemented` after logging a warning. Critically, the TLS configuration is accepted without error at init time -- the failure only surfaces when the first message is sent, and only as a warning log.

**Evidence:**

`src/syslog.zig:225-236`:

```zig
fn sendTls(self: *SyslogSender, message: []const u8) !void {
    _ = self;
    _ = message;
    log.warn("TLS syslog transport not yet implemented; use stunnel or TCP", .{});
    return error.TlsNotImplemented;
}
```

`src/config.zig:96-102` -- TLS config struct with fields that create the appearance of TLS support:

```zig
pub const SyslogTlsConfig = struct {
    pinned_cert_hash: ?[]const u8 = null,
    ca_bundle_path: ?[]const u8 = null,
    verify_hostname: bool = true,
    pool_size: u8 = 4,
    idle_timeout_ms: u32 = 30000,
};
```

`src/syslog.zig:59` -- `tls_pool` struct field allocated but never used:

```zig
tls_pool: [MAX_POOL_SIZE]?PooledConnection,
```

**Attack scenario:** An operator configures `"protocol": "tls"` with `"pinned_cert_hash": "abc..."` believing the connection is encrypted and certificate-pinned. The library starts successfully. Every audit event silently fails to send (the error is caught and logged as a warning by `processQueue`). The audit trail is silently lost.

**Impact:** False assurance of encrypted transport. Silent data loss of all audit events when TLS protocol is selected.

**Fix guidance:**

1. At `SyslogSender.init`, check if `protocol == .tls` and return `error.TlsNotImplemented` immediately, preventing silent startup.
2. Remove or clearly mark the `SyslogTlsConfig` fields as unimplemented to avoid misleading operators.
3. Remove the dead `tls_pool` field and `verifyCertificatePin` function to reduce attack surface.

**Acceptance criteria:**

- [ ] `SyslogSender.init` returns an error when `protocol = .tls`.
- [ ] Documentation explicitly states TLS is not yet supported.
- [ ] Dead TLS-related code is removed or gated behind a compile-time feature flag.

**How to verify:** Attempt to create a `SyslogSender` with `protocol = .tls` and verify it returns an error at initialization, not at first message send.

---

### S10: Silent Ring Buffer Overflow Drops Audit Events

**Severity:** Medium | **Risk Score:** 24 (Impact 3 x Likelihood 2 x 4) | **SLA:** 90 days
**Confidence:** `confirmed`
**CWE:** CWE-770 (Allocation of Resources Without Limits), CWE-779 (Logging of Excessive Data)
**OWASP:** A09:2021 Security Logging and Monitoring Failures
**Exploit surface:** Internal (triggered by burst traffic or slow syslog server)

**Summary:** When the ring buffer is full, `SyslogSender.send` silently drops the oldest message and overwrites it with the new one. There is no counter, no log message, no metric, and no callback to inform the application that audit events are being lost.

**Evidence:**

`src/syslog.zig:128-133`:

```zig
if (!self.queue.push(syslog_line)) {
    if (self.queue.pop()) |old_msg| {
        self.allocator.free(old_msg);
    }
    _ = self.queue.push(syslog_line);
}
```

**Attack scenario:** An attacker floods an application with requests, generating audit events faster than the syslog sender can drain. The ring buffer (10,000 entries) fills up. Subsequent events silently overwrite older ones. The attacker's initial reconnaissance events are dropped from the audit trail, leaving only later events that appear benign.

**Impact:** Audit trail gaps during high-traffic periods. Attackers can deliberately cause event loss to cover their tracks.

**Fix guidance:**

1. Add an atomic counter for dropped messages.
2. Log a warning on first drop and periodically (e.g., every 1000 drops).
3. Expose `dropped_count` via a public method so applications can monitor it.
4. Consider a configurable backpressure policy (block, drop-newest, drop-oldest).

**Acceptance criteria:**

- [ ] Dropped message counter is incremented on every overflow.
- [ ] A warning is logged on the first drop and periodically thereafter.
- [ ] `SyslogSender` exposes a method to query the drop count.

**How to verify:** Fill the ring buffer beyond capacity and verify the drop counter is nonzero and a warning was logged.

---

### S7: PRNG Seeded From `microTimestamp` -- Predictable Trace/Span IDs

**Severity:** Medium | **Risk Score:** 20 (Impact 2 x Likelihood 2 x 4 = 16, adjusted to 20 per provided scoring) | **SLA:** 90 days
**Confidence:** `confirmed`
**CWE:** CWE-330 (Use of Insufficiently Random Values), CWE-338 (Use of Cryptographically Weak PRNG)
**OWASP:** A02:2021 Cryptographic Failures
**Exploit surface:** Internal (requires knowledge of approximate startup time)

**Summary:** `SystemIdGen.init()` seeds `std.Random.DefaultPrng` (xoshiro256) with `std.time.microTimestamp()`, a predictable value based on system time. An attacker who knows the approximate startup time of the application can enumerate possible seeds and predict all future trace IDs, span IDs, and request IDs.

**Evidence:**

`src/time.zig:136-139`:

```zig
pub fn init() SystemIdGen {
    return SystemIdGen{
        .rng = std.Random.DefaultPrng.init(@intCast(std.time.microTimestamp())),
    };
}
```

**Attack scenario:** An attacker observes the approximate startup time (within a few seconds) of a service using this library. They enumerate the ~1,000,000 possible microsecond seeds for that window and compute the PRNG output sequence. They can now predict or forge trace/span IDs, potentially correlating or spoofing distributed traces.

**Impact:** Predictable trace/span/request IDs. While these are not security tokens, predictability undermines trace integrity and could enable trace injection in distributed tracing systems.

**Fix guidance:**

1. Replace `std.time.microTimestamp()` with `std.crypto.random.int(u64)` or `std.posix.getrandom()` for the PRNG seed.
2. Alternatively, use `std.crypto.random` directly for ID generation instead of a seeded PRNG.

**Acceptance criteria:**

- [ ] `SystemIdGen.init()` seeds from OS entropy, not from a timestamp.
- [ ] Unit test: two `SystemIdGen` instances created in the same microsecond produce different sequences.

**How to verify:** Create two `SystemIdGen` instances in rapid succession and verify their first trace IDs differ.

---

### S8: No AuditEvent Field Validation

**Severity:** Medium | **Risk Score:** 20 (Impact 2 x Likelihood 2 x 4 = 16, adjusted to 20 per provided scoring) | **SLA:** 90 days
**Confidence:** `confirmed`
**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A03:2021 Injection
**Exploit surface:** Any caller of `AuditLogger.audit()`

**Summary:** `AuditEvent` is a plain struct with no validation. Any caller can construct an event with empty `category`, empty `actor_id`, arbitrarily long strings, or malformed `source_ip` values. These invalid events flow through formatting and sink output without any checks.

**Evidence:**

`src/events.zig:47-60`:

```zig
pub const AuditEvent = struct {
    category: []const u8,
    action: []const u8,
    outcome: Outcome,
    ts_unix_ms: i128,
    severity: Severity,
    actor_id: []const u8,
    subject_id: ?[]const u8,
    request_id: ?[]const u8,
    session_id: ?[]const u8,
    source_ip: ?[]const u8,
    trace_id: ?[32]u8,
    span_id: ?[16]u8,
    metadata: ?std.json.Value,
    // ... no validate() method exists ...
};
```

**Attack scenario:** A caller logs an event with `actor_id` set to a 10MB string. This passes through CEF formatting and syslog, potentially causing OOM, oversized UDP packets (>65535 bytes), or log file bloat.

**Impact:** DoS via resource exhaustion, malformed log entries, potential buffer issues in downstream SIEM systems.

**Fix guidance:**

1. Add a `validate() !void` method to `AuditEvent` that enforces:
   - `category` and `action` are non-empty and under 256 bytes.
   - `actor_id` is non-empty and under 256 bytes.
   - `source_ip`, if present, is a valid IPv4 or IPv6 address.
   - String fields contain no control characters (except in metadata values).
   - Total serialized size is bounded.
2. Call `validate()` at the top of `AuditLogger.audit()`.

**Acceptance criteria:**

- [ ] `AuditEvent` has a `validate()` method that checks all field constraints.
- [ ] `AuditLogger.audit()` calls `validate()` before processing.
- [ ] Unit tests confirm invalid events are rejected with descriptive errors.

**How to verify:** Construct an event with empty `category` and verify `validate()` returns an error.

---

### S9: File Path From Config Not Sanitized

> **Status update (2026-06-11):** Superseded by **GAP-043** ([#62](https://gitlab.com/devnw/zig/audit/-/issues/62), open). A partial mitigation (a `".."` substring check in `FileSink.openCurrentFile`) was added, but the 2026-06-11 appsec review found it incomplete: absolute paths (e.g. `/etc/cron.d/evil`) and symlinked directory components still escape any intended base, and rotation paths inherit the same unvalidated base. Tracking continues under GAP-043.

**Severity:** Medium | **Risk Score:** 20 (Impact 2 x Likelihood 2 x 4 = 16, adjusted to 20 per provided scoring) | **SLA:** 90 days
**Confidence:** `confirmed`
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
**OWASP:** A01:2021 Broken Access Control
**Exploit surface:** Configuration-controlled (admin/operator level)

**Summary:** `FileSink.openCurrentFile` uses the config path directly with `std.fs.cwd().createFile()` and `std.fs.cwd().makePath()`. A path containing `..` sequences (e.g., `"../../etc/cron.d/evil"`) would create files outside the intended directory. While this requires control over the config file, a config injection or TOCTOU attack could exploit this.

**Evidence:**

`src/file_sink.zig:249-254`:

```zig
fn openCurrentFile(self: *FileSink) !void {
    if (std.fs.path.dirname(self.config.path)) |dir_path| {
        std.fs.cwd().makePath(dir_path) catch {};
    }
    self.current_file = try std.fs.cwd().createFile(self.config.path, .{ .truncate = false });
```

Note that `makePath` errors are silently ignored (`catch {}`), which could mask permission or path issues.

**Impact:** Arbitrary file creation/overwrite within the filesystem permissions of the running process. Potential for privilege escalation if the process runs with elevated permissions.

**Fix guidance:**

1. Resolve the config path to an absolute path and verify it does not escape an allowed base directory.
2. Reject paths containing `..` components.
3. Do not silently ignore `makePath` errors -- propagate them or log a warning.

**Acceptance criteria:**

- [ ] Paths containing `..` are rejected at config load or `FileSink.init` time.
- [ ] `makePath` errors are logged, not silently swallowed.
- [ ] Unit test: config with `"path": "../../tmp/evil.log"` is rejected.

**How to verify:** Attempt to initialize a `FileSink` with a path containing `../` and verify it returns an error.

---

### SC-1: DNS Dependency Pinned to Commit Hash, Not Tagged Release

> **Status update (2026-06-11):** Superseded by **GAP-045** ([#64](https://gitlab.com/devnw/zig/audit/-/issues/64), open). The dependency is now pinned by tag, but the 2026-06-11 appsec review found a ref/version-hash drift: the `dns` URL requests `?ref=v0.1.9` while the recorded content `.hash` self-labels `dns-0.1.8-...` (otel shows the same class of drift). Auditability tracking continues under GAP-045; the original cross-repo tagging item remains GAP-029 ([#24](https://gitlab.com/devnw/zig/audit/-/issues/24)).

**Severity:** Low | **Risk Score:** 12 (Impact 2 x Likelihood 1 x 4 = 8, adjusted to 12 per provided scoring) | **SLA:** 180 days
**Confidence:** `confirmed`
**CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**OWASP:** A06:2021 Vulnerable and Outdated Components
**Exploit surface:** Build-time supply chain

**Summary:** The DNS dependency is pinned to a specific git commit hash rather than a tagged release. This makes it harder to audit which version is in use and to track whether the dependency has known vulnerabilities.

**Evidence:**

`build.zig.zon:7-10`:

```zig
.dns = .{
    .url = "git+https://gitlab.com/devnw/zig/dns.git#976fedf07befad3724fa66092677b9e5242a58fc",
    .hash = "dns-0.1.0-x4U-zalRDABmEIaJxV8eY7UqOlpvJRJIbtIQ-CSgCzVL",
},
```

**Impact:** Reduced supply chain auditability. No clear version identifier for vulnerability tracking.

**Fix guidance:**

1. Tag the DNS library with a semver release (e.g., `v0.1.0`).
2. Update `build.zig.zon` to reference the tag instead of the commit hash.
3. The content hash provides integrity verification, so this is primarily an auditability concern.

**Acceptance criteria:**

- [ ] DNS dependency references a tagged release.
- [ ] Content hash is still present for integrity verification.

---

### S11: DNS Queries Unauthenticated

**Severity:** Low | **Risk Score:** 12 (Impact 2 x Likelihood 2 x 4 = 16, adjusted to 12 per provided scoring) | **SLA:** 180 days
**Confidence:** `confirmed`
**CWE:** CWE-350 (Reliance on Reverse DNS Resolution for a Security-Critical Action)
**OWASP:** A07:2021 Identification and Authentication Failures
**Exploit surface:** Network (requires man-in-the-middle position)

**Summary:** `resolveHostToAddress` uses plain DNS (no DNSSEC, no DoH/DoT) to resolve syslog server hostnames. An attacker in a MitM position can spoof DNS responses and redirect audit events to an attacker-controlled server.

**Evidence:**

`src/syslog.zig:21-41`:

```zig
fn resolveHostToAddress(allocator: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
    if (std.net.Address.parseIp4(host, port)) |addr| {
        return addr;
    } else |_| {
        var client = dns.Client.init(allocator) catch {
            return error.DnsInitFailed;
        };
        defer client.deinit();
        var result = client.resolveA(host) catch {
            return error.DnsResolutionFailed;
        };
        // ... uses first A record ...
    }
}
```

**Impact:** Audit events could be redirected to an attacker-controlled server via DNS spoofing. Limited by the requirement for a network-level MitM position.

**Fix guidance:**

1. Document the DNS spoofing risk in the library README.
2. Recommend using IP addresses directly in production config to bypass DNS.
3. Recommend `/etc/hosts` entries or DNS-over-HTTPS for hostname resolution.

**Acceptance criteria:**

- [ ] Documentation warns about DNS spoofing risk for hostname-based syslog config.
- [ ] README recommends using IP addresses for production syslog endpoints.

---

### S12: `i128`-to-`i64` Cast Truncation

**Severity:** Low | **Risk Score:** 8 (Impact 1 x Likelihood 2 x 4) | **SLA:** 180 days
**Confidence:** `confirmed`
**CWE:** CWE-681 (Incorrect Conversion between Numeric Types)
**OWASP:** A04:2021 Insecure Design
**Exploit surface:** Internal (requires specific timestamp values)

**Summary:** In `releasePooledConnection`, the clock's `nowMs()` returns `i128` but is cast to `i64` via `@intCast`. While current timestamps fit in `i64`, this cast would panic on overflow for sufficiently large `i128` values, which could occur with a misbehaving `Clock` implementation.

**Evidence:**

`src/syslog.zig:249`:

```zig
conn.last_used = @as(i64, @intCast(self.clock.nowMs()));
```

The `Clock.nowMs` returns `i128` (see `time.zig:11`), and `PooledConnection.last_used` is `i64` (see `syslog.zig:45`).

**Impact:** Potential runtime panic if a `Clock` implementation returns values outside `i64` range. Low probability with real system clocks.

**Fix guidance:**

1. Use `std.math.cast(i64, value)` which returns `null` on overflow instead of panicking.
2. Or change `PooledConnection.last_used` to `i128` to match the `Clock` return type.

**Acceptance criteria:**

- [ ] The cast handles overflow gracefully without panicking.

---

### S13: `@panic` in MockSyslogSender Initialization

**Severity:** Low | **Risk Score:** 4 (Impact 1 x Likelihood 1 x 4) | **SLA:** 180 days
**Confidence:** `confirmed`
**CWE:** CWE-248 (Uncaught Exception)
**OWASP:** A11:2021 (custom -- Next in OWASP methodology)
**Exploit surface:** Test code only

**Summary:** `MockSyslogSender.init` calls `@panic("MockSyslogSender init failed")` if `ArrayList.initCapacity` fails. While this is test-only code, `@panic` is unrecoverable and prevents graceful error handling.

**Evidence:**

`src/syslog.zig:282`:

```zig
.captured_messages = std.ArrayList([]const u8).initCapacity(allocator, 16) catch @panic("MockSyslogSender init failed"),
```

**Impact:** Test crash with no recovery path. Minimal production impact since `MockSyslogSender` is test infrastructure.

**Fix guidance:**

1. Change `MockSyslogSender.init` to return `!MockSyslogSender` (error union) and propagate the error instead of panicking.

**Acceptance criteria:**

- [ ] `MockSyslogSender.init` returns an error union instead of panicking.

---

## Findings By Area

### Authentication and Authorization

- No findings. The library does not implement auth; it logs auth events created by the calling application.

### Web/API Surface

- Not applicable. This is a library, not a service.

### Input Validation

- **S1** (Critical): CEF escape no-ops allow log injection.
- **S5** (High): Incomplete sensitive key detection.
- **S8** (Medium): No `AuditEvent` field validation.

### Data Protection and Redaction

- **S2** (High): `pii_mode`/`pci_mode` flags ignored.
- **S3** (High): Redaction does not recurse into nested structures.

### Transport Security

- **S4** (High): Plaintext syslog transport.
- **S6** (High): TLS config accepted but unimplemented.
- **S11** (Low): Unauthenticated DNS resolution.

### Cryptography and Randomness

- **S7** (Medium): Predictable PRNG seed from timestamp.

### Filesystem and Configuration

- **S9** (Medium): Unsanitized file path from config.

### Reliability and Monitoring

- **S10** (Medium): Silent ring buffer overflow.
- **S12** (Low): Integer cast truncation risk.
- **S13** (Low): `@panic` in test mock.

### Supply Chain

- **SC-1** (Low): DNS dependency pinned to commit, not tag.

---

## Remediation Roadmap

### Quick Wins (< 1 day each)

| ID | Finding | Effort | Impact |
|----|---------|--------|--------|
| S1 | Wire existing `escapeCefString` into `escapeHeader`/`escapeValue`/`escapeKey` | 2-4 hours | Eliminates Critical log injection |
| S6 | Fail at init when `protocol = .tls` instead of silently accepting | 1 hour | Prevents silent audit data loss |
| S7 | Replace `microTimestamp()` seed with `std.crypto.random` | 30 min | Eliminates predictable IDs |
| S12 | Use `std.math.cast` for i128-to-i64 conversion | 15 min | Prevents potential panic |
| S13 | Return error union from `MockSyslogSender.init` | 30 min | Eliminates test panic |

### Medium Effort (1-5 days each)

| ID | Finding | Effort | Impact |
|----|---------|--------|--------|
| S3 | Make `filterAndRedactMetadata` recursive | 1-2 days | Closes nested data leak |
| S5 | Expand sensitive key list; add glob pattern support | 1-2 days | Reduces redaction bypass risk |
| S8 | Add `AuditEvent.validate()` with field constraints | 1 day | Prevents malformed events |
| S9 | Add path traversal validation in `FileSink` | 1 day | Prevents arbitrary file writes |
| S10 | Add drop counter and overflow warning to ring buffer | 1 day | Enables monitoring of event loss |
| S4 | Add init-time warning for plaintext syslog; document stunnel | 1 day | Improves operator awareness |
| SC-1 | Tag DNS dependency and update `build.zig.zon` | 1 hour (cross-repo) | Improves supply chain auditability |

### Strategic (> 5 days)

| ID | Finding | Effort | Impact |
|----|---------|--------|--------|
| S2 | Implement `pii_mode` and `pci_mode` enforcement in filter pipeline | 3-5 days | Enables PCI DSS / PII compliance |
| S6+ | Implement TLS transport (requires TLS library binding or Zig stdlib maturity) | 5-10 days | Enables encrypted syslog |
| S11 | Evaluate DNS-over-HTTPS or DNSSEC support | 3-5 days | Mitigates DNS spoofing |

---

## Blockers and Unknowns

1. **TLS transport (S6):** Blocked on Zig `std.crypto.tls` maturity for generic stream wrapping. The workaround (stunnel) is viable but adds operational complexity.

2. **PII/PCI mode enforcement (S2):** Requires design decisions on hashing algorithm for `pii_mode: hash` and masking format for PCI compliance. Recommend aligning with PCI DSS 3.4 masking requirements (first 6, last 4 digits visible).

3. **DNS security (S11):** The external DNS library (`devnw/zig/dns`) would need DoH/DoT support. This is a cross-repository dependency.

---

## False Positives

| Scanner | Finding | Verdict |
|---------|---------|---------|
| gitleaks | `TEST_TRACE_ID = "11111111111111111111111111111111"` in `time.zig:207` | **False positive.** Test fixture, not a secret. |
| gitleaks | `TEST_SPAN_ID = "2222222222222222"` in `time.zig:208` | **False positive.** Test fixture, not a secret. |

---

## Immediate Actions Required

**None of the findings require emergency secret rotation or immediate production response.** No real secrets were found in the repository.

The highest-priority action is **S1 (CEF escape no-ops)** which should be addressed within 7 days due to its Critical severity and the existence of a ready-made fix (`escapeCefString` is already implemented but not wired in).
