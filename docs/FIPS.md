# FIPS-140-3 Status — audit

**Requirement ID:** AUDIT-FIPS-001

**Mode:** This library performs only **non-security** cryptographic, hashing,
and random-number operations. It is **exempt** from the workspace FIPS-140-3
routing requirement (see `fips` package spec
`docs/superpowers/specs/2026-06-20-fips-pqc-design.md` §5). No security
primitive in this library produces, protects, or verifies a secret, key,
credential, authentication tag, or signature; therefore none is routed
through the `crypto_backend` seam and none links the OpenSSL FIPS provider.
When a consumer builds with `-Dfips=true`, this library is unaffected: it
adds no `-Dfips` flag and changes no behavior.

## Exempt call sites

| File:Line | Primitive | Use | Why non-security (exempt) |
|-----------|-----------|-----|---------------------------|
| `src/filters.zig:296` | SHA-256 (`std.crypto.hash.sha2.Sha256`) | PII pseudonymization for log correlation | Output documented as correlatable-but-not-secret (`filters.zig:289-294`); never a key/tag/credential. It is an unkeyed hash of low-entropy PII explicitly *not* relied upon for confidentiality. |
| `src/time.zig:139,155` | `std.Random.DefaultPrng` | Trace/span ID generation (`SystemIdGen`) | Observability correlators; not secrets or auth material. IDs identify spans/traces, not subjects. |

## zlint allow-list

Every site above carries an inline `// fips-exempt: non-security — <reason>`
annotation so the `zlint` FIPS rule treats it as allow-listed rather than a
violation. Adding a new `std.crypto` / `std.hash` / `std.Random` use to this
library REQUIRES adding both the inline annotation and a row in the table
above.
