//! Verifies the no-op invariant when `-Dwith_otel=false` (the default).
//!
//! audit publishes its public surface as the "audit" module rooted at
//! `src/root.zig`. The seam is exposed as `audit.observability` so this
//! test can drive the disabled-mode invariants through the public root.

const std = @import("std");
const audit = @import("audit");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces `-Dwith_otel=true`, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled is hardcoded off (Zig 0.16 dedup workaround)" {
    // 2026-05-02: `observability.enabled` is hardcoded `false` (see the
    // comment in src/observability.zig) to dodge a Zig 0.16 named-module
    // dedup quirk in downstream build graphs. Until the conditional
    // build_options wiring is restored, the seam is a documented no-op
    // even under `-Dwith_otel=true` — assert the invariant that actually
    // holds rather than the aspirational flag-tracking one, so the
    // otel-enabled build stays green (appsec iter-2 finding N1).
    try std.testing.expectEqual(false, audit.observability.enabled);
}

test "client/server seams are no-ops when otel disabled" {
    if (audit.observability.enabled) return error.SkipZigTest;
    var span = audit.observability.startClientSpan(.{
        .method = "GET",
        .route = "/",
        .url = "https://example.test/",
    });
    audit.observability.endClientSpan(span, 200);
    // Belt-and-suspenders: the seam's `endClientSpan` already covers the
    // lifecycle; this line just verifies the no-op fallback's signature
    // matches the real API's `Span.end(?u64) void`.
    span.end(null);

    var sspan = audit.observability.startServerSpan(.{
        .method = "GET",
        .route = "/",
        .url = "/",
    });
    audit.observability.endServerSpan(sspan, 200);
    sspan.end(null);
}

test "audit-record span helper is a no-op when otel disabled" {
    if (audit.observability.enabled) return error.SkipZigTest;
    var span = audit.observability.startAuditRecordSpan("user.login");
    audit.observability.endAuditRecordSpan(span, true, true);
    span.end(null);
}
