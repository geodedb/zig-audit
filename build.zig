// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -Dwith_otel: compile in otel instrumentation. OFF by default;
    // when off the otel dependency is never resolved and the seam
    // collapses to a comptime-known no-op (verified by
    // otel/scripts/verify-consumer-noop.sh).
    const with_otel = b.option(
        bool,
        "with_otel",
        "Compile in otel instrumentation (off by default; zero overhead when off)",
    ) orelse false;

    // Materialize ONE shared `build_options` module. Each consumer
    // module imports the SAME module instance via `addImport` to avoid
    // Zig 0.16's "file exists in modules X and X0" error when two
    // independent `addOptions` modules end up sharing a transitive
    // file path.
    const build_options = b.addOptions();
    build_options.addOption(bool, "with_otel", with_otel);
    const build_options_mod = build_options.createModule();

    // Observability seam (otel). Declared as a SHARED NAMED MODULE so
    // every consumer (lib, tests, examples, benchmarks, plus the seam
    // tests) resolves to the same source file via
    // `@import("observability")`. Using relative
    // `@import("observability.zig")` from each module would trip
    // Zig's "file exists in modules X and Y" error because the file
    // would be pulled into multiple module trees. The seam's
    // `enabled` flag tracks `build_options.with_otel`; when off,
    // every helper compiles to a comptime-known no-op and the otel
    // dependency is never resolved. The optional `otel` import is
    // wired below inside the `if (with_otel)` block.
    const observability_mod = b.addModule("observability", .{
        .root_source_file = b.path("src/observability.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // External dependency: DNS library for hostname resolution
    const dns_dep = b.dependency("dns", .{
        .target = target,
        .optimize = optimize,
    });
    const dns_mod = dns_dep.module("dns");

    // Main library module
    const module = b.addModule("audit", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("dns", dns_mod);
    module.addImport("observability", observability_mod);
    module.addImport("build_options", build_options_mod);

    // Gated otel dependency. The `lazy = true` entry in build.zig.zon
    // means Zig only fetches the package when this branch executes;
    // with the flag off the dependency is never resolved and the
    // produced artifacts contain zero otel symbols (verified by
    // otel/scripts/verify-consumer-noop.sh).
    const otel_mod_opt: ?*std.Build.Module = if (with_otel) blk: {
        const otel_dep = b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        }) orelse break :blk null;
        const otel_module = otel_dep.module("otel");
        // The seam itself imports `otel` when enabled. Wire it onto
        // the shared observability module so every consumer sees the
        // same otel namespace.
        observability_mod.addImport("otel", otel_module);
        module.addImport("otel", otel_module);

        // Bootstrap helper. Only registered when `-Dwith_otel=true`
        // so the disabled build never compiles otel-touching code.
        // Gated from root.zig via
        // `if (observability.enabled) @import("observability_init")`.
        const observability_init_mod = b.addModule("observability_init", .{
            .root_source_file = b.path("src/observability_init.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "otel", .module = otel_module },
                .{ .name = "observability", .module = observability_mod },
            },
        });
        module.addImport("observability_init", observability_init_mod);
        break :blk otel_module;
    } else null;

    // Unit tests (run tests defined in the module itself).
    // Reuse the public `audit` module directly so the test root and
    // the library root resolve the same source file under the same
    // module tree — this avoids Zig 0.16's "file exists in modules X
    // and Y" error when a NAMED module (`observability`,
    // `observability_init`) would otherwise be pulled into two trees.
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Integration tests (separate test file with module import)
    const integration_step = b.step("test-integration", "Run integration tests");
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "audit", .module = module },
            },
        }),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    integration_step.dependOn(&run_integration_tests.step);

    // CEF tests
    const cef_test_step = b.step("test-cef", "Run CEF formatting tests");
    const cef_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_cef.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "audit", .module = module },
            },
        }),
    });
    cef_test_step.dependOn(&b.addRunArtifact(cef_tests).step);

    // Filter tests
    const filter_test_step = b.step("test-filters", "Run filter and redaction tests");
    const filter_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_filters.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "audit", .module = module },
            },
        }),
    });
    filter_test_step.dependOn(&b.addRunArtifact(filter_tests).step);

    // Transport tests
    const transport_test_step = b.step("test-transports", "Run transport tests");
    const transport_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_transports.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "audit", .module = module },
            },
        }),
    });
    transport_test_step.dependOn(&b.addRunArtifact(transport_tests).step);

    // Run all tests
    const all_test_step = b.step("test-all", "Run all tests");
    all_test_step.dependOn(&run_unit_tests.step);
    all_test_step.dependOn(&run_integration_tests.step);
    all_test_step.dependOn(&b.addRunArtifact(cef_tests).step);
    all_test_step.dependOn(&b.addRunArtifact(filter_tests).step);
    all_test_step.dependOn(&b.addRunArtifact(transport_tests).step);

    // Example: basic usage (compile check + runnable)
    const example_step = b.step("example", "Build and run the basic example");
    const example = b.addExecutable(.{
        .name = "basic-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "audit", .module = module },
            },
        }),
    });
    const run_example = b.addRunArtifact(example);
    example_step.dependOn(&run_example.step);

    // Compile-check the example as part of test-all so CI catches breakage
    all_test_step.dependOn(&example.step);

    // Check step for IDE integration (fast syntax validation).
    // Reuses the public `audit` module so the seam's NAMED
    // `observability` module stays in a single module tree.
    const check_step = b.step("check", "Check for compilation errors");
    const check = b.addTest(.{
        .root_module = module,
    });
    check_step.dependOn(&check.step);

    // ── Benchmarks ─────────────────────────────────────────────────────────

    // Basic micro-benchmarks
    const bench_step = b.step("bench", "Run performance micro-benchmarks");
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "audit", .module = module },
            },
        }),
    });
    const run_bench = b.addRunArtifact(bench);
    bench_step.dependOn(&run_bench.step);

    // Incremental scale benchmark (JSON output to stdout)
    const scale_bench_step = b.step("scale-bench", "Run incremental scale benchmark");
    const scale_bench = b.addExecutable(.{
        .name = "scale-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/scale_bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "audit", .module = module },
            },
        }),
    });
    if (b.args) |args| {
        const run_scale = b.addRunArtifact(scale_bench);
        run_scale.addArgs(args);
        scale_bench_step.dependOn(&run_scale.step);
    } else {
        const run_scale = b.addRunArtifact(scale_bench);
        scale_bench_step.dependOn(&run_scale.step);
    }
    b.installArtifact(scale_bench);

    // Benchmark comparison tool
    const compare_step = b.step("compare-bench", "Compare benchmark results against baseline");
    const compare = b.addExecutable(.{
        .name = "compare-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/compare.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    const run_compare = b.addRunArtifact(compare);
    if (b.args) |args| {
        run_compare.addArgs(args);
    }
    compare_step.dependOn(&run_compare.step);

    // ── Observability seam tests ─────────────────────────────────────────
    //
    // Disabled-mode no-op tests. Verifies `build_options.with_otel == false`
    // is the default and that the seam's public surface returns a
    // comptime-known no-op when otel is off. The test is skip-guarded
    // for the enabled build so it passes under both flag values.
    const observability_disabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_disabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "audit", .module = module },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    const run_observability_disabled_tests = b.addRunArtifact(observability_disabled_tests);
    test_step.dependOn(&run_observability_disabled_tests.step);
    all_test_step.dependOn(&run_observability_disabled_tests.step);

    // Enabled-mode smoke test. Skips under -Dwith_otel=false; under
    // -Dwith_otel=true it installs an in-memory recorder, drives one
    // audit-record span through the seam, and asserts the recorder
    // captured it. Compiles cleanly under both flag values because
    // the otel-namespace identifiers sit behind `comptime if (enabled)`
    // short-circuits.
    const observability_enabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_enabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "audit", .module = module },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    if (otel_mod_opt) |otel_module| {
        // Re-resolve the otel module under the same `with_otel`
        // guard so the smoke test reaches `@import("otel")`. The
        // earlier `lazyDependency` call handles the public `audit`
        // module; the test root needs its own import wire.
        observability_enabled_tests.root_module.addImport("otel", otel_module);
    }
    const run_observability_enabled_tests = b.addRunArtifact(observability_enabled_tests);
    test_step.dependOn(&run_observability_enabled_tests.step);
    all_test_step.dependOn(&run_observability_enabled_tests.step);
}
