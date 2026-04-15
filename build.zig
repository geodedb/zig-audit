// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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

    // Unit tests (run tests defined in the module itself)
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dns", .module = dns_mod },
            },
        }),
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

    // Check step for IDE integration (fast syntax validation)
    const check_step = b.step("check", "Check for compilation errors");
    const check = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dns", .module = dns_mod },
            },
        }),
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
}
