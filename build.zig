const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options (arch, os, abi)
    const target = b.standardTargetOptions(.{});

    // Standard optimization options (Debug, ReleaseSafe, ReleaseFast, ReleaseSmall)
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ws_server",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    // Add C source files
    exe.addCSourceFiles(.{
        .root = b.path("src"),
        .files = &.{
            "main.c",
            "server.c",
            "websocket.c",
        },
        .flags = &.{
            "-Wall",
            "-Wextra",
            "-std=c23",
            "-D_GNU_SOURCE",
        },
    });

    // Include the current directory for headers
    exe.addIncludePath(b.path("src"));

    // Link against system libuv
    // This requires libuv headers and libraries to be in standard system paths.
    exe.linkSystemLibrary("uv");

    // Link against the C standard library
    exe.linkLibC();

    // If you add crypto for handshakes (e.g., OpenSSL), link it here:
    // exe.linkSystemLibrary("ssl");
    // exe.linkSystemLibrary("crypto");

    // Install the artifact (moves it to zig-out/bin)
    b.installArtifact(exe);

    // Create a 'run' step to execute the server directly via 'zig build run'
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the WebSocket server");
    run_step.dependOn(&run_cmd.step);
}
