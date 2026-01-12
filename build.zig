const std = @import("std");

pub fn build(b: *std.Build) void {
    // const target = b.standardTargetOptions(.{});
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .musl,
    });
    // Default to ReleaseSmall for production embedded use if not specified
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "microrainbow",
        .root_module = exe_mod,
    });
    exe.root_module.strip = true; // Strip symbols for smaller binary

    // exe.root_module.addIncludePath(b.path("src/include"));
    exe.root_module.addIncludePath(b.path("deps/include"));

    exe.root_module.addLibraryPath(b.path("deps/lib"));
    exe.root_module.addLibraryPath(b.path("."));
    // exe.root_module.addLibraryPath(.{ .cwd_relative = "/lib" }); // Avoid system libs which are stripped

    exe.root_module.linkSystemLibrary("uci", .{});
    exe.root_module.linkSystemLibrary("ubox", .{});
    exe.root_module.link_libc = true;

    b.installArtifact(exe);
}
