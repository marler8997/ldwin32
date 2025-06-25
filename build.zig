const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const win32_dep = b.dependency("win32", .{});
    const win32_mod = win32_dep.module("win32");


    const exe = b.addExecutable(.{
        .name = "execexample",
        .root_module = b.createModule(.{
            .root_source_file = b.path("execexample.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "win32", .module = win32_mod },
            },
            .single_threaded = true,
        }),
    });
    // use an odd base address so we are less likely to conflict with
    // other executables (note that default is 0x140000000)
    //exe.image_base = 0x110000000;
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
