const std = @import("std");
const GitRepoStep = @import("GitRepoStep.zig");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();


    const zigwin32_repo = GitRepoStep.create(b, .{
        .url = "https://github.com/marlersoft/zigwin32",
        .branch = "15.0.1-preview",
        .sha = "a74c9dae6a1ccd361eb9a1d146a09c08d22f02b0",
    });


    const exe = b.addExecutable("execexample", "execexample.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.step.dependOn(&zigwin32_repo.step);
    const zigwin32_repo_path = zigwin32_repo.getPath(&exe.step);
    exe.addPackage(std.build.Pkg{
        .name = "win32",
        .path = .{ .path = b.pathJoin(&.{ zigwin32_repo_path, "win32.zig" }) },
    });
    // use an odd base address so we are less likely to conflict with
    // other executables (note that default is 0x140000000)
    //exe.image_base = 0x110000000;
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}
