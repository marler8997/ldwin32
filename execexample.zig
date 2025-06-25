const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.execve);

const ldwin32 = @import("ldwin32.zig");

const ArgIteratorWindows = @import("ArgIteratorWindows.zig");

const global = struct {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    pub const allocator = arena.allocator();
};

fn sliceFromUnicode(s: std.os.windows.UNICODE_STRING) []u16 {
    const buffer = s.Buffer orelse return &[_]u16{};
    return buffer[0..s.Length];
}

pub export fn WinMainCRTStartup() callconv(@import("std").os.windows.WINAPI) noreturn {
    switch (tryMain()) {
        error.InvalidCmdLine => @panic("Invalid Command Line (invalid unicode characters)"),
        error.OutOfMemory => @panic("Out Of Memory"),
    }
}
fn tryMain() error{OutOfMemory, InvalidCmdLine} {
    const peb = std.os.windows.peb();

    log.debug("CommandLine ({*}) is '{}'", .{
        peb.ProcessParameters.CommandLine.Buffer,
        std.unicode.fmtUtf16Le(sliceFromUnicode(peb.ProcessParameters.CommandLine)),
    });
    var arg_it = ArgIteratorWindows.initWithCmdLine(peb.ProcessParameters.CommandLine.Buffer orelse &.{});

    if (!arg_it.skip()) @panic("empty CommandLine");

    // skip whitespace so we can save the start of the new first argument
    skip_whitespace: while(true) : (arg_it.index += 1) {
        switch (arg_it.cmd_line[arg_it.index]) {
            ' ', '\t' => continue,
            else => break :skip_whitespace,
        }
    }
    const new_cmd_line_start: c_ushort = @intCast(arg_it.index);

    const first_arg = try (arg_it.next(global.allocator) orelse {
        std.io.getStdOut().writer().writeAll("Usage: execexample EXE ARGS...\n") catch |err|
            std.debug.panic("write to stdout failed: {s}", .{@errorName(err)});
        std.process.exit(0xff);
    });
    std.log.info("FirstArg '{s}'", .{first_arg});

    // Shift CommandLine to remove the first argument (updating the PEB CommandLine string pointers didn't seem to work)
    //peb.ProcessParameters.CommandLine.Length -= new_cmd_line_start;
    //peb.ProcessParameters.CommandLine.MaximumLength -= new_cmd_line_start;
    //peb.ProcessParameters.CommandLine.Buffer += new_cmd_line_start;

    // TODO: this is a memmove
    for (0 .. peb.ProcessParameters.CommandLine.Length - new_cmd_line_start) |i| {
        peb.ProcessParameters.CommandLine.Buffer.?[i] = peb.ProcessParameters.CommandLine.Buffer.?[i + new_cmd_line_start];
    }

    //std.log.info("NewCommandLine: '{}'", .{std.unicode.fmtUtf16Le(std.mem.span(std.meta.assumeSentinel(peb.ProcessParameters.CommandLine.Buffer, 0)))});
    std.log.info("NewCommandLine: '{}'", .{std.unicode.fmtUtf16Le(std.mem.span(GetCommandLineW() orelse &[_:0]u16{}))});

    switch (ldwin32.execve(first_arg)) {
        else => |e| {
            std.log.err("execve failed with {s}", .{@errorName(e)});
            std.process.exit(0xff);
        },
    }
}

extern "kernel32" fn GetCommandLineW() callconv(std.os.windows.WINAPI) ?[*:0]u16;
