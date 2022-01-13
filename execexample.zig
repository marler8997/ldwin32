const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.execve);

const ldwin32 = @import("ldwin32.zig");

const global = struct {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    pub const allocator = arena.allocator();
};

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
        std.unicode.fmtUtf16le(std.mem.span(std.meta.assumeSentinel(peb.ProcessParameters.CommandLine.Buffer, 0))),
    });
    var arg_it = std.process.ArgIteratorWindows.initWithCmdLine(peb.ProcessParameters.CommandLine.Buffer);

    if (!arg_it.skip()) @panic("empty CommandLine");

    // skip whitespace so we can save the start of the new first argument
    skip_whitespace: while(true) : (arg_it.index += 1) {
        switch (arg_it.cmd_line[arg_it.index]) {
            ' ', '\t' => continue,
            else => break :skip_whitespace,
        }
    }
    const new_cmd_line_start = @intCast(c_ushort, arg_it.index);

    const first_arg = (try arg_it.next(global.allocator)) orelse {
        std.io.getStdOut().writer().writeAll("Usage: execexample EXE ARGS...\n") catch |err|
            std.debug.panic("write to stdout failed: {s}", .{@errorName(err)});
        std.os.exit(0xff);
    };
    std.log.info("FirstArg '{s}'", .{first_arg});

    // Shift CommandLine to remove the first argument (updating the PEB CommandLine string pointers didn't seem to work)
    //peb.ProcessParameters.CommandLine.Length -= new_cmd_line_start;
    //peb.ProcessParameters.CommandLine.MaximumLength -= new_cmd_line_start;
    //peb.ProcessParameters.CommandLine.Buffer += new_cmd_line_start;
    {
        var i: usize = 0;
        while (true) : (i += 1 ){
            peb.ProcessParameters.CommandLine.Buffer[i] = peb.ProcessParameters.CommandLine.Buffer[i + new_cmd_line_start];
            if (peb.ProcessParameters.CommandLine.Buffer[i] == 0)
                break;
        }
    }

    //std.log.info("NewCommandLine: '{}'", .{std.unicode.fmtUtf16le(std.mem.span(std.meta.assumeSentinel(peb.ProcessParameters.CommandLine.Buffer, 0)))});
    std.log.info("NewCommandLine: '{}'", .{std.unicode.fmtUtf16le(std.mem.span(std.os.windows.kernel32.GetCommandLineW()))});

    switch (ldwin32.execve(first_arg)) {
        else => |e| {
            std.log.err("execve failed with {s}", .{@errorName(e)});
            std.os.exit(0xff);
        },
    }
}
