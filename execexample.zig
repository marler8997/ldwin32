const std = @import("std");
const ldwin32 = @import("ldwin32.zig");

var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
const allocator = arena.allocator();

pub fn main() !u8 {
    const args = try std.process.argsAlloc(allocator);
    // should we free?

    if (args.len <= 1) {
        std.log.err("Usage: execexample.exe EXE ARGS...", .{});
        return 0xff;
    }

    switch (ldwin32.execve(args[1])) {
        else => |e| {
            std.log.err("execve failed with {s}", .{@errorName(e)});
            return 1;
        },
    }
}
