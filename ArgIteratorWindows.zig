const ArgIteratorWindows = @This();

index: usize,
cmd_line: [*]const u16,

pub const NextError = error{ OutOfMemory, InvalidCmdLine };

pub fn init() ArgIteratorWindows {
    return initWithCmdLine(os.windows.kernel32.GetCommandLineW());
}

pub fn initWithCmdLine(cmd_line: [*]const u16) ArgIteratorWindows {
    return ArgIteratorWindows{
        .index = 0,
        .cmd_line = cmd_line,
    };
}

fn getPointAtIndex(self: *ArgIteratorWindows) u16 {
    // According to
    // https://docs.microsoft.com/en-us/windows/win32/intl/using-byte-order-marks
    // Microsoft uses UTF16-LE. So we just read assuming it's little
    // endian.
    return std.mem.littleToNative(u16, self.cmd_line[self.index]);
}

/// You must free the returned memory when done.
pub fn next(self: *ArgIteratorWindows, allocator: Allocator) ?(NextError![:0]u8) {
    // march forward over whitespace
    while (true) : (self.index += 1) {
        const character = self.getPointAtIndex();
        switch (character) {
            0 => return null,
            ' ', '\t' => continue,
            else => break,
        }
    }

    return self.internalNext(allocator);
}

pub fn skip(self: *ArgIteratorWindows) bool {
    // march forward over whitespace
    while (true) : (self.index += 1) {
        const character = self.getPointAtIndex();
        switch (character) {
            0 => return false,
            ' ', '\t' => continue,
            else => break,
        }
    }

    var backslash_count: usize = 0;
    var in_quote = false;
    while (true) : (self.index += 1) {
        const character = self.getPointAtIndex();
        switch (character) {
            0 => return true,
            '"' => {
                const quote_is_real = backslash_count % 2 == 0;
                if (quote_is_real) {
                    in_quote = !in_quote;
                }
            },
            '\\' => {
                backslash_count += 1;
            },
            ' ', '\t' => {
                if (!in_quote) {
                    return true;
                }
                backslash_count = 0;
            },
            else => {
                backslash_count = 0;
                continue;
            },
        }
    }
}

fn internalNext(self: *ArgIteratorWindows, allocator: Allocator) NextError![:0]u8 {
    var buf = std.ArrayList(u16).init(allocator);
    defer buf.deinit();

    var backslash_count: usize = 0;
    var in_quote = false;
    while (true) : (self.index += 1) {
        const character = self.getPointAtIndex();
        switch (character) {
            0 => {
                return convertFromWindowsCmdLineToUTF8(allocator, buf.items);
            },
            '"' => {
                const quote_is_real = backslash_count % 2 == 0;
                try self.emitBackslashes(&buf, backslash_count / 2);
                backslash_count = 0;

                if (quote_is_real) {
                    in_quote = !in_quote;
                } else {
                    try buf.append(std.mem.nativeToLittle(u16, '"'));
                }
            },
            '\\' => {
                backslash_count += 1;
            },
            ' ', '\t' => {
                try self.emitBackslashes(&buf, backslash_count);
                backslash_count = 0;
                if (in_quote) {
                    try buf.append(std.mem.nativeToLittle(u16, character));
                } else {
                    return convertFromWindowsCmdLineToUTF8(allocator, buf.items);
                }
            },
            else => {
                try self.emitBackslashes(&buf, backslash_count);
                backslash_count = 0;
                try buf.append(std.mem.nativeToLittle(u16, character));
            },
        }
    }
}

fn convertFromWindowsCmdLineToUTF8(allocator: Allocator, buf: []u16) NextError![:0]u8 {
    return std.unicode.utf16LeToUtf8AllocZ(allocator, buf) catch |err| switch (err) {
        error.ExpectedSecondSurrogateHalf,
        error.DanglingSurrogateHalf,
        error.UnexpectedSecondSurrogateHalf,
        => return error.InvalidCmdLine,

        error.OutOfMemory => return error.OutOfMemory,
    };
}
fn emitBackslashes(self: *ArgIteratorWindows, buf: *std.ArrayList(u16), emit_count: usize) !void {
    _ = self;
    var i: usize = 0;
    while (i < emit_count) : (i += 1) {
        try buf.append(std.mem.nativeToLittle(u16, '\\'));
    }
}

const std = @import("std");
const os = std.os;

const Allocator = std.mem.Allocator;
