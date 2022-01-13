const std = @import("std");
const win32 = struct {
    usingnamespace @import("win32").system.memory;
};

const MappedFile = @This();

pub const Access = enum {
    read_only,
    read_write,
};

mapping: std.os.windows.HANDLE,
ptr: [*]align(std.mem.page_size) u8,

pub fn init(file: std.fs.File, opt: struct {
    len: usize = 0,
    access: Access = .read_only,
    offset: u64 = 0,
}) !MappedFile {
    const mapping = win32.CreateFileMappingW(
        file.handle,
        null,
        switch (opt.access) {
            .read_only => win32.PAGE_READONLY,
            .read_write => win32.PAGE_READWRITE,
        },
        0,
        0,
        null,
    ) orelse return switch (std.os.windows.kernel32.GetLastError()) {
        // TODO: insert error handling
        else => |err| std.os.windows.unexpectedError(err),
    };
    errdefer std.os.close(mapping);
    const ptr = win32.MapViewOfFile(
        mapping,
        switch (opt.access) {
            .read_only => win32.FILE_MAP_READ,
            .read_write => win32.FILE_MAP.initFlags(.{.READ=1, .WRITE=1}),
        },
        @intCast(u32, (opt.offset >> 32) & 0xffffffff),
        @intCast(u32, (opt.offset >>  0) & 0xffffffff),
        opt.len,
    ) orelse switch (std.os.windows.kernel32.GetLastError()) {
        else => |err| return std.os.windows.unexpectedError(err),
    };
    return MappedFile { .mapping = mapping, .ptr = @alignCast(std.mem.page_size, @ptrCast([*]u8, ptr)) };
}

pub fn deinit(self: MappedFile) void {
    std.debug.assert(0 != win32.UnmapViewOfFile(self.ptr));
    std.os.close(self.mapping);
}
