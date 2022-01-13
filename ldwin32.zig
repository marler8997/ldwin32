// TODO:
// note that one way to make this work in more cases is if this execuable
// can relocate itself at runtime to get out of the way if necessary

const std = @import("std");
const win32 = struct {
    usingnamespace @import("win32").zig;
    usingnamespace @import("win32").foundation;
    usingnamespace @import("win32").system.system_services;
    usingnamespace @import("win32").system.diagnostics.debug;
    usingnamespace @import("win32").system.memory;
    usingnamespace @import("win32").system.library_loader;
    usingnamespace @import("win32").system.windows_programming;
    usingnamespace @import("win32").system.threading;
    usingnamespace @import("win32").storage.file_system;
};
const MappedFile = @import("MappedFile.zig");

const log = std.log.scoped(.execve);

pub const ExecveError = error { MsvcrtInitArgsFailed } || LoadExeError || LoadImportsError;
pub fn execve(exe_filename: []const u8) ExecveError {
    const load_exe_result = try loadExe(exe_filename);
    const load_imports_result = try loadImports(load_exe_result.mem, load_exe_result.nt_header_offset);
    _ = load_imports_result;

    // !!!!!!!!!!!!!!!!!!!
    // TODO: TLS Setup???
    // !!!!!!!!!!!!!!!!!!!

    const peb = std.os.windows.peb();

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena_instance.allocator();

    const image_path_name = std.unicode.utf8ToUtf16LeWithNull(allocator, exe_filename) catch |err| switch (err) {
        error.OutOfMemory => @panic("Out of memory"),
        error.InvalidUtf8 => @panic("exe filename is invalid UTF8"),
    };
    peb.ProcessParameters.ImagePathName = .{
        .Buffer = image_path_name.ptr,
        .Length = @intCast(c_ushort, image_path_name.len),
        .MaximumLength = @intCast(c_ushort, image_path_name.len),
    };

    const entry =  load_exe_result.mem.ptr + load_exe_result.AddressOfEntryPoint;
    log.debug("entry is {*}", .{entry});

    //win32.DebugBreak();
    @ptrCast(fn() callconv(std.os.windows.WINAPI) noreturn, entry)();
    unreachable;
}

const LoadExeError = error { OpenExeFailed, Unexpected } || LoadExeFromContentsError;
const LoadExe = struct {
    mem: []align(std.mem.page_size) u8,
    nt_header_offset: u31,
    AddressOfEntryPoint: u32,
};
fn loadExe(exe_filename: []const u8) LoadExeError!LoadExe {
    const exe_file = std.fs.cwd().openFile(exe_filename, .{}) catch |err| switch (err) {
        else => |e| {
            log.err("failed to open '{s}', error={s}", .{exe_filename, @errorName(e)});
            return error.OpenExeFailed;
        },
    };
    defer std.os.close(exe_file.handle);

    const file_size = try std.os.windows.GetFileSizeEx(exe_file.handle);

    const exe_file_map = try MappedFile.init(exe_file, .{ .len = file_size });
    defer exe_file_map.deinit();

    return loadExeFromContents(exe_file_map.ptr[0 .. file_size]);
}

const LoadExeFromContentsError = error { InvalidExe, ImageAllocFailed };
pub fn loadExeFromContents(exe_contents: []align(std.mem.page_size) const u8) LoadExeFromContentsError!LoadExe {
    if (exe_contents.len < @sizeOf(win32.IMAGE_DOS_HEADER)) {
        log.err("file size {d} is to small for an exe", .{exe_contents.len});
        return error.InvalidExe;
    }

    const dos_header = @ptrCast(*const win32.IMAGE_DOS_HEADER, exe_contents.ptr);
    if (dos_header.e_magic != win32.IMAGE_DOS_SIGNATURE) {
        log.err("invalid exe format (bad signature)", .{});
        return error.InvalidExe;
    }

    if (exe_contents.len < dos_header.e_lfanew + @sizeOf(win32.IMAGE_NT_HEADERS64)) {
        log.err("exe ends (size={d}) before e_lfanew boundary ({d})", .{exe_contents.len, dos_header.e_lfanew + @sizeOf(win32.IMAGE_NT_HEADERS64)});
        return error.InvalidExe;
    }

    // NOTE: we assume 64-bit for now by using IMAGE_NT_HEADERS64
    //       TODO: verify it is a 64-bit image
    // TODO: verify that e_lfanew is non-negative?
    const nt_header = @ptrCast(
        *const win32.IMAGE_NT_HEADERS64,
        // TODO: does e_lfanew guarnatee alignment?  I'm assuming it does for now.
        @alignCast(@alignOf(win32.IMAGE_NT_HEADERS64), exe_contents.ptr + @intCast(usize, dos_header.e_lfanew)),
    );

    // Allocate memory for the executable image
    log.debug("ImageBase=0x{x} Size={d}", .{nt_header.OptionalHeader.ImageBase, nt_header.OptionalHeader.SizeOfImage});

    // TODO: verify ImageBase is not something bad like 0
    // TODO: verify SizeOfImage is not 0
    const mem: [*]align(std.mem.page_size)u8 = blk: {
        break :blk @alignCast(std.mem.page_size, @ptrCast([*]u8, win32.VirtualAlloc(
            @intToPtr(*anyopaque, nt_header.OptionalHeader.ImageBase),
            nt_header.OptionalHeader.SizeOfImage,
            win32.VIRTUAL_ALLOCATION_TYPE.initFlags(.{ .COMMIT = 1, .RESERVE = 1}),
            win32.PAGE_EXECUTE_READWRITE,
        ) orelse {
            triageAllocFail(nt_header.OptionalHeader.ImageBase);
            log.warn("NOTE: could not allocate to 0x{x}, error={}", .{nt_header.OptionalHeader.ImageBase, win32.GetLastError()});
            // Allow it to pick its own address, maybe we'll get lucky I guess?
            // Can we relocate the current exe/stuff to free up the memory here?
            break :blk @alignCast(std.mem.page_size, @ptrCast([*]u8, win32.VirtualAlloc(
                null,
                nt_header.OptionalHeader.SizeOfImage,
                win32.VIRTUAL_ALLOCATION_TYPE.initFlags(.{ .COMMIT = 1, .RESERVE = 1}),
                win32.PAGE_EXECUTE_READWRITE,
            ) orelse {
                // TODO: verify whether error is because ImageBase is not available?
                log.err("VirtualAlloc of size {d} failed with {}", .{nt_header.OptionalHeader.SizeOfImage, win32.GetLastError()});
                return error.ImageAllocFailed;
            }));
        }));
    };
    errdefer std.debug.assert(0 != win32.VirtualFree(mem, 0, win32.MEM_RELEASE));

    if (@ptrToInt(mem) != nt_header.OptionalHeader.ImageBase) {
        log.warn("could not load image to 0x{x}, loaded to 0x{*} instead", .{nt_header.OptionalHeader.ImageBase, mem});
        //return error.ImageAllocFailed;
    }

    // TODO: verify mem and exe_contents are large enough for SizeOfHeaders
    @memcpy(mem, exe_contents.ptr, nt_header.OptionalHeader.SizeOfHeaders);

    const section_headers = IMAGE_FIRST_SECTION(nt_header)[0 .. nt_header.FileHeader.NumberOfSections];
    {
        for (section_headers) |hdr| {
            if (hdr.VirtualAddress + hdr.SizeOfRawData > nt_header.OptionalHeader.SizeOfImage) {
                log.err("section at RVA 0x{x} len {d} is out of bounds ({d})", .{hdr.VirtualAddress, hdr.SizeOfRawData, nt_header.OptionalHeader.SizeOfImage});
                return error.InvalidExe;
            }
            log.debug("loading section at RVA 0x{x} to 0x{x}", .{hdr.VirtualAddress, hdr.VirtualAddress + hdr.SizeOfRawData});
            @memcpy(mem + hdr.VirtualAddress, exe_contents.ptr + hdr.PointerToRawData, hdr.SizeOfRawData);
        }
    }
    return LoadExe{
        .mem = mem[0 .. nt_header.OptionalHeader.SizeOfImage],
        .nt_header_offset = @intCast(u31, dos_header.e_lfanew),
        .AddressOfEntryPoint = nt_header.OptionalHeader.AddressOfEntryPoint,
    };
}

const GetMainArgsFn = fn(
    out_argc: *c_int,
    out_argv: *[*][*:0]u8,
    out_envp: *[*][*:0]u8,
    do_wildcard: c_int,
    start_info: ?*win32.STARTUPINFOA,
) callconv(std.os.windows.WINAPI) c_int;

// functions that are patched
const patch = struct {
    pub var __getmainargs_fn: ?GetMainArgsFn = null;
    fn __getmainargs(
        out_argc: *c_int,
        out_argv: *[*][*:0]u8,
        out_envp: *[*][*:0]u8,
        do_wildcard: c_int,
        start_info: ?*win32.STARTUPINFOA,
    ) callconv(std.os.windows.WINAPI) c_int {
        log.debug("getmainargs is being called (wildcard={})!", .{do_wildcard});
        const result = (__getmainargs_fn orelse unreachable)(out_argc, out_argv, out_envp, do_wildcard, start_info);
        if (result != 0) {
            log.debug("original __getmainargs failed, GetLastError()={}", .{win32.GetLastError()});
            return result;
        }
        log.debug("    argc={}", .{out_argc.*});
        for (out_argv.*[0 .. @intCast(usize, out_argc.*)]) |arg, i| {
            log.debug("    argv[{}] {*} '{s}'", .{i, arg, std.mem.span(arg)});
        }

        // remove the first argument
        std.debug.assert(out_argc.* >= 2);
        out_argc.* = out_argc.* - 1;
        out_argv.* = out_argv.* + 1;

        return result;
    }
};


const LoadImportsError = error { LoadLibraryFailed };
fn loadImports(mem: []align(std.mem.page_size) u8, nt_header_off: usize) LoadImportsError!void {
    const nt_header = @ptrCast(
        *const win32.IMAGE_NT_HEADERS64,
        // TODO: does e_lfanew guarnatee alignment?  I'm assuming it does for now.
        @alignCast(@alignOf(win32.IMAGE_NT_HEADERS64), mem.ptr + nt_header_off),
    );

    log.debug("Need to load {d} imports", .{nt_header.OptionalHeader.DataDirectory[@enumToInt(win32.IMAGE_DIRECTORY_ENTRY_IMPORT)].Size});
    if (nt_header.OptionalHeader.DataDirectory[@enumToInt(win32.IMAGE_DIRECTORY_ENTRY_IMPORT)].Size != 0) {

        // TODO: is alignment guaranteed?
        const import_descriptors_ptr = @alignCast(
            @alignOf(win32.IMAGE_IMPORT_DESCRIPTOR),
            @intToPtr(
                [*]align(1) win32.IMAGE_IMPORT_DESCRIPTOR,
                @ptrToInt(mem.ptr) + nt_header.OptionalHeader.DataDirectory[@enumToInt(win32.IMAGE_DIRECTORY_ENTRY_IMPORT)].VirtualAddress,
            ),
        );

        var import_index: usize = 0;
        while (import_descriptors_ptr[import_index].Name != 0) : (import_index += 1) {
            // TODO: verify libname_ptr is valid
            const libname = @intToPtr([*:0]u8, @ptrToInt(mem.ptr) + import_descriptors_ptr[import_index].Name);

            const libhandle = blk: {
                if (win32.GetModuleHandleA(libname)) |existing| {
                    log.debug("Library '{s}' is already loaded", .{libname});
                    break :blk existing;
                }
                log.debug("LoadLibrary '{s}'...", .{libname});
                // TODO: need to modify search diretory to match the exe being loaded
                break :blk win32.LoadLibraryA(libname) orelse {
                    log.err("failed to load '{s}', error={}", .{std.mem.span(libname), win32.GetLastError()});
                    return error.LoadLibraryFailed;
                };
            };
            const is_msvcrt = std.mem.eql(u8, std.mem.span(libname), "msvcrt.dll");

            // TODO: is alignment guaranteed?
            const name_ref = @alignCast(
                @alignOf(win32.IMAGE_THUNK_DATA64),
                @intToPtr(
                    [*]align(1) win32.IMAGE_THUNK_DATA64,
                    @ptrToInt(mem.ptr) + import_descriptors_ptr[import_index].Anonymous.Characteristics,
                ),
            );
            // TODO: is alignment guaranteed?
            const symbol_ref = @alignCast(
                @alignOf(win32.IMAGE_THUNK_DATA64),
                @intToPtr(
                    [*]align(1) win32.IMAGE_THUNK_DATA64,
                    @ptrToInt(mem.ptr) + import_descriptors_ptr[import_index].FirstThunk,
                ),
            );

            // TODO: Do this after copying the exe into the executable memory address
            //       rather than modifying the in memory exe file
            var ref_index: usize = 0;
            while (name_ref[ref_index].u1.AddressOfData != 0) : (ref_index += 1) {
                if (0 != (name_ref[ref_index].u1.AddressOfData & 0x8000000000000000)) {
                    const resource = MAKEINTRESOURCEA(name_ref[ref_index].u1.AddressOfData);
                    log.debug("    function IntResource({d})", .{@ptrToInt(resource)});
                    if (win32.GetProcAddress(libhandle, resource)) |addr| {
                        symbol_ref[ref_index].u1.AddressOfData = @ptrToInt(addr);
                    } else {
                        log.warn("GetProcAddress lib='{s}' func=IntResource({d}) failed, error={d}", .{std.mem.span(libname), @ptrToInt(resource), win32.GetLastError()});
                    }
                } else {
                    // TODO: is alignment guaranteed?
                    const thunk_data = @alignCast(
                        @alignOf(win32.IMAGE_IMPORT_BY_NAME),
                        @intToPtr(
                            *align(1) win32.IMAGE_IMPORT_BY_NAME,
                            @ptrToInt(mem.ptr) + name_ref[ref_index].u1.AddressOfData,
                        ),
                    );
                    const func_name = @ptrCast([*:0]u8, &thunk_data.Name);
                    log.debug("    function '{s}'", .{std.mem.span(func_name)});
                    if (win32.GetProcAddress(libhandle, func_name)) |addr| {
                        if (is_msvcrt and std.mem.eql(u8, std.mem.span(func_name), "__getmainargs")) {
                            log.debug("    function '{s}' (setting override)", .{std.mem.span(func_name)});
                            patch.__getmainargs_fn = @ptrCast(GetMainArgsFn, addr);
                            symbol_ref[ref_index].u1.AddressOfData = @ptrToInt(patch.__getmainargs);
                        } else {
                            symbol_ref[ref_index].u1.AddressOfData = @ptrToInt(addr);
                        }
                    } else {
                        log.warn("GetProcAddress lib='{s}' func='{s}' failed, error={d}", .{std.mem.span(libname), func_name, win32.GetLastError()});
                    }
                }
            }
        }
    }

    if ((0 != nt_header.OptionalHeader.DataDirectory[@enumToInt(win32.IMAGE_DIRECTORY_ENTRY_BASERELOC)].Size) and (nt_header.OptionalHeader.ImageBase != @ptrToInt(mem.ptr))) {
        @panic("not impl");
//        printf("\nBase relocation.\n");
//
//        DWORD i, num_items;
//        DWORD_PTR diff;
//        IMAGE_BASE_RELOCATION* r;
//        IMAGE_BASE_RELOCATION* r_end;
//        WORD* reloc_item;
//
//        diff = (DWORD)mem - nt_header->OptionalHeader.ImageBase; //Difference between memory allocated and the executable's required base.
//        r = (IMAGE_BASE_RELOCATION*)((DWORD)mem + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); //The address of the first I_B_R struct
//        r_end = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)r + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION)); //The addr of the last
//
//        for (; r<r_end; r = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)r + r->SizeOfBlock))
//        {
//            reloc_item = (WORD*)(r + 1);
//            num_items = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
//
//            for (i = 0; i<num_items; ++i, ++reloc_item)
//            {
//                switch (*reloc_item >> 12)
//                {
//                case IMAGE_REL_BASED_ABSOLUTE:
//                    break;
//                case IMAGE_REL_BASED_HIGHLOW:
//                    *(DWORD_PTR*)((DWORD)mem + r->VirtualAddress + (*reloc_item & 0xFFF)) += diff;
//                    break;
//                default:
//                    return 1;
//                }
//            }
//        }
    }
}

fn IMAGE_FIRST_SECTION(nt_header: *const win32.IMAGE_NT_HEADERS64) [*]const win32.IMAGE_SECTION_HEADER {
    return @intToPtr([*]win32.IMAGE_SECTION_HEADER,
        @ptrToInt(nt_header) +
        @offsetOf(win32.IMAGE_NT_HEADERS64, "OptionalHeader") +
        nt_header.FileHeader.SizeOfOptionalHeader,
    );
}

fn MAKEINTRESOURCEA(val: anytype) [*:0]const u8 {
    return @intToPtr([*:0]const u8, 0xffff & val);
}

fn triageAllocFail(addr: usize) void {
    var info: win32.MEMORY_BASIC_INFORMATION = undefined;
    {
        const len = win32.VirtualQuery(@intToPtr(*const anyopaque, addr), &info, @sizeOf(@TypeOf(info)));
        if (len == 0) {
            log.err("VirtualQuery on address 0x{x} failed, error={}", .{addr, win32.GetLastError()});
            return;
        }
        if (len < @sizeOf(@TypeOf(info))) {
            log.err("expected at least {} bytes from VirtualQuery but got {}", .{@sizeOf(@TypeOf(info)), len});
            return;
        }
    }
    log.info("VirtualQueryInfo: {}", .{info});

    // TODO: check if the current process conflicts with that address
    log.info("ThisProcess {}", .{std.os.windows.peb().Ldr.*});
}
