const std = @import("std");

pub const @"1KiB of bytes": comptime_int = 1024;
pub const @"1MiB of bytes": comptime_int = 1024 * 1024;
pub const @"1GiB of bytes": comptime_int = 1 << 30;
pub const @"Byte amount fitting within 48 bit address space": comptime_int = (1 << 48) - 1;

pub fn Ptr(comptime Pointee: type, comptime is_mutable: bool) type {
    const Ty = if (is_mutable) *Pointee else *const Pointee;
    return struct {
        addr: usize = 0,
        pub fn get(self: @This()) Ty {
            return @ptrFromInt(self.addr);
        }
        pub fn set(self: *@This(), ptr: Ty) void {
            self.addr = @intFromPtr(ptr);
        }
        pub fn advance(self: *@This(), count: usize) void {
            self.addr += @sizeOf(Pointee) * count;
        }
        pub fn add_bytes(self: *@This(), byte_count: usize) void {
            self.addr += byte_count;
        }
        pub fn alignment_offset_for(self: @This(), desired_alignment: usize) usize {
            return std.mem.alignForward(usize, self.addr, desired_alignment) - self.addr;
        }
        pub fn align_for(self: *@This(), desired_alignment: usize) void {
            self.addr = std.mem.alignForward(usize, self.addr, desired_alignment);
        }
        pub fn is_aligned_for(self: @This(), alignment: usize) bool {
            return std.mem.alignForward(usize, self.addr, alignment) == self.addr;
        }
        pub fn as_raw(self: *@This()) Ptr(u8, is_mutable) {
            return Ptr(u8, is_mutable){ .addr = self.addr };
        }
        pub fn rebind_to(self: @This(), comptime T: type) Ptr(T, is_mutable) {
            if (!self.is_aligned_for(@alignOf(T))) @panic("Provided ptr is not aligned for " ++ @typeName(T));
            return Ptr(T, is_mutable){ .addr = self.addr };
        }
        pub fn is_null(self: @This()) bool {
          return self.addr == 0;
        }
        pub fn set_null(self: *@This()) void {
            self.addr = 0;
        }
    };
}

pub fn CompressedPtr(
    comptime Pointee: type,
    comptime address_space_byte_size: comptime_int,
    comptime is_mutable: bool
) type {
    const pointee_byte_stride = @sizeOf(Pointee);
    if (@sizeOf(Pointee) > address_space_byte_size) {
        @compileError("Not enough capacity in address space to place " ++ @typeName(Pointee));
    }
    const nominal_size = address_space_byte_size / pointee_byte_stride;
    const minimal_ptr_bit_width =
        @as(comptime_int, @intFromFloat(@ceil(@log2(@as(comptime_float, @floatFromInt(nominal_size))))));
    const MinimalPtrBitwidth = std.meta.Int(std.builtin.Signedness.unsigned, minimal_ptr_bit_width);
    const full_ptr_bit_width = bitwidth_for_byte_granularity_ptr(address_space_byte_size);
    const spare_trailing_bits_count = full_ptr_bit_width - minimal_ptr_bit_width;
    const PtrTy = if (is_mutable) *Pointee else *const Pointee;

    return packed struct {
        address: MinimalPtrBitwidth = 0,
        pub fn get(self: @This()) PtrTy {
            const full_addr = @as(usize, @intCast(self.address)) << spare_trailing_bits_count;
            return @as(PtrTy, @ptrFromInt(full_addr));
        }
        pub fn set_addr(self:*@This(), addr: usize) void {
            self.address = @truncate(addr >> spare_trailing_bits_count);
        }
        pub fn set(self: *@This(), ptr: PtrTy) void {
            const addr = @intFromPtr(ptr) >> spare_trailing_bits_count;
            self.address = @intCast(addr);
        }
        pub fn advance(self: *@This(), count: MinimalPtrBitwidth) void {
            self.address += count;
        }
        pub fn is_null(self:@This()) bool {
            return self.address == 0;
        }
        pub fn set_null(self: *@This()) void {
            self.address = 0;
        }
        pub fn as_uncompressed(self:@This()) Ptr(u8, is_mutable) {
            var ptr_ : Ptr(u8, is_mutable) = undefined;
            ptr_.set(self.get());
            return ptr_;
        }
    };
}
pub fn take_compact_ref(ptr: anytype, comptime address_space_byte_size: comptime_int) mk_ret_ty_comp_ref(@TypeOf(ptr), address_space_byte_size) {
    const PtrTy = @TypeOf(ptr);
    comptime {
        if (!std.meta.trait.isSingleItemPtr(PtrTy)) {
            @compileError("Expected pointer, got " ++ @typeName(@TypeOf(ptr)));
        }
    }
    const is_const = comptime std.meta.trait.isConstPtr(PtrTy);
    var ptr_: CompressedPtr(@typeInfo(PtrTy).Pointer.child, address_space_byte_size, !is_const) = .{};
    ptr_.set(ptr);
    return ptr_;
}
fn mk_ret_ty_comp_ref(comptime T: type, comptime address_space_byte_size: comptime_int) type {
    comptime {
        if (!std.meta.trait.isSingleItemPtr(T)) {
            @compileError("Expected pointer, got " ++ @typeName(T));
        }
    }
    const mut = std.meta.trait.isConstPtr(T);
    return CompressedPtr(@typeInfo(T).Pointer.child, address_space_byte_size, !mut);
}

pub fn take_ref(ptr: anytype) mk_ret_ty_take_ref(@TypeOf(ptr)) {
    var ptr_ = mk_ret_ty_take_ref(@TypeOf(ptr)){};
    ptr_.set(ptr);
    return ptr_;
}
fn mk_ret_ty_take_ref(comptime Ptr_: type) type {
    comptime {
        if (!std.meta.trait.isSingleItemPtr(Ptr_)) @compileError("Expected pointer, got " ++ @typeName(Ptr_));
    }
    const mut = std.meta.trait.isConstPtr(Ptr_);
    return Ptr(@typeInfo(Ptr_).Pointer.child, !mut);
}

pub fn bitwidth_for_byte_granularity_ptr(comptime address_space_byte_size: comptime_int) comptime_int {
    return @as(comptime_int, @ceil(@log2(@as(comptime_float, @floatFromInt(address_space_byte_size)))));
}

test "basic sanity check for ptr compression" {
    const T = u32;
    var value: T = 0;
    var ptr = take_compact_ref(&value, @"Byte amount fitting within 48 bit address space");
    std.debug.assert((1 << @bitSizeOf(@TypeOf(ptr))) - 1 ==
        @"Byte amount fitting within 48 bit address space" / @sizeOf(T));
    var value_ = ptr.get().*;
    std.debug.assert(value == value_);
}

test "common programm address space in managed env" {
    const Ty = CompressedPtr(u8, @"Byte amount fitting within 48 bit address space", false);
    const byte_ptr_bit_width = bitwidth_for_byte_granularity_ptr(@"Byte amount fitting within 48 bit address space");
    std.debug.assert(@bitSizeOf(Ty) == byte_ptr_bit_width);
}

test "overaligned value" {
    const P = struct { u8 align(4096) };
    const CP = CompressedPtr(P, @"Byte amount fitting within 48 bit address space", false);
    std.debug.assert((1 << @bitSizeOf(CP)) - 1 == @"Byte amount fitting within 48 bit address space" / 4096);
}

test "only pointers" {
    const val: u32 = 1337;
    const ptr = take_compact_ref(&val, @"Byte amount fitting within 48 bit address space");
    std.debug.assert(ptr.get().* == val);
}

test "advancable compressed ptr" {
    const item: [2]u32 = .{ 0, 1 };
    var ptr = take_compact_ref(@as(*const u32, @ptrCast(&item)), @"Byte amount fitting within 48 bit address space");
    ptr.advance(1);
    std.debug.assert(ptr.get().* == 1);
}
test "advancable regular ptr" {
    const item: [2]u32 = .{ 0, 1 };
    var ptr = take_ref(@as(*const u32, @ptrCast(&item)));
    ptr.advance(1);
    std.debug.assert(ptr.get().* == 1);
}

test "alignment works" {
    const u8max = (1 << 8) - 1;
    var vals: [4]u8 = .{ u8max, u8max, u8max, u8max };
    var ptr = take_ref(@as(*u8, @ptrCast(&vals)));
    ptr.add_bytes(1);
    ptr.align_for(@alignOf(u16));
    ptr.rebind_to(u16).get().* = 0;
    std.debug.assert(vals[2] == 0 and vals[3] == 0 and vals[0] == u8max and vals[1] == u8max);
}

test "geting from packed" {
    const T = packed struct {
        ptr: CompressedPtr(u8, @"Byte amount fitting within 48 bit address space", true)
    };
    var t : T=  undefined;
    t.ptr.set(@ptrCast(&t));
    try std.testing.expect(t.ptr.get() == @as(*u8,@ptrCast(&t)));
}

test "allocation sizes" {
    const t = try std.testing.allocator.alloc(u32, 1);
    std.debug.print("{*}", .{@as(*u32,@ptrCast(t))});
    std.testing.allocator.destroy(@as(*[1]u32,@ptrCast(t)));
}