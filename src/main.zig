const std = @import("std");
const testing = std.testing;
const ptrs = @import("pointers.zig");
const commons = @import("commons.zig");
const ralloc = @import("driver.zig");
// const driver = @import("driver.zig");

const State = enum {
    Dangling,
    Uninit,
    Operational
};

const D = struct {
    T(State.Uninit)
};
const Data = struct {
    chars: [4]u8
};
fn T (comptime STATE: State) type {
    return struct {
        comptime state : State = STATE,
        data: Data,

        fn ensure_state(self:@This(), comptime state:State) void {
            if (self.state != state) {
                const msg = std.fmt.comptimePrint("Expected {}, got {}", .{state, self.state});
                @compileError(msg);
            }
        }
        fn change_state(self:@This(), comptime state:State) T(state) {
            return T(state) {.data = self.data};
        }

        fn init(self:@This()) T(State.Operational) {
            self.ensure_state(State.Dangling);
            return self.change_state(State.Operational);
        }
    };
}


pub fn main() !void {


    // var val : K() = undefined;
    // val.init();
    // val.init();
    // std.debug.print("{} {}", .{val, val.state_is()});

    // var i : usize = std.rand.limitRangeBiased(usize, 1, 512);

    // var val : struct { u8, u16, u32 } = undefined;
    // std.debug.print("{}", .{val[i]});

    // var allocer = std.heap.page_allocator;
    // var sralocer : driver.RegionAllocator = undefined;
    // sralocer.init();
    // var pallocer : driver.InfailablePageProvider = undefined;
    // pallocer.infailable_source = &allocer;
    // const obj = try sralocer.alloc_object([4096]u8, &pallocer);
    // const ptr_ = obj.get_data_ref();
    // ptr_.* = (1 << 16) - 1;
    // std.debug.print("{any}", .{obj});

    // std.debug.print("{}", .{@alignOf(@Vector(16, u128))});

    // var ralloc_: ralloc.RootAllocator = undefined;
    // try ralloc_.init();

    // const mem = ralloc_.get_page_blocking() catch unreachable;
    // const mem_ = mem.rebind_to([4096]u8).get();
    // @memset(mem_, (1 << 8) - 1);
    // std.debug.print("{any}", .{mem_.*});

    // const T = packed struct { a:u,b:u17 };
    // std.debug.print("{}", .{@alignOf(u13)});

    // const vals: [3]u8 = .{ 0, 0, (1 << 8) - 1 };

    // const T = commons.Outcome(
    //     [*]const u8,
    //     ptrs.CompressedPtr(u32, ptrs.@"Byte amount fitting within 48 bit address space", true));
    // var val: T = undefined;
    // val.store_success((&vals).ptr);
    // std.debug.print("{any} {}", .{ val.get_success_ref().*, val.contains_error() });


    // var val : u32 = (1 << 32) - 1;
    // std.debug.print("value is at {}\n", .{&val});
    // var ptr = ptrs.take_copmpact_ref(
    //     &val,
    //     ptrs.@"Byte amount fitting within 48 bit address space");
    // std.debug.print("type of addr is {s}\n", .{@typeName(@TypeOf(ptr.address))});
    // std.debug.print("ptr reconstr {}\n", .{ptr.get()});
    // std.debug.print("and the value is... {}\n", .{ptr.get().*});

    // std.debug.print("size {}\n", .{@sizeOf(struct {u64, u64, u64})});
    // std.debug.print("48-bit AddrSpace ptr bw {}\n", .{
    //     @bitSizeOf(
    //         ptrs.CompressedPtr(struct { u64 align(4096) },
    //         ptrs.@"Byte amount fitting within 48 bit address space"))});
    // const T = MemBlock(8, 256, struct { u16 }, struct { u16, u8 });
    // const mb : T = undefined;
    // std.debug.print("size {} {}\n", .{@sizeOf(T), mb.items.len});

    // const m : u32 = 132;
    // invoke(&m, @ptrCast(&wow));

    // const val_ = .{.item=@as(u32, 1)};
    // std.debug.print("{}", .{val_.item});
    // const T = commons.MemBlock(4096, 4096, u8, u8);
    // var gar: T = undefined;
    // std.debug.print("{} {} {} {}", .{ @offsetOf(T, "header"), @sizeOf(@TypeOf(gar.header)), @sizeOf(T), @alignOf(T) });
    // @memset(&gar.items, 0);
    // gar.items[0] = (1 << 8) - 1;
    // const ptr = @as(*u8, @ptrFromInt(@intFromPtr(&gar) + @offsetOf(T, "items")));
    // std.debug.assert(ptr.* == (1 << 8) - 1);
}

// fn wow(ptr: *const u32) void {
//     std.debug.print("{}", .{ptr.*});
// }
// fn invoke(ptr: *const anyopaque, fun: *const fn (*const anyopaque) void) void {
//     fun(ptr);
// }
