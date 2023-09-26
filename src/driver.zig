const std = @import("std");
const atomic = std.atomic;
const commons = @import("commons.zig");
const ptr = @import("pointers.zig");
const Allocator = std.mem.Allocator;
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const AtomicOrder = std.builtin.AtomicOrder;


comptime {
    const bits = @as(comptime_int,@log2(@as(comptime_float, std.mem.page_size)));
    const invalid = (1 << bits) != std.mem.page_size;
    if (invalid) @compileError("page size must be power of 2");
}
const SlabBlockMtd = packed struct {
    ref_count: u16
};
const Segment = commons.MemBlock(512, 512, SlabBlockMtd, u8);
comptime {
    const sh = @offsetOf(Segment, "header");
    const rm = @offsetOf(RAllocMtd, "ref_count");
    if (sh != rm) {
        const msg = std.fmt.comptimePrint("Not identical offsets {} {}", .{sh, rm});
        @compileError(msg);
    }
}
const page_size = v: {
    if ((std.mem.page_size / @sizeOf(Segment)) > 64) {
        const forced_size = @sizeOf(Segment) * 64;
        @compileLog(std.fmt.comptimePrint(
            "Page size forced to {} bytes", .{}));
        break :v forced_size;
    }
    break :v std.mem.page_size;
};
const GenericPage = commons.MemBlock(page_size, page_size, void, u8);
const HugePage = commons.MemBlock(page_size, 1 << 21, void, u8);
comptime {
    if (@log2(@as(comptime_float,@sizeOf(GenericPage) / @sizeOf(Segment))) > 15)
        @compileError("That wouldnt fit into a segment count");
}
fn GenericPageWMtd(comptime Mtd:type) type {
    return commons.MemBlock(page_size,page_size, Mtd, u8);
}


pub const MemAllocFailure = error{BlockedForRealloc};

pub const RootAllocator = struct {
    root_allocator: Allocator,
    hugepage_head: ptr.Ptr(HugePage, true),
    meta: u32,

    pub fn init(self: *@This(), allocer:Allocator) !void {
        @atomicStore(u32, &self.meta, 0, AtomicOrder.Monotonic);
        self.root_allocator = allocer;
        const page_ = try allocer.alloc(HugePage, 1);
        self.hugepage_head.set(@ptrCast(page_));
    }
    // pub fn refill(self:*@This(), page_source: InfailablePageProvider) !void {

    // }
    pub fn try_get_page_nonblocking(
        self: *@This(),
    ) !ptr.Ptr(GenericPage, true) {
        const offset = @atomicRmw(u32, &self.meta, AtomicRmwOp.Add, 1 << 1, AtomicOrder.Monotonic);
        const locked = (offset & 1) == 1;
        if (locked) return MemAllocFailure.BlockedForRealloc;
        const index = offset >> 1;
        const did_overshoot = index >= comptime (@sizeOf(HugePage) / @sizeOf(GenericPage));
        if (did_overshoot) {
            const item = @atomicRmw(u32, &self.meta, AtomicRmwOp.Or, 1, AtomicOrder.Monotonic);
            const already_locked = (item & 1) == 1;
            if (already_locked) return MemAllocFailure.BlockedForRealloc
            else { // we have just locked it for supplying new page
                const new_hugepage = try self.root_allocator.alloc(HugePage, 1);
                var ptr_: ptr.Ptr(HugePage, true) = undefined;
                ptr_.set(@ptrCast(new_hugepage));
                self.hugepage_head = ptr_;
                @atomicStore(u32, &self.meta, 1 << 1, AtomicOrder.Release);
                return ptr_.rebind_to(GenericPage);
            }
        } else {
            @fence(AtomicOrder.Acquire);
            var ptr_ = self.hugepage_head.rebind_to(GenericPage);
            ptr_.advance(index);
            return ptr_;
        }
    }
    pub fn get_page(
        self: *@This(),
    ) !*GenericPage {
        var blk: ptr.Ptr(GenericPage, true) = undefined;
        while (true) {
            blk = self.try_get_page_nonblocking() catch |err| switch (err) {
                MemAllocFailure.BlockedForRealloc => continue,
                Allocator.Error.OutOfMemory => return err,
            };
            break;
        }
        return blk.get();
    }
    pub fn get_page_blocking(
        self: *@This(),
    ) !ptr.Ptr(GenericPage, true) {
        var blk: ptr.Ptr(GenericPage, true) = undefined;
        while (true) {
            blk = self.try_get_page_nonblocking() catch |err| switch (err) {
                MemAllocFailure.BlockedForRealloc => continue,
                else => return err
            };
            break;
        }
        return blk;
    }

};
const SomeFailablePageProvider = struct {
    data: *anyopaque,
    get_free_page_fn: *const fn (*anyopaque) ?*GenericPage,

    fn try_get_page(self:*const @This()) ?*GenericPage {
        return self.get_free_page_fn(self.data);
    }
};
const SomeInfailablePageProvider = struct {
    data: *anyopaque,
    get_free_page_fn: *const fn (*anyopaque) Allocator.Error!*GenericPage,

    fn init(self: *@This(),object_ref:anytype) void {
        const ti = comptime @typeInfo(@TypeOf(object_ref));
        // comptime if (!std.meta.trait.isSingleItemPtr(@TypeOf(object_ref))) {
        //     @compileError("Expected ptr, got " ++ @typeName(@TypeOf(object_ref)));
        // };
        const PointeeTy = ti.Pointer.child;
        // comptime if (!@hasDecl(PointeeTy, "get_field")) {
        //     const msg = std.fmt.comptimePrint(
        //         "Pointed object {} does not have member function named 'get_page'", .{@typeName(PointeeTy)});
        //     @compileError(msg);
        // };
        // const mem_fun_ty = @TypeOf(@field(PointeeTy, "get_page"));
        // comptime if (mem_fun_ty != fn (self:*PointeeTy) *GenericPage) {
        //     @compileError("Invalid type of member function 'get_page'");
        // };
        self.data = @ptrCast(object_ref);
        self.get_free_page_fn = @ptrCast(&PointeeTy.get_page);
    }
    fn get_page(self:*const @This()) Allocator.Error!*GenericPage {
        return try self.get_free_page_fn(self.data);
    }
};
pub const InfailablePageProvider = struct {
    infailable_source: SomeInfailablePageProvider,
    failable_sources: []SomeFailablePageProvider,

    pub fn get_page(self:*const @This()) *GenericPage {
        for (self.failable_sources) |is| {
            const outcome = is.try_get_page();
            if (outcome != null) return outcome;
        }
        const page = self.infailable_source.get_page();
        return @ptrCast(page);
    }
};


pub const AllocationFailure = error {
    InvalidSize
};
const RAllocMtd = packed struct {
    ref_count: u16,
    _pad0: u48,
    segment_occupation_map: u64, // 1 taken , 0 free
    next_page: ?*anyopaque
};
const RAllocBlock = GenericPageWMtd(RAllocMtd);
comptime { commons.ensure_exact_byte_size(RAllocBlock, page_size); }


pub const RegionAllocator = struct {
    page_start: ptr.Ptr(RAllocBlock, true),
    current_write_page: ptr.Ptr(RAllocBlock, true),
    current_sub_block: ptr.Ptr(Segment, true),
    allocation_tail: ptr.Ptr(u8, true),
    sub_block_index: u6,

    pub fn init(self:*@This()) void {
        self.page_start.set_null();
        self.sub_block_index = 0;
    }

    pub fn alloc_bytes(
        self:*@This(),
        object_size:usize,
        alignment: usize,
        ralloc:SomeInfailablePageProvider
    ) !OpaqueObjectRef {
        const max_object_size = page_size - @sizeOf(Segment);
        if (object_size > max_object_size) {
            @panic("Invalid size not handled prior");
        }
        comptime if (@sizeOf(GenericPage) == @sizeOf(Segment)) {
            @compileError("(page size / segment size) is not greater then 1");
        };
        const not_initialised = self.page_start.is_null();
        if (not_initialised) {
            try self.do_initial_setup(ralloc);
            self.setup_fresh_page();
        }
        const segment_occupation_count =
            @as(usize,@intCast(object_size / @sizeOf(Segment)));
        const fits_within_segment = segment_occupation_count == 0;
        if (fits_within_segment) {
            loop: while(true) {
                if (self.is_dangling()) {
                    try self.pagein(ralloc) ;
                    self.setup_fresh_page();
                }
                const non_setuped_block = self.allocation_tail.addr == self.current_sub_block.addr;
                if (non_setuped_block) {
                    self.setup_current_segment();
                }
                var addr = std.mem.alignForward(usize, self.allocation_tail.addr, alignment);
                var new_tail = addr + object_size;
                const limit = self.current_sub_block.addr + @sizeOf(Segment);
                if (new_tail > limit) {
                    _ = self.advance_to_next_segment();
                    continue :loop;
                }
                _ = @atomicRmw(
                    u16,
                    &self.current_sub_block.get().header.ref_count,
                    AtomicRmwOp.Add,
                    1,
                    AtomicOrder.Monotonic);
                self.allocation_tail.addr = new_tail;
                var ref_ : OpaqueObjectRef = undefined;
                ref_.tag = .SingleItemRef;
                var ptr_ : @TypeOf(ref_.payload.single)= undefined;
                ptr_.set(@ptrFromInt(addr));
                ref_.payload.single = ptr_;
                return ref_;
            }
        } else {
            const segment_occupation_count_ =
                if (@sizeOf(Segment) * segment_occupation_count < object_size) segment_occupation_count + 1
                else segment_occupation_count;
            if (self.is_dangling()) {
                try self.pagein(ralloc);
                self.setup_fresh_page();
            }
            while (true) {
                const setuped_block = self.allocation_tail.addr != self.current_sub_block.addr;
                if (setuped_block) {
                    if (self.is_at_zeroth_segment()) {
                        self.current_sub_block.advance(1);
                        self.sub_block_index += 1;
                    } else {
                        _ = self.advance_to_next_segment();
                    }
                }
                const alloc_start_addr = self.allocation_tail.addr;
                const tail_alloc_addr =
                    alloc_start_addr + (@sizeOf(Segment) * segment_occupation_count_);
                const page_boundry_addr = self.current_write_page.addr + page_size;
                const fits_in_remaining_space = tail_alloc_addr <= page_boundry_addr;
                if (fits_in_remaining_space) {
                    var ref : OpaqueObjectRef = undefined;
                    ref.tag = .MultisegmentRef;
                    var ptr_ : @TypeOf(ref.payload.multi.ptr) = undefined;
                    ptr_.set(@ptrFromInt(alloc_start_addr));
                    ref.payload.multi.ptr = ptr_;
                    ref.payload.multi.segment_count = @truncate(segment_occupation_count_);

                    self.current_sub_block.advance(segment_occupation_count_);
                    self.allocation_tail = self.current_sub_block.as_raw();
                    // set mark which segments were taken
                    const index_range: u64 = (@as(u64, 1) << @intCast(segment_occupation_count_)) - 1;
                    const mask = index_range << self.sub_block_index;
                    _ = @atomicRmw(
                        u64,
                        &self.current_write_page.get().header.segment_occupation_map,
                        AtomicRmwOp.Or,
                        mask,
                        AtomicOrder.Monotonic);
                    self.sub_block_index += @intCast(segment_occupation_count_);
                    return ref;
                } else { // doesnt fit
                    if (self.release_current_page()) {
                        try self.pagein(ralloc);
                    }
                    self.setup_fresh_page();
                    continue;
                }
            }
        }
    }
    fn is_dangling(self:*const @This()) bool {
        return self.current_sub_block.addr == self.current_write_page.addr + page_size;
    }
    // true if left dangling
    fn release_current_page(self:*@This()) bool {
        const header = &self.current_write_page.get().header;
        const free_bitpattern: u64 = 0;
        const outcome = @cmpxchgStrong(
            u64,
            &header.segment_occupation_map,
            free_bitpattern,
            0,
            AtomicOrder.Acquire,
            AtomicOrder.Monotonic);
        if (outcome == null) {
            const addr = self.current_write_page.addr;
            self.current_sub_block.addr = addr;
            self.allocation_tail.addr = addr;
            self.sub_block_index = 0;
            return false;
        }
        return true;
    }
    fn do_initial_setup(self:*@This(), allocer: SomeInfailablePageProvider) !void {
        const page = try allocer.get_page();
        const addr = @intFromPtr(page);
        self.page_start.addr = addr;
        self.current_write_page.addr = addr;
        self.current_sub_block.addr = addr;
        self.allocation_tail.addr = addr;
    }
    fn setup_current_segment(self:*@This()) void {
        var ptr_ = self.current_sub_block;
        @atomicStore(u16, &ptr_.get().header.ref_count, 1, AtomicOrder.Monotonic);
        ptr_.add_bytes(@sizeOf(SlabBlockMtd));
        self.allocation_tail = ptr_.as_raw();
        const mask : u64 = @as(u64,1) << self.sub_block_index;
        _ = @atomicRmw(
            u64,
            &self.current_write_page.get().header.segment_occupation_map,
            AtomicRmwOp.Or,
            mask,
            AtomicOrder.Monotonic);
    }
    fn setup_fresh_page(self:*@This()) void {
        const header = &self.current_write_page.get().header;
        @atomicStore(
            u64,
            &header.segment_occupation_map,
            1,
            AtomicOrder.Monotonic);
        @atomicStore(
            u16, &header.ref_count, 1, AtomicOrder.Monotonic);
        header.next_page = null;
        self.allocation_tail.add_bytes(@sizeOf(RAllocMtd));
    }
    fn pagein(self:*@This(), palloc:SomeInfailablePageProvider) !void {
        const new_page = try palloc.get_page();
        const addr = @intFromPtr(new_page);
        self.current_write_page.get().header.next_page = @ptrCast(new_page);
        self.current_write_page.addr = addr;
        self.current_sub_block.addr = addr;
        self.allocation_tail.addr = addr;
        self.sub_block_index = 0;
    }
    fn is_at_zeroth_segment(self:*const @This()) bool {
        return self.current_write_page.addr == self.current_sub_block.addr;
    }
    // true if left dangling
    fn advance_to_next_segment(self:*@This()) enum { Poisoned, Switched, Reused } {
        if (self.current_sub_block.addr == self.allocation_tail.addr)
            @panic("attempt to switch unsetup segment");
        const prior = @atomicRmw(
            u16,
            &self.current_sub_block.get().header.ref_count,
            AtomicRmwOp.Sub,
            1,
            AtomicOrder.Monotonic);
        const current_segment_is_free = prior == 1;
        if (current_segment_is_free) {
            @fence(AtomicOrder.Acquire);
            self.allocation_tail = self.current_sub_block.as_raw();
            return .Reused;
        } else {
            self.current_sub_block.advance(1);
            self.sub_block_index += 1;
            self.allocation_tail.addr = self.current_sub_block.addr;
            if (self.current_sub_block.addr == self.current_write_page.addr + page_size) {
                return .Poisoned;
            }
            return .Switched;
        }
    }
};

const ArrayBlockChainHeader = struct {
    header: packed struct {
        next_segment_ptr: ptr.CompressedPtr(
            ArrayBlockChainHeader,
            ptr.@"Byte amount fitting within 48 bit address space",
            true),
        segment_item_count: u12,
        has_entire_page: bool
    },

    fn get_region_mtd(self: *const @This()) *SlabBlockMtd {
        const addr = @intFromPtr(self);
        const origin_addr = addr & ~((1 << 12) - 1);
        return @ptrFromInt(origin_addr);
    }
    fn get_next_region_ptr(self:*const @This()) *ArrayBlockChainHeader {
        return @ptrFromInt(self.header.segment_item_count);
    }
    fn set_next_region_ptr(self: *@This(), ptr_: *anyopaque) void {
        self.header.next_segment_ptr = @truncate(@intFromPtr(ptr_));
    }
};
const FirstBlock = packed struct {
    tail_block: ptr.CompressedPtr(
        ArrayBlockChainHeader,
        ptr.@"Byte amount fitting within 48 bit address space",
        true),
    segment_item_count: u12,
    owns_entire_page: bool,
    next_segment_ptr: ptr.CompressedPtr(
        ArrayBlockChainHeader,
        ptr.@"Byte amount fitting within 48 bit address space",
        true),
};
fn ArrayRef(comptime Item: type) type {
    _ = Item;
    return packed struct {
        head_ptr: ptr.CompressedPtr(
            FirstBlock,
            ptr.@"Byte amount fitting within 48 bit address space",
            true),
        alignment: u16,
        total_item_count: usize,

        pub fn item_count(self:*const @This()) u48 {
            return self.total_item_count;
        }
        pub fn rebind_to(self: *const @This(), comptime T:type) ArrayRef(T) {
            _  = self;
        }
    };
}
const OpaqueObjectRef = packed struct {
    payload: packed union {
        single: ptr.CompressedPtr(u8, ptr.@"Byte amount fitting within 48 bit address space", true),
        multi: packed struct {
            ptr: ptr.CompressedPtr(u8, ptr.@"Byte amount fitting within 48 bit address space", true),
            segment_count: u15
        }
    },
    tag: enum { SingleItemRef, MultisegmentRef },

    fn get_data_ptr(self: *const @This()) *anyopaque {
        const ptr_ = self.payload.single;
        const ptr__ = ptr_.get();
        return @ptrCast(ptr__);
    }
    fn get_segment_mtd_ref(self:*@This()) *SlabBlockMtd {
        const ptr_ = self.get_data_ptr();
        const addr = @intFromPtr(ptr_) & ~@as(usize,@sizeOf(SlabBlockMtd) - 1);
        return @ptrFromInt(addr);
    }
    fn get_region_mtd_ref(self:*@This()) *RAllocBlock {
        const ptr_ = self.get_data_ptr();
        const addr = @intFromPtr(ptr_) & ~@as(usize,@sizeOf(GenericPage) - 1);
        return @ptrFromInt(addr);
    }
};
comptime {
    commons.ensure_exact_byte_size(OpaqueObjectRef, 8);
}

fn ObjectRef(comptime T: type) type {
    return packed struct {
        ptr: OpaqueObjectRef,

        fn get_data_ptr(self: *const @This()) *T {
            const ptr_ = self.ptr.get_data_ptr();
            return @ptrCast(ptr_);
        }
    };
}

// const WorkGroupCreationFailure = error {

// };
pub const WorkGroup = struct {
    host_allocator: Allocator,
    root_allocator: RootAllocator,
    occupation_registry: u64, // 1 for available, 0 for taken
    external_ref_count: u32,
    inline_workers: [16]Worker,
    all_idle_mask: u64,
    worker_count: u32,
    group_destruction_began: bool,

    pub fn new(page_source: Allocator) !WorkGroupRef {
        const cpu_count : u32 = @intCast(@min(16,try std.Thread.getCpuCount())); // todo fixme

        var host_alloc = page_source;
        var wg : *WorkGroup = @ptrCast(try host_alloc.alloc(WorkGroup, 1));
        try wg.root_allocator.init(host_alloc);
        @atomicStore(u32, &wg.external_ref_count, 1, AtomicOrder.Monotonic);
        const occupation_bits : usize =
            if (cpu_count == 64) ~@as(u64,0) else (@as(u64, 1) << @intCast(cpu_count)) - 1;
        wg.all_idle_mask = occupation_bits;
        @atomicStore(u64, &wg.occupation_registry, occupation_bits, AtomicOrder.Monotonic);
        wg.host_allocator = host_alloc;
        wg.worker_count = cpu_count;
        @atomicStore(
            bool,
            &wg.group_destruction_began,
            false,
            AtomicOrder.Monotonic);

        var ix : u32 = 0;
        while (true) {
            const wref = &wg.inline_workers[ix];
            wref.init_defaults();
            wref.work_group_ref = wg;
            wref.worker_index = ix;
            wref.futex_wake_location.value = 0;

            ix += 1;
            if (ix == cpu_count) break;
        }
        var wref : WorkGroupRef = undefined;
        wref.ptr = wg;
        return wref;
    }
    fn external_side_destroy(self:*@This()) void {
        var ix:u32 = 0;
        const limit = self.worker_count;
        while (true) {
            const worker = self.get_worker_at_index(ix);
            const outcome = @cmpxchgStrong(
                bool,
                &worker.flags.was_started,
                true, true,
                AtomicOrder.Monotonic, AtomicOrder.Monotonic);
            const was_started = outcome == null;
            if (was_started) {
                worker.flags.kill_self = true;
                worker.wakeup();
                worker.thread.?.join();
            }
            ix += 1;
            if (ix == limit) break;
        }
    }
    fn try_find_unoccupied_index(self:*@This()) ?u64 {
        var bits : u64 = (1 << 64) - 1;
        while (true) {
            const free_index = @ctz(bits);
            const free_index_bit: u64 = @as(usize,1) << @intCast(free_index);
            const prior = @atomicRmw(
                u64,
                &self.occupation_registry,
                AtomicRmwOp.Or,
                free_index_bit,
                AtomicOrder.Monotonic);
            const we_have_it = prior & free_index_bit != 0;
            if (we_have_it) {
                return free_index;
            } else {
                const no_free_workers = prior == 0;
                if (no_free_workers) return null;
                bits = prior;
                continue;
            }
        }
    }
    fn get_worker_at_index(self:*@This(), index: u64) *Worker {
        if (index < 16) {
            return &self.inline_workers[index];
        } else {
            @panic("todo");
        }
    }
};
pub const WorkGroupRef = struct {
    ptr: *WorkGroup,

    pub fn submit_task_and_await(
        self:*const @This(),
        capture: anytype,
        operation: *const fn (*const TaskContext, *@TypeOf(capture)) Continuation
    ) !void {
        var resume_flag : atomic.Atomic(u32) = undefined;
        resume_flag.value = 0;
        if (self.ptr.try_find_unoccupied_index()) |some_index| {
            const free_worker = self.ptr.get_worker_at_index(some_index);
            try free_worker.start(); // idempotent
            free_worker.begin_safe_sync_access();
            {
                const exported = free_worker.exported_worker_local_data.?;

                var page_source : SomeInfailablePageProvider = undefined;
                page_source.init(&free_worker.work_group_ref.root_allocator);

                var initial_task : Task = undefined;
                initial_task.set_fun_ptr(@ptrCast(operation));
                initial_task.meta0.action_type = ActionType.Then;
                initial_task.meta0.frame_layout = .ThreadResumer;

                const task_frame_align : usize = @alignOf(TaskFrame_ResumesThread);
                var size : usize = @sizeOf(TaskFrame_ResumesThread);
                const aligned_for_data = std.mem.alignForward(usize, size, @alignOf(@TypeOf(capture)));
                const need_overalign = aligned_for_data - size != 0;
                initial_task.meta0.data_alignment_order =
                    if (need_overalign) @ctz(aligned_for_data) else 0 ;

                size += @sizeOf(@TypeOf(capture));

                const frame = try exported.region_allocator.alloc_bytes(
                    size, task_frame_align, page_source);
                initial_task.frame_ptr = frame;

                var ptr_ : ptr.Ptr(TaskFrame_ResumesThread, true) = undefined;
                ptr_.set(@alignCast(@ptrCast(frame.get_data_ptr())));

                const frame_header = ptr_.get();
                frame_header.child_task_count = 0;
                frame_header.resume_flag = &resume_flag;

                var data_ptr = ptr_;
                data_ptr.add_bytes(aligned_for_data);
                data_ptr.rebind_to(@TypeOf(capture)).get().* = capture;

                _ = exported.task_set.push(initial_task);
            }
            free_worker.end_safe_sync_access();
            free_worker.wakeup();
        } else {
            // no free workers exist.
            // we can park this thread and put it into wait queue.
            // eventually one of workers will take handle of this.
            @panic("todo");
        }
        // wait til submited task is completed
        while (true) {
            std.Thread.Futex.wait(&resume_flag, 0);
            if (resume_flag.load(AtomicOrder.Monotonic) == 1) break;
        }
    }
    pub fn submit_task(self:*const @This()) void {
        _ = self;
    }
    pub fn clone_ref(self:*const @This()) WorkGroupRef {
        _ = @atomicRmw(u32, &self.ptr.external_ref_count, AtomicRmwOp.Add, 1, AtomicOrder.Monotonic);
        return self.*;
    }
    pub fn done_here(self:*const @This()) void {
        const prior_ref_count = @atomicRmw(
            u32, &self.ptr.external_ref_count, AtomicRmwOp.Sub, 1, AtomicOrder.Monotonic);
        const last_observer = prior_ref_count == 1;
        const all_idle_mask = self.ptr.all_idle_mask;
        const outcome = @cmpxchgStrong(
            u64,
            &self.ptr.occupation_registry,
            all_idle_mask,
            all_idle_mask,
            AtomicOrder.Monotonic,
            AtomicOrder.Monotonic);
        const all_idle = outcome == null;
        const dispose = last_observer and all_idle;
        if (dispose) {
            const outcome_ = @cmpxchgStrong(
                bool,
                &self.ptr.group_destruction_began,
                false,
                true,
                AtomicOrder.Monotonic,
                AtomicOrder.Monotonic);
            const already_began = outcome_ != null;
            if (already_began) return
            else self.ptr.external_side_destroy();
        }
    }
};

const CrossWorkerTransactionState = enum(u8) {
    ReadyToRecieve, Finished
};
const WorkerInitFlags = enum(u8) {
    Void, Initing, Done
};
pub const Worker = struct {
    work_group_ref: *WorkGroup,
    thread: ?std.Thread,
    futex_wake_location: atomic.Atomic(u32),
    worker_index: u32,
    exported_worker_local_data: ?*WorkerExportData,
    shared_task_pack: TaskPackPtr,
    flags: struct {
        kill_self: bool,
        was_started: bool,
        transaction_state: CrossWorkerTransactionState
    },

    pub fn init_defaults(self:*@This()) void {
        self.thread = null;
        self.futex_wake_location.value = 0;
        self.exported_worker_local_data = null;
        self.shared_task_pack.set_null();
        self.flags.was_started = false;
        @atomicStore(
            CrossWorkerTransactionState,
            &self.flags.transaction_state,
            .Finished,
            AtomicOrder.Monotonic);
    }
    pub fn start(self:*@This()) !void {
        const flag = @cmpxchgStrong(
            bool,
            &self.flags.was_started,
            false,
            true,
            AtomicOrder.Monotonic,
            AtomicOrder.Monotonic);
        if (flag) |_| return;

        const conf : std.Thread.SpawnConfig = .{};
        const thread = try std.Thread.spawn(conf, worker_processing_routine, .{self});
        self.thread = thread;
    }
    pub fn begin_safe_sync_access(self:*@This()) void {
        const was_started = @cmpxchgStrong(
            bool,
            &self.flags.was_started,
            true,
            true,
            AtomicOrder.Monotonic,
            AtomicOrder.Monotonic);
        if (was_started != null) @panic("Attempt to sync with worker that was not started");
        while (true) {
            const transaction_state = @atomicLoad(
                CrossWorkerTransactionState, &self.flags.transaction_state, AtomicOrder.Monotonic);
            switch (transaction_state) {
                .ReadyToRecieve => { @fence(AtomicOrder.Acquire); return; },
                else => continue,
            }
        }
    }
    pub fn end_safe_sync_access(self:*@This()) void {
        @atomicStore(
            CrossWorkerTransactionState,
            &self.flags.transaction_state,
            .Finished,
            AtomicOrder.Release);
    }
    // true if should suicide
    pub fn hibernate(self:*@This()) bool {
        while (true) {
            const outcome = @cmpxchgStrong(
                CrossWorkerTransactionState,
                &self.flags.transaction_state,
                .Finished,
                .ReadyToRecieve,
                AtomicOrder.Acquire,
                AtomicOrder.Monotonic);
            if (outcome == null) return false;
            // its good idead to perform mem defrag here
            std.Thread.Futex.wait(&self.futex_wake_location, 0);
            if (self.flags.kill_self) return true;
        }
    }
    pub fn wakeup(self:*const @This()) void {
        std.Thread.Futex.wake(&self.futex_wake_location, 1);
    }
    // true if all idle
    pub fn advertise_as_available(self:*@This()) bool {
        const mask = @as(u64,1) << @intCast(self.worker_index);
        const prior_occupation_map = @atomicRmw(
            u64,
            &self.work_group_ref.occupation_registry,
            AtomicRmwOp.Or,
            mask,
            AtomicOrder.Monotonic);
        const all_idle = prior_occupation_map | mask == self.work_group_ref.all_idle_mask;
        return all_idle;
    }
    pub fn internal_side_dispose(self:*@This()) void {
        var ix:u32 = 0;
        const work_group = self.work_group_ref;
        const limit = work_group.worker_count;
        while (true) {
            if (ix == self.worker_index) { continue; }
            const outcome = @cmpxchgStrong(
                bool,
                &self.flags.was_started,
                true, true,
                AtomicOrder.Monotonic, AtomicOrder.Monotonic);
            const was_started = outcome == null;
            if (was_started) {
                const worker_ = work_group.get_worker_at_index(ix);
                worker_.flags.kill_self = true;
                worker_.wakeup();
                worker_.thread.?.join();
            }
            ix += 1;
            if (ix == limit) break;
        }
    }
};
const TaskPack = @Vector(16, u128);
const CombinerPageMtd = packed struct {
    occupation_map: u64, // 0 taken, 1 available
    next_page: ?*anyopaque,
};
const CombinerPage = GenericPageWMtd(CombinerPageMtd);
const Combiner = struct {
    page_start: ptr.Ptr(CombinerPage, true),
    current_write_page: ptr.Ptr(CombinerPage, true),
    current_segment_read_ptr: ptr.Ptr(TaskPack, true),
    current_segment_write_ptr: ptr.Ptr(TaskPack, true),

    fn init(self:*@This()) void {
        self.page_start.set_null();
        self.current_write_page.set_null();
        self.current_segment_read_ptr.set_null();
        self.current_segment_write_ptr.set_null();
    }
    fn do_first_init(self:*@This(), allocer:*InfailablePageProvider) void {
        const page : *CombinerPage = @ptrCast(try allocer.get_page());
        page.header.next_page.set_null();
        const map = (1 << (@sizeOf(GenericPage) / @sizeOf(Segment))) - 1;
        @atomicStore(u64, &page.header.occupation_map, map, AtomicOrder.Monotonic);
        self.page_start.set(page);
        self.current_write_page.set(page);
        self.current_segment_read_ptr.addr = @intFromPtr(page);
        self.current_segment_read_ptr.advance(1);
        self.current_segment_write_ptr.addr = @intFromPtr(page);
        self.current_segment_write_ptr.advance(1);
    }
    fn pagein(self:*@This(), allocator:*InfailablePageProvider) !void {
        const page = try allocator.get_page();
        self.page_start.addr = @intFromPtr(page);
        @atomicStore(
            u16,
            &self.current_write_page.get().header.ref_count,
            1,
            AtomicOrder.Monotonic);
        self.segment_ptr.addr = @intFromPtr(page);
        self.segment_ptr.advance(1);
    }
    // true if object in left in uninit state
    fn release_page(self:*@This()) void {
        const val = @atomicRmw(
            u16,
            &self.page_start.get().header.ref_count,
            AtomicRmwOp.Sub,
            1,
            AtomicOrder.Monotonic);
        if (val == 1) {
            @fence(AtomicOrder.Acquire);
            @atomicStore(
                u16,
                &self.page_start.get().header.ref_count,
                1,
                AtomicOrder.Monotonic);
            self.segment_ptr.addr = self.page_start.addr;
            self.segment_ptr.advance(1);
        } else {
            self.page_start.set_null();
        }
    }
    fn get_storage_for_pack(
        self:*@This(),
        allocator:*InfailablePageProvider
    ) ptr.Ptr(TaskPack, true) {
        if (self.page_start.is_null()) try self.pagein(allocator);
        const task_pack_addr = self.segment_ptr.addr;
        _ = @atomicRmw(
            u16,
            &self.page_start.get().header.ref_count,
            AtomicRmwOp.Add,
            1,
            AtomicOrder.Monotonic);
        const next_pack_addr = task_pack_addr + @sizeOf(TaskPack);
        const at_the_boundry = next_pack_addr == self.page_start.addr + page_size;
        if (at_the_boundry) self.release_page();
        var ptr_ : ptr.Ptr(TaskPack, true) = undefined;
        ptr_.addr = task_pack_addr;
        return ptr_;
    }
};
const TaskPackPtr = packed struct {
    ptr: ptr.CompressedPtr(TaskPack, ptr.@"Byte amount fitting within 48 bit address space", true),
    item_count: u16,

    fn set_null(self:*@This()) void {
        var ptr_ : @TypeOf(self.ptr) = undefined;
        ptr_.set_null();
        self.ptr = ptr_;
        self.item_count = 0;
    }
    fn is_null(self:*const @This()) bool {
        return @as(u64,@bitCast(self.*)) == 0;
    }
    fn get_mtd_ref(self:*const @This()) *u16 {
        const addr = @as(usize,self.ptr.address) & ~(@alignOf(GenericPage) - 1);
        return @ptrFromInt(addr);
    }
    fn unpack(self: *const @This()) struct { *TaskPack, u16 } {
        const ptr_ = self.ptr;
        const ptr__ = ptr_.get();
        return .{ ptr__, self.item_count };
    }
};
comptime {
    commons.ensure_exact_byte_size(TaskPackPtr, 8);
}
const TaskSet = struct {
    inline_tasks: commons.InlineQueue(Task, 16, @alignOf(TaskPack)),
    paging_storage_start: Combiner,

    fn init(self:*@This()) void {
        self.inline_tasks.init();
    }
    fn push(self:*@This(), task: Task) bool {
        return self.inline_tasks.push_to_tail(task);
    }
    fn pop(self:*@This()) ?Task {
        return self.inline_tasks.pop_from_head();
    }
} ;
const TempData = struct {
    subtask_count: usize = 0,

    fn did_spawn_any_subtasks(self:*const @This()) bool {
        return self.subtask_count != 0;
    }
};
pub const TaskContext = struct {
    export_data: *WorkerExportData,
    temp_data: *TempData,

    pub fn spawn_subtask(
        self: *const @This(),
        capture: anytype,
        operation: *const fn(*const TaskContext, *@TypeOf(capture)) Continuation
    ) void {
        _ = self;
        _ = operation;

    }
};
pub const WorkerExportData = struct {
    region_allocator: RegionAllocator,
    task_set: TaskSet,
};

const ActionType = enum {
    Then, Done
};

const TaskFrame_Standalone = packed struct {
    child_task_count: u64
};
const TaskFrame_ResumesThread = packed struct {
    child_task_count: u64,
    resume_flag: *atomic.Atomic(u32),
};
const TaskFrame_Subtask = packed struct {
    child_task_count: u64,
    resumption_task_lot: ObjectRef(Task)
};
comptime {
    const counterOffsetOk1 =
        @offsetOf(TaskFrame_Standalone, "child_task_count") ==
        @offsetOf(TaskFrame_ResumesThread, "child_task_count");
    if (!counterOffsetOk1) @compileError("Invalid counter offset");
    const counterOffsetOk2 =
        @offsetOf(TaskFrame_Standalone, "child_task_count") ==
        @offsetOf(TaskFrame_Subtask, "child_task_count");
    if (!counterOffsetOk2) @compileError("Invalid counter offset");
}

fn worker_processing_routine(worker: *Worker) void {

    worker.flags.kill_self = false;
    // const work_group = worker.work_group_ref;

    var export_context : WorkerExportData = undefined;
    worker.exported_worker_local_data = &export_context;

    export_context.region_allocator.init();
    export_context.task_set.init();

    var temp_data : TempData = .{};

    const task_ctx : TaskContext = . {
        .export_data = &export_context,
        .temp_data = &temp_data
    };

    var curernt_task : Task = undefined;
    quantum: while (true) {
        if (export_context.task_set.pop()) |task| curernt_task = task
        else {
            // mark as available for consumption
            const all_idle = worker.advertise_as_available();
            const outcome = @cmpxchgStrong(
                u32,
                &worker.work_group_ref.external_ref_count,
                0,
                0,
                AtomicOrder.Monotonic,
                AtomicOrder.Monotonic);
            const no_external_references = outcome == null;
            const should_dispose_workgroup = all_idle and no_external_references;
            if (should_dispose_workgroup) {
                // release any resource
                const outcome_ = @cmpxchgStrong(
                    bool,
                    &worker.work_group_ref.group_destruction_began,
                    false, true,
                    AtomicOrder.Monotonic,
                    AtomicOrder.Monotonic);
                const already_began = outcome_ != null;
                if (already_began) return
                else {
                    worker.internal_side_dispose();
                }
                return;
            } else {
                const suicide = worker.hibernate();
                if (suicide) {
                    // release resources
                    return;
                } else {
                    continue :quantum;
                }
            }
        }
        const action_ptr = curernt_task.action_ptr.get();
        switch (curernt_task.meta0.action_type) {
            .Then => {
                const components = curernt_task.get_components();
                fast_path:while (true) {
                    var action =
                        @as(*const fn (*const TaskContext, *anyopaque) Continuation, @ptrCast(action_ptr));
                    const outcome = action(&task_ctx, components.data_ptr);
                    // we need to deal with subtasks
                    switch (outcome.payload) {
                        .Then => |data| {
                            action = data.next_operation;
                            continue :fast_path;
                        },
                        .Done => {
                            switch (curernt_task.meta0.frame_layout) {
                                .ThreadResumer => {
                                    const header = @as(*TaskFrame_ResumesThread,@alignCast(@ptrCast(components.header_ptr)));
                                    header.resume_flag.store(1, AtomicOrder.Monotonic);
                                    std.Thread.Futex.wake(header.resume_flag, 1);
                                },
                                .Standalone => {

                                },
                                .TaskResumer => {

                                }
                            }
                            continue :quantum;
                        }
                    }
                }
            },
            .Done => unreachable
        }
    }
}

pub const Continuation = struct {
    payload: union(ActionType) {
        Then: struct {
            next_operation: *const fn (*const TaskContext, *anyopaque) Continuation
        },
        Done
    },
};
const Task = packed struct {
    action_ptr: ptr.CompressedPtr(
        u8,
        ptr.@"Byte amount fitting within 48 bit address space",
        false),
    meta0: packed struct(u16) {
        data_alignment_order: u8,
        frame_layout: enum { Standalone, ThreadResumer, TaskResumer },
        action_type: ActionType,
        _pad1: u5
    },
    frame_ptr: OpaqueObjectRef,

    fn set_fun_ptr(self:*@This(), fptr: *const anyopaque) void {
        var ptr_ : ptr.CompressedPtr(
            u8,
            ptr.@"Byte amount fitting within 48 bit address space",
            false) = undefined;
        ptr_.set(@ptrCast(fptr));
        self.action_ptr = ptr_;
    }
    fn get_components(self:@This()) struct {
        header_ptr: *anyopaque,
        data_ptr: *anyopaque
    } {
        const frame_addr = @intFromPtr(self.frame_ptr.get_data_ptr());
        const header_size:usize = switch (self.meta0.frame_layout) {
            .Standalone => @sizeOf(TaskFrame_Standalone),
            .ThreadResumer => @sizeOf(TaskFrame_ResumesThread),
            .TaskResumer => @sizeOf(TaskFrame_Subtask)
        };
        const past_header_addr = frame_addr + header_size;
        const align_order = self.meta0.data_alignment_order;
        const data_addr =
            if (align_order == 0) past_header_addr
            else std.mem.alignForward(
                usize, past_header_addr, @as(usize,1) << @intCast(align_order));
        return .{.header_ptr = @ptrFromInt(frame_addr), .data_ptr = @ptrFromInt(data_addr) };
    }

};
comptime {
    commons.ensure_exact_byte_size(Task, 16);
    if (@bitOffsetOf(Task, "action_ptr") != 0) @compileError("invalid position");
    if (@bitOffsetOf(Task, "frame_ptr") != 64) @compileError("invalid position");
}


test "ralocing" {
    var ralloc : RootAllocator = undefined;
    try ralloc.init(std.heap.page_allocator);

    var sralloc : RegionAllocator = undefined;
    sralloc.init();

    const hui = SomeInfailablePageProvider {
        .data = &ralloc,
        .get_free_page_fn = @ptrCast(&RootAllocator.get_page)
    };

    const Item = u32;
    const n = page_size * 2;
    var items : [n]OpaqueObjectRef = undefined;
    for (0 .. n) |ix| {
        const ref = try sralloc.alloc_bytes(@sizeOf(Item),@alignOf(Item), hui);
        @as(*Item,@alignCast(@ptrCast(ref.get_data_ptr()))).* = @intCast(ix);
        items[ix] = ref;
    }
    for (0 .. n) |ix| {
        const val = @as(*u32,@alignCast(@ptrCast(items[ix].get_data_ptr()))).*;
        if (val != ix) {
            std.debug.print("Expected {} got {}", .{ix, val});
        }
        try std.testing.expect(val == ix);
    }
}


test "wg init" {
    const wg = try WorkGroup.new(std.heap.page_allocator);
    const T = struct {
        fn jopa(_: *const TaskContext, capture: *u32) Continuation {
            std.debug.print("{}", .{capture.*});
            return Continuation { .payload = .Done };
        }
    };
    try wg.submit_task_and_await(@as(u32,1111), T.jopa);
    wg.done_here();
}

