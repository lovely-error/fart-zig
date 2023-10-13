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
    return commons.MemBlock(page_size, page_size, Mtd, u8);
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

pub const InfailablePageProvider = struct {
    failable_sources: []SomeFailablePageProvider,
    infailable_source: *RootAllocator,

    pub fn get_page(self:*const @This()) !*GenericPage {
        for (self.failable_sources) |is| {
            const outcome = is.try_get_page();
            if (outcome != null) return outcome.?;
        }
        const page = try self.infailable_source.get_page();
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
        ralloc:*InfailablePageProvider
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
                    ref.tag = .MultiSegmentRef;
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
    // fn dealloc_bytes(self:*@This(), ref: OpaqueObjectRef) void {
    //     switch (ref.tag) {
    //         .MultiSegmentRef => {
    //             const t = ref.payload.multi;
    //             @panic("todo");
    //         },
    //         .SingleItemRef => {
    //             const t = ref.payload.single;
    //             @panic("todo");
    //         }
    //     }
    // }
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
    fn do_initial_setup(self:*@This(), allocer: *InfailablePageProvider) !void {
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
    fn pagein(self:*@This(), palloc:*InfailablePageProvider) !void {
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
    tag: enum { SingleItemRef, MultiSegmentRef },

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
    fn bind_to(self:@This(), comptime T:type) ObjectRef(T) {
        return .{.ptr = self };
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
            return @alignCast(@ptrCast(ptr_));
        }
    };
}
comptime {
    commons.ensure_exact_byte_size(ObjectRef(anyopaque), 8);
}
// const WorkGroupCreationFailure = error {

// };
const OperationState = enum {
    Normal, ShutdownStarted, ShutdownFinished
};
pub const WorkGroup = struct {
    host_allocator: Allocator,
    root_allocator: RootAllocator,
    occupation_registry: u64, // 1 for available, 0 for taken
    external_ref_count: u32,
    all_idle_mask: u64,
    worker_count: u32,
    operation_state: OperationState,
    inline_workers: [16]Worker,

    pub fn new(page_source: Allocator) !WorkGroupRef {
        // const cpu_count : u32 = @intCast(@min(16,try std.Thread.getCpuCount())); // todo fixme
        const cpu_count = 1;

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
        @atomicStore(OperationState, &wg.operation_state, .Normal, AtomicOrder.Monotonic);

        var ix : u32 = 0;
        while (true) {
            const wref = &wg.inline_workers[ix];
            wref.init_defaults();
            wref.work_group_ref = wg;
            wref.worker_index = ix;
            wref.futex_wake_object.value = 0;

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
                worker.futex_wake_object.store(
                    @intFromEnum(WorkerSignal.WakeToDie), AtomicOrder.Monotonic);
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

                const Capture = @TypeOf(capture);
                var initial_task : Task = undefined;
                const ptrs = try initial_task.do_pre_init(
                    @ptrCast(operation),
                    &exported.region_allocator,
                    &exported.some_provider,
                    @alignOf(Capture),
                    @sizeOf(Capture),
                    .ThreadResumer);

                const frame_header = @as(
                    *TaskFrame_ThreadResumer,
                    @alignCast(@ptrCast(ptrs.header)));
                frame_header.child_task_count = 0;
                frame_header.resume_flag = &resume_flag;

                @as(*Capture,@alignCast(@ptrCast(ptrs.data))).* = capture;

                _ = try exported.task_set.push(initial_task, &exported.some_provider);
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
        if (last_observer) {
            self.ptr.external_side_destroy();
        }
    }
};

pub const Worker = struct {
    work_group_ref: *WorkGroup,
    thread: ?std.Thread,
    futex_wake_object: atomic.Atomic(u32),
    worker_index: u32,
    exported_worker_local_data: ?*WorkerExportData,
    shared_task_pack: TaskPackPtr,
    flags: struct {
        was_started: bool,
    },

    pub fn init_defaults(self:*@This()) void {
        self.thread = null;
        self.futex_wake_object.store(@intFromEnum(WorkerSignal.None), AtomicOrder.Monotonic);
        self.exported_worker_local_data = null;
        self.shared_task_pack.set_null();
        @atomicStore(bool, &self.flags.was_started, false, AtomicOrder.Monotonic);
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
            const signal: WorkerSignal = @enumFromInt(
                self.futex_wake_object.load(AtomicOrder.Monotonic));
            switch (signal) {
                .Sleeping => { @fence(AtomicOrder.Acquire); return; },
                else => continue,
            }
        }
    }
    pub fn end_safe_sync_access(self:*@This()) void {
        self.futex_wake_object.store(
            @intFromEnum(WorkerSignal.WakeToWork), AtomicOrder.Release);
    }
    pub fn wakeup(self:*const @This()) void {
        std.Thread.Futex.wake(&self.futex_wake_object, 1);
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
};
const TaskPack = @Vector(16, u128);

const TaskPackPtr = packed struct {
    ptr: ptr.CompressedPtr(TaskPack, ptr.@"Byte amount fitting within 48 bit address space", true),
    item_count: u16,

    fn set_arr(
        self:*@This(),
        ptr_ : *[16]Task,
        item_count: u16
    ) void {
        var ptr__ : @TypeOf(self.ptr)= undefined;
        ptr__.set(@alignCast(@ptrCast(ptr_)));
        self.ptr = ptr__;
        self.item_count = item_count;
    }
    fn set_null(self:*@This()) void {
        var ptr_ : @TypeOf(self.ptr) = undefined;
        ptr_.set_null();
        self.ptr = ptr_;
        self.item_count = 0;
    }
    fn is_null(self:*const @This()) bool {
        return self.ptr.is_null();
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
const OutlinerMtd = packed struct {
    occupation_map: u64, // 0 taken , 1 free
    next_page: ?*anyopaque
};
const OutlinerPage = GenericPageWMtd(OutlinerMtd);
comptime {
    if(@alignOf(OutlinerPage) != @alignOf(GenericPage)) {
        // @compileLog("Incorrect alignment");
    }
}
const Outliner = struct {
    first_page: ptr.Ptr(OutlinerPage, true),
    current_page: ptr.Ptr(OutlinerPage, true),
    write_head: ptr.Ptr(TaskPack, true),

    fn init(self:*@This()) void {
        self.first_page.set_null();
        self.current_page.set_null();
        self.current_page.set_null();
    }
    fn all_free_map() u64 {
        return ((@as(u64,1) << @intCast(@sizeOf(GenericPage) / @sizeOf(TaskPack))) - 1) ^ 1;
    }
    fn do_first_init(self:*@This(), page_provider: *InfailablePageProvider) !void {
        const page = try page_provider.get_page();
        const addr = @intFromPtr(page);
        self.current_page.addr = addr;
        self.first_page.addr = addr;
        self.write_head.addr = self.current_page.addr + @sizeOf(TaskPack);

        const header = &self.first_page.get().header;
        header.next_page = null;
        const map: u64 = @This().all_free_map();
        @atomicStore(
            u64,
            &header.occupation_map,
            map,
            AtomicOrder.Monotonic);
    }
    fn switch_page(self:*@This(), page_provider:*InfailablePageProvider) !void {
        const page: *OutlinerPage = @alignCast(@ptrCast(try page_provider.get_page()));
        self.current_page.get().header.next_page = page;
        const header = &page.header;
        header.next_page = null;
        const map: u64 = @This().all_free_map();
        @atomicStore(
            u64,
            &header.occupation_map,
            map,
            AtomicOrder.Monotonic);
        self.current_page.set(page);
        self.write_head.addr = self.current_page.addr + @sizeOf(TaskPack);
    }
    fn find_free_space(self:*@This(), page_provider: *InfailablePageProvider) !*[16]Task {
        if (self.first_page.is_null()) {
            try self.do_first_init(page_provider);
        }
        var page = self.first_page;
        while (true) {
            var header = page.get().header;
            const map = @atomicLoad(
                u64,
                &header.occupation_map,
                AtomicOrder.Monotonic);
            const free_index = @ctz(map);
            const no_space = free_index == 64;
            if (no_space) {
                if (header.next_page == null) {
                    try self.switch_page(page_provider);
                    page = self.current_page;
                    continue;
                } else {
                    page.set(@alignCast(@ptrCast(header.next_page.?)));
                    continue;
                }
            } else {
                const index = (self.write_head.addr - self.current_page.addr) / @sizeOf(TaskPack);
                const mask = ~(@as(u64,1) << @intCast(index));
                _ = @atomicRmw(
                    u64,
                    &self.current_page.get().header.occupation_map,
                    AtomicRmwOp.And,
                    mask,
                    AtomicOrder.Monotonic);
                var space = self.current_page.rebind_to(TaskPack);
                space.advance(index);
                return @ptrCast(space.get());
            }
        }
    }
};
const OutlineTasks = std.ArrayList(TaskPackPtr);
const TaskSet = struct {
    inline_tasks: commons.InlineQueue(Task, 16, @alignOf(TaskPack)),
    outline_tasks: OutlineTasks,
    outline_storage: Outliner,
    pack_ptr: ?*[16]Task,
    current_subindex: u16,

    fn init(self:*@This()) !void {
        self.inline_tasks.init();
        self.outline_tasks = try OutlineTasks.initCapacity(std.heap.page_allocator, 16);
        self.current_subindex = 0;
        self.pack_ptr = null;
    }
    // true if failed
    fn push(self:*@This(), task: Task, page_provider:*InfailablePageProvider) !void {
        const failed = self.inline_tasks.push_to_tail(task);
        if (failed) {
            if (self.pack_ptr == null) {
                self.pack_ptr = try self.outline_storage.find_free_space(page_provider);
            }
            self.pack_ptr.?[self.current_subindex] = task;
            const si = self.current_subindex + 1;
            if (si == 16) {
                var ptr_ : TaskPackPtr = undefined;
                ptr_.set_arr(self.pack_ptr.?, si);
                (try self.outline_tasks.addOne()).* = ptr_;
                self.pack_ptr = null;
                self.current_subindex = 0;
            } else {
                self.current_subindex = si;
            }
        }
    }
    fn pop(self:*@This()) ?Task {
        return self.inline_tasks.pop_from_head();
    }
    fn finish(self:*@This()) !void {
        if (self.pack_ptr != null) {
            var ptr_ : TaskPackPtr = undefined;
            ptr_.set_arr(self.pack_ptr.?, self.current_subindex);
            (try self.outline_tasks.addOne()).* = ptr_;
            self.pack_ptr = null;
            self.current_subindex = 0;
        }
    }
} ;
const TempData = struct {
    subtask_count: usize = 0,
    current_task: *Task,

    fn did_spawn_any_subtasks(self:*const @This()) bool {
        return self.subtask_count != 0;
    }
    fn reset(self:*@This()) void {
        self.subtask_count = 0;
    }
    fn init_defaults(self:*@This()) void {
        self.subtask_count = 0;
    }
};
pub const TaskContext = struct {
    export_data: *WorkerExportData,
    temp_data: *TempData,

    pub fn spawn_subtask(
        self: *const @This(),
        capture: anytype,
        operation: *const fn(*const TaskContext, *@TypeOf(capture)) Continuation
    ) !void {
        self.temp_data.subtask_count += 1;

        const Capture = @TypeOf(capture);
        var subtask: Task = undefined;
        const ptrs = try subtask.do_pre_init(
            @ptrCast(operation),
            &self.export_data.region_allocator,
            &self.export_data.some_provider,
            @alignOf(Capture),
            @sizeOf(Capture),
            .TaskResumer);
        @as(*Capture,@alignCast(@ptrCast(ptrs.data))).* = capture;
        const header = @as(
            *TaskFrame_TaskResumer,
            @alignCast(@ptrCast(ptrs.header)));
        header.parent_task_frame = self.temp_data.current_task.frame_ptr;
        @atomicStore(u64, &header.child_task_count, 0, .Monotonic);

        try self.export_data.task_set.push(subtask, &self.export_data.some_provider);
    }
};
pub const WorkerExportData = struct {
    region_allocator: RegionAllocator,
    some_provider: InfailablePageProvider,
    task_set: TaskSet,
};

const ActionType = enum {
    Then, Done
};
const FrameType = enum {
    Standalone, ThreadResumer, TaskResumer
};
const TaskFrame_CombinedView = packed struct {
    child_task_count: u64,
    park_task_metadata: TaskMetadata
};
const TaskFrame_Standalone = packed struct {
    child_task_count: u64,
    park_data: TaskMetadata
};
const TaskFrame_ThreadResumer = packed struct {
    child_task_count: u64,
    park_data: TaskMetadata,
    resume_flag: *atomic.Atomic(u32),
};
const TaskFrame_TaskResumer = packed struct {
    child_task_count: u64,
    park_data: TaskMetadata,
    parent_task_frame: OpaqueObjectRef,
};
comptime {
    const counterOffsetOk1 =
        @offsetOf(TaskFrame_Standalone, "child_task_count") ==
        @offsetOf(TaskFrame_ThreadResumer, "child_task_count");
    if (!counterOffsetOk1) @compileError("Invalid counter offset");
    const counterOffsetOk2 =
        @offsetOf(TaskFrame_Standalone, "child_task_count") ==
        @offsetOf(TaskFrame_TaskResumer, "child_task_count");
    if (!counterOffsetOk2) @compileError("Invalid counter offset");
}
const WorkerState = enum {
    Processing, Sleeping, WorkFinding
};
const WorkerSignal = enum(u32) {
    WakeToDie, WakeToWork, Sleeping, None
};

fn worker_processing_routine(worker: *Worker) void {

    @atomicStore(bool, &worker.flags.was_started, true, AtomicOrder.Monotonic);
    // const work_group = worker.work_group_ref;

    var export_context : WorkerExportData = undefined;
    worker.exported_worker_local_data = &export_context;

    export_context.region_allocator.init();
    export_context.task_set.init() catch @panic("failed init");

    export_context.some_provider = .{
        .failable_sources = &[_]SomeFailablePageProvider{},
        .infailable_source = &worker.work_group_ref.root_allocator
    };

    var temp_data : TempData = undefined;
    temp_data.init_defaults();

    const task_ctx : TaskContext = . {
        .export_data = &export_context,
        .temp_data = &temp_data
    };

    var current_task : Task = undefined;
    temp_data.current_task = &current_task;
    var state: WorkerState = .Sleeping;
    state_dispath:while (true) {
        switch (state) {
            .WorkFinding => {
                if (export_context.task_set.pop()) |task| {
                    current_task = task;
                    state = .Processing;
                    continue :state_dispath;
                }

                state = .Sleeping;
                continue :state_dispath;
            },
            .Processing => {
                const cont = current_task.load_continuation();
                const components = current_task.get_components();
                switch (cont.payload) {
                    .Then => |cont_| {
                        var action = @as(
                            *const fn (*const TaskContext, *anyopaque) Continuation,
                            @ptrCast(cont_.next_operation));
                        const continuation = action(&task_ctx, components.data_ptr);
                        current_task.store_continuation(continuation);
                        const subtask_count = temp_data.subtask_count;
                        if (subtask_count != 0) {
                            const header = @as(
                                *TaskFrame_CombinedView,
                                @alignCast(@ptrCast(components.header_ptr)));
                            @atomicStore(
                                u64,
                                &header.child_task_count,
                                subtask_count,
                                AtomicOrder.Monotonic);
                            header.park_task_metadata = current_task.metadata;
                            export_context.task_set.finish() catch @panic("oops");
                            const overfilled =
                                export_context.task_set.outline_tasks.items.len != 0;
                            if (overfilled) {
                                while (true) {
                                    const mix = worker.work_group_ref.try_find_unoccupied_index();
                                    if (mix) |ix| {
                                        const mitem = export_context.task_set.outline_tasks.popOrNull();
                                        if (mitem) |item| {
                                            const free_worker = worker.work_group_ref.get_worker_at_index(ix);
                                            free_worker.start() catch @panic("fix me");
                                            free_worker.begin_safe_sync_access();
                                            {
                                                free_worker.shared_task_pack = item;
                                            }
                                            free_worker.end_safe_sync_access();
                                            free_worker.wakeup();
                                        }else { break; }
                                    } else {break;}
                                }
                            }
                            temp_data.reset();
                            state = .WorkFinding;
                        }
                        continue :state_dispath;
                    },
                    .Done => {
                        switch (current_task.metadata.frame_layout) {
                            .ThreadResumer => {
                                const header = @as(
                                    *TaskFrame_ThreadResumer,
                                    @alignCast(@ptrCast(components.header_ptr)));
                                header.resume_flag.store(1, AtomicOrder.Monotonic);
                                std.Thread.Futex.wake(header.resume_flag, 1);
                                // release this task frame
                            },
                            .Standalone => {
                                @panic("todo");
                            },
                            .TaskResumer => {
                                const current_task_header = @as(
                                    *TaskFrame_TaskResumer,
                                    @alignCast(@ptrCast(components.header_ptr)));
                                const parent_task_frame_ptr =
                                     current_task_header.parent_task_frame.get_data_ptr();
                                const parent_task_frame_ptr_ =
                                    @as(*TaskFrame_CombinedView,@ptrCast(@alignCast(parent_task_frame_ptr)));
                                const prior = @atomicRmw(
                                    u64,
                                    &parent_task_frame_ptr_.child_task_count,
                                    AtomicRmwOp.Sub,
                                    1,
                                    AtomicOrder.Release);
                                const last = prior == 1;
                                if (last) {
                                    @fence(AtomicOrder.Acquire);
                                    current_task.frame_ptr = current_task_header.parent_task_frame;
                                    current_task.metadata = parent_task_frame_ptr_.park_task_metadata;
                                    state = .Processing;
                                    continue :state_dispath;
                                } else {
                                    // dispose frame of self
                                }
                            }
                        }
                        state = .WorkFinding;
                        continue :state_dispath;
                    }
                }
            },
            .Sleeping => {
                const all_idle = worker.advertise_as_available();
                const outcome = @cmpxchgStrong(
                    u32,
                    &worker.work_group_ref.external_ref_count,
                    0,
                    0,
                    AtomicOrder.Monotonic,
                    AtomicOrder.Monotonic);
                const no_external_references = outcome == null;
                const time_to_shutdown = all_idle and no_external_references;
                if (time_to_shutdown) {
                    // there will be at least one external reference always active
                    // to join threads.
                    // dont forget to release resources
                    return;
                }
                const signal: u32 = @intFromEnum(WorkerSignal.Sleeping);
                worker.futex_wake_object.store(signal, AtomicOrder.Release);
                var signal_ : WorkerSignal = undefined;
                while (true) {
                    std.Thread.Futex.wait(&worker.futex_wake_object, signal);
                    signal_ = @enumFromInt(worker.futex_wake_object.load(.Monotonic));
                    if (signal_ != .Sleeping) break;
                }
                switch (signal_) {
                    .WakeToWork => {
                        @fence(AtomicOrder.Acquire);
                        state = .WorkFinding;
                        continue :state_dispath;
                    },
                    .WakeToDie => {
                        // this is basically goto to redo logic of this state
                        continue :state_dispath;
                    },
                    .Sleeping => unreachable,
                    .None => unreachable
                }
            }
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

    fn then(opeartion: anytype) @This() {
        const OpTy = @TypeOf(opeartion);
        comptime {
            if (!std.meta.trait.isSingleItemPtr(OpTy)) {
                @compileError("Expected function pointer, got " ++ @typeName(OpTy));
            }
        }
        comptime {
            const ti = @typeInfo(@typeInfo(OpTy).Pointer.child);
            switch (ti) {
                .Fn => |fun| {
                    if ((fun.return_type == null) or (fun.return_type.? != Continuation)) {
                        @compileError("Function has to return Continuation");
                    }
                    if (fun.params.len != 2) {
                        @compileError("Function has to take immutable pointer to TaskContext and pointer to capture");
                    }
                    if (fun.params[0].type.? != *const TaskContext) {
                        @compileError("First parameter have to be *const TaskContext");
                    }
                    if (!std.meta.trait.isSingleItemPtr(fun.params[1].type.?)) {
                        @compileError("Second parameter have to be pointer to captured data");
                    }
                },
                else => {
                    @compileError("Expected function pointer, got " ++ @typeName(OpTy));
                }
            }
        }
        const opaque_fun:
            *const fn (*const TaskContext, *anyopaque) Continuation = @ptrCast(opeartion);
        var this : @This() = undefined;
        this.payload = .{ .Then = .{.next_operation = opaque_fun} };
        return this;
    }
    fn done() @This() {
        var this : @This() = undefined;
        this.payload = .Done;
        return this;
    }
};
const TaskMetadata = packed struct(u64) {
    action_ptr: ptr.CompressedPtr(
        u8,
        ptr.@"Byte amount fitting within 48 bit address space",
        false),
    data_alignment_order: u8,
    frame_layout: FrameType,
    action_type: ActionType,
    _pad1: u5
};
const Task = packed struct {
    metadata: TaskMetadata,
    frame_ptr: OpaqueObjectRef,

    fn set_fun_ptr(self:*@This(), fptr: *const anyopaque) void {
        var ptr_ : ptr.CompressedPtr(
            u8,
            ptr.@"Byte amount fitting within 48 bit address space",
            false) = undefined;
        ptr_.set(@ptrCast(fptr));
        self.metadata.action_ptr = ptr_;
    }
    fn get_counter_ptr(self:@This()) *u64 {
        return @as(*u64,@alignCast(@ptrCast(self.frame_ptr.get_data_ptr())));
    }
    fn get_components(self:@This()) struct {
        header_ptr: *anyopaque,
        data_ptr: *anyopaque
    } {
        const frame_addr = @intFromPtr(self.frame_ptr.get_data_ptr());
        const header_size:usize = switch (self.metadata.frame_layout) {
            .Standalone => @sizeOf(TaskFrame_Standalone),
            .ThreadResumer => @sizeOf(TaskFrame_ThreadResumer),
            .TaskResumer => @sizeOf(TaskFrame_TaskResumer)
        };
        const past_header_addr = frame_addr + header_size;
        const align_order = self.metadata.data_alignment_order;
        const data_addr =
            if (align_order == 0) past_header_addr
            else std.mem.alignForward(
                usize, past_header_addr, @as(usize,1) << @intCast(align_order));
        return .{.header_ptr = @ptrFromInt(frame_addr), .data_ptr = @ptrFromInt(data_addr) };
    }
    fn do_pre_init(
        self:*@This(),
        operation: *const fn (*TaskContext, *anyopaque) Continuation,
        frame_allocator: *RegionAllocator,
        page_provider: *InfailablePageProvider,
        capture_align: usize,
        capture_size:usize,
        frame_type: FrameType
    ) !struct { header: *anyopaque, data: *anyopaque } {
        self.set_fun_ptr(@ptrCast(operation));
        self.metadata.action_type = ActionType.Then;
        self.metadata.frame_layout = frame_type;

        const task_frame_align : usize = switch (frame_type) {
            .Standalone => @alignOf(TaskFrame_Standalone),
            .ThreadResumer => @alignOf(TaskFrame_ThreadResumer),
            .TaskResumer => @alignOf(TaskFrame_TaskResumer)
        };
        var size : usize = switch (frame_type) {
            .Standalone => @sizeOf(TaskFrame_Standalone),
            .ThreadResumer => @sizeOf(TaskFrame_ThreadResumer),
            .TaskResumer => @sizeOf(TaskFrame_TaskResumer)
        };
        const aligned_for_data = std.mem.alignForward(usize, size, capture_align);
        const need_overalign = aligned_for_data - size != 0;
        self.metadata.data_alignment_order =
            if (need_overalign) @ctz(aligned_for_data) else 0 ;

        size += capture_size;

        const frame = try frame_allocator.alloc_bytes(size, task_frame_align, page_provider);
        self.frame_ptr = frame;

        const header_ptr: *anyopaque = frame.get_data_ptr();
        const data_ptr: *anyopaque = @ptrFromInt(@intFromPtr(header_ptr) + aligned_for_data);
        return .{ .header = header_ptr, .data = data_ptr };
    }
    fn store_continuation(self:*@This(), continuation: Continuation) void {
        switch (continuation.payload) {
            .Then => |next| {
                self.metadata.action_type = .Then;
                self.set_fun_ptr(next.next_operation);
            },
            .Done => {
                self.metadata.action_type = .Done;
            }
        }
    }
    fn load_continuation(self:*@This()) Continuation {
        var cont : Continuation = undefined;
        switch (self.metadata.action_type) {
            .Then => {
                const fun = @as(
                    *const fn (*const TaskContext, *anyopaque) Continuation,
                    @ptrCast(self.metadata.action_ptr.get()));
                cont.payload = .{ .Then = .{.next_operation = fun } };
            },
            .Done => {
                cont.payload = .Done;
            }
        }
        return cont;
    }
};
comptime {
    commons.ensure_exact_byte_size(Task, 16);
    if (@bitOffsetOf(Task, "metadata") != 0) @compileError("invalid position");
    if (@bitOffsetOf(Task, "frame_ptr") != 64) @compileError("invalid position");
}


test "ralocing" {
    var ralloc : RootAllocator = undefined;
    try ralloc.init(std.heap.page_allocator);

    var sralloc : RegionAllocator = undefined;
    sralloc.init();

    const hui = InfailablePageProvider {
        .failable_sources = .{},
        .infailable_source = &ralloc
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
    const text = "ahoy, maties!";
    const T = struct {
        fn run(_: *const TaskContext, capture: *@TypeOf(text)) Continuation {
            std.testing.expect(capture.* == text) catch @panic("fooo");
            // std.debug.print("{s}", .{capture.*});
            return Continuation { .payload = .Done };
        }
    };
    try wg.submit_task_and_await(text, T.run);
    wg.done_here();
}

test "wg subtasking" {
    const wg = try WorkGroup.new(std.heap.page_allocator);
    const Ty = [2]u32;
    const T = struct {
        fn run(ctx: *const TaskContext, fooo: **Ty) Continuation {
            for (fooo.*) |*item| {
                ctx.spawn_subtask(item,subtask) catch unreachable;
            }
            return Continuation.then(&finish);
        }
        fn subtask(_:*const TaskContext, data:**u32) Continuation {
            data.*.* = @as(u32,1);
            return Continuation.done();
        }
        fn finish(_:*const TaskContext, data: **Ty) Continuation {
            const data_: Ty = data.*.*;
            const data__ = Ty {1,1};
            const same = std.mem.eql(u32, &data_, &data__);
            std.testing.expect(same) catch @panic("oops");
            // std.debug.print("{any}", .{data_});
            return Continuation.done();
        }
    };
    var vals = Ty {0,0};
    try wg.submit_task_and_await(&vals, T.run);
    wg.done_here();
}