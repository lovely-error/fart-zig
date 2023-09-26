
const std = @import("std");

pub fn MemBlock(
    comptime block_alignment: comptime_int,
    comptime block_byte_size: comptime_int,
    comptime Header: type,
    comptime Item: type
) type {
    if (@sizeOf(Header) > block_byte_size)
        @panic("Header cannot be fit in given block size");
    if (@alignOf(Header) > block_alignment)
        @panic("Alignment of header is bigger then alignment of block");
    const item_count = (block_byte_size - @sizeOf(Header)) / @sizeOf(Item);
    const T = struct {
        header: Header align(block_alignment),
        items: [item_count]Item,
    };
    return T;
}

pub fn Outcome(comptime Ok: type, comptime Error: type) type {
    const T = packed struct { payload: packed union { success: Ok, failure: Error }, tag: enum(u2) {} };
    var fake: T = undefined;
    const OkPtrTy = comptime @TypeOf(&fake.payload.success);
    const ErrPtrTy = comptime @TypeOf(&fake.payload.failure);
    return packed struct {
        payload: packed union { success: Ok, failure: Error },
        tag: enum { success, failure },

        pub fn store_success(self: *@This(), success: Ok) void {
            self.payload.success = success;
            self.tag = .success;
        }
        pub fn store_failure(self: *@This(), failure: Error) void {
            self.payload.failure = failure;
            self.tag = .failure;
        }
        pub fn get_success_ref(self: *@This()) OkPtrTy {
            if (self.tag != .success) @panic("Attempt to interpret error as success");
            return &self.payload.success;
        }
        pub fn get_error_ref(self: *@This()) ErrPtrTy {
            if (self.tag != .failure) @panic("Attempt to interpret success as error");
            return &self.payload.failure;
        }
        pub fn contains_error(self: *const @This()) bool {
            return self.tag == .failure;
        }
    };
}

pub fn ensure_exact_byte_size(
    comptime T: type,
    comptime expected_size: comptime_int
) void {
    if (@sizeOf(T) != expected_size)
        @compileError(std.fmt.comptimePrint(
            "Expected size to be {} bytes, but its {} bytes actually",
            .{expected_size,@sizeOf(T)}));
}


pub fn InlineQueue(
    comptime Item: type,
    comptime capacity: usize,
    comptime overalign: ?usize
) type {
    return struct {
        head_index: usize,
        tail_index: usize,
        item_count: usize,
        items: [capacity]Item align(overalign orelse @alignOf(Item)),

        pub fn init(self:*@This()) void {
            self.head_index = 0;
            self.tail_index = 0;
            self.item_count = 0;
        }
        pub fn pop_from_head(self:*@This()) ?Item {
            if (self.item_count == 0) return null;
            const head_index = self.head_index;
            const item = self.items[head_index];
            const next_head = head_index + 1;
            self.head_index =
                if (next_head == capacity) 0
                else next_head;
            self.item_count -= 1;
            return item;
        }
        pub fn pop_from_tail(self:*@This()) ?Item {
            if (self.item_count == 0) return null;
            const tail_index = self.tail_index;
            const item = self.items[tail_index];
            self.tail_index =
                (if (tail_index == 0) capacity else tail_index) - 1;
            self.item_count -= 1;
            return item;
        }
        // true if insertion failed
        pub fn push_to_tail(self:*@This(), item:Item) bool {
            if (self.item_count == capacity) return true;
            const tail_index = self.tail_index;
            self.items[tail_index] = item;
            const next_tail = tail_index + 1;
            self.tail_index =
                if (next_tail == capacity) 0
                else next_tail;
            self.item_count += 1;
            return false;
        }
    };
}