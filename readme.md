This third itteration of a fiber runtime after I watched Naughty Dog's GDC talk about how they managed to increase throughput and effectively saturated ps4 hardware with work. Fiber in this sentence is meant to mean user-level managed concurency(suspendible tasks), this contrasts to system managed concurency(OS threads).

I though a bit more about that and found that effectively any problem can be presented as some variation of barebones code bellow

```rust
struct Task {
  capture: *mut (), // type erased ptr to owned data
  action: Action
}
enum Action {
  Thunk {
    continuation: fn (/*erased frame ptr*/*mut ()) -> Action
  },
  SpawnSubtasks {
    subtasks: Vec<Coro>,
    continuation: fn (*mut ()) -> Action
  },
  // Add here any suspension points you like
  RequestMemory {
    allocation_size: usize,
    continuation: fn (*mut (), SomeMemPtr) -> Action
  }
  Completed,
  // and so much more!
  // ...
}

// used like this

fn demo() -> Action {
  let sharable_items : Vec<Smth> ;
  let subtasks: Vec<Task> ;
  // make these thing above somehow.
  // subtasks can even capture data from an env!
  return Action::SpawnSubtasks { subtasks, continuation: |captured_data_ptr| {
    // oh, we are in a function again! can do anything.
    // all substasks are guaranted by the system that at this point to have
    // finished and their sideeffects can be observed in this function.
    // continue your work after subtasks have finished .
    return Action::RequestMemory {
      allocation_size: usize,
      continuation: |captured_data_ptr, allocated_mem_ref| {
        // use provided memory!
        // store into captures!
        // signal to the executor that this task have finished
        return Action::Completed
      }
    }
  }}
}

```

This structure can faithfully represent any programm in an os-like environment.
Then it is possible to build an evaluator for this object to do work of interest.

This approch has benefits like:
1. Concurency can be represented as work sharing, rather then work stealing, because it is based on explicitely suspendible tasks.
2. Concurency is structured (parent task does not need to poll children to know when they are completed). Children can look into parent's captured data.
3. OS syscalls need not to block calling thread (in the presense of io_uring or such). Tasks can be suspended instead, and resumed later when their requests to OS are fullfiled.
4. This approch seems to be fairly uninuversal to use with anything.


So in simple terms, you effectively define your own computation scheme for a seqeunce of steps, and an instance of executor which can both handle suspension/resumptions and computation. ~~A Monad!🫢~~



Real implementation, of course alters the appearance of this, but not essence.