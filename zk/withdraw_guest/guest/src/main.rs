#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // Implemented in a follow-up commit (core logic + input format + journal).
    // Keep the guest compiling while we build the core with strict TDD.
    let _: u32 = env::read();
    panic!("withdraw_guest not implemented");
}

