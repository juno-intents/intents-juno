#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let journal_len: u32 = env::read();
    let mut journal = Vec::with_capacity(journal_len as usize);
    journal.resize(journal_len as usize, 0u8);
    env::read_slice(&mut journal);
    env::commit_slice(&journal);
}
