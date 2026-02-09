#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use deposit_guest_core::{
    prove_deposit_batch, DepositItemWitness, OrchardActionWitness, MAX_DEPOSIT_ITEMS,
};
use orchard::keys::{IncomingViewingKey, PreparedIncomingViewingKey};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

// Placeholder IncomingViewingKey bytes for development only.
//
// This MUST be replaced with the oWallet IncomingViewingKey derived from the operator
// keyset manifest (DKG output). The deposit image ID must commit to the correct keyset.
const OWALLET_IVK_BYTES: [u8; 64] = make_placeholder_ivk();

const fn make_placeholder_ivk() -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0usize;
    while i < 32 {
        out[i] = 7;
        i += 1;
    }
    // ivk scalar (little-endian) = 1
    out[32] = 1;
    out
}

fn main() {
    let input = read_input();

    let ivk = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(&OWALLET_IVK_BYTES))
        .expect("invalid IncomingViewingKey bytes");
    let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);

    let journal = prove_deposit_batch(
        input.final_orchard_root,
        input.base_chain_id,
        input.bridge_contract,
        &prepared_ivk,
        &input.items,
    )
    .expect("prove_deposit_batch failed");

    env::commit_slice(&journal);
}

struct Input {
    final_orchard_root: [u8; 32],
    base_chain_id: u32,
    bridge_contract: [u8; 20],
    items: Vec<DepositItemWitness>,
}

fn read_input() -> Input {
    let mut final_orchard_root = [0u8; 32];
    env::read_slice(&mut final_orchard_root);

    let base_chain_id: u32 = env::read();

    let mut bridge_contract = [0u8; 20];
    env::read_slice(&mut bridge_contract);

    let n: u32 = env::read();
    if (n as usize) > MAX_DEPOSIT_ITEMS {
        panic!("too many deposit items");
    }

    let mut items = Vec::with_capacity(n as usize);
    for _ in 0..n {
        items.push(read_item());
    }

    Input {
        final_orchard_root,
        base_chain_id,
        bridge_contract,
        items,
    }
}

fn read_item() -> DepositItemWitness {
    let leaf_index: u32 = env::read();

    let mut auth_path = [[0u8; 32]; 32];
    env::read_slice(&mut auth_path);

    let action = read_action();

    DepositItemWitness {
        leaf_index,
        auth_path,
        action,
    }
}

fn read_action() -> OrchardActionWitness {
    let mut nf_bytes = [0u8; 32];
    env::read_slice(&mut nf_bytes);

    let mut rk_bytes = [0u8; 32];
    env::read_slice(&mut rk_bytes);

    let mut cmx_bytes = [0u8; 32];
    env::read_slice(&mut cmx_bytes);

    let mut epk_bytes = [0u8; 32];
    env::read_slice(&mut epk_bytes);

    let mut enc_ciphertext = [0u8; 580];
    env::read_slice(&mut enc_ciphertext);

    let mut out_ciphertext = [0u8; 80];
    env::read_slice(&mut out_ciphertext);

    let mut cv_net_bytes = [0u8; 32];
    env::read_slice(&mut cv_net_bytes);

    OrchardActionWitness {
        nf_bytes,
        rk_bytes,
        cmx_bytes,
        epk_bytes,
        enc_ciphertext,
        out_ciphertext,
        cv_net_bytes,
    }
}

