#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use orchard::keys::OutgoingViewingKey;
use risc0_zkvm::guest::env;
use withdraw_guest_core::{
    prove_withdraw_batch, OrchardActionWitness, WithdrawItemWitness, MAX_WITHDRAW_ITEMS,
};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input = read_input();
    let ovk = OutgoingViewingKey::from(input.owallet_ovk_bytes);

    let journal = prove_withdraw_batch(
        input.final_orchard_root,
        input.base_chain_id,
        input.bridge_contract,
        &ovk,
        &input.items,
    )
    .expect("prove_withdraw_batch failed");

    env::commit_slice(&journal);
}

struct Input {
    final_orchard_root: [u8; 32],
    base_chain_id: u32,
    bridge_contract: [u8; 20],
    owallet_ovk_bytes: [u8; 32],
    items: Vec<WithdrawItemWitness>,
}

fn read_input() -> Input {
    let mut final_orchard_root = [0u8; 32];
    env::read_slice(&mut final_orchard_root);

    let base_chain_id: u32 = env::read();

    let mut bridge_contract = [0u8; 20];
    env::read_slice(&mut bridge_contract);

    let mut owallet_ovk_bytes = [0u8; 32];
    env::read_slice(&mut owallet_ovk_bytes);

    let n: u32 = env::read();
    if (n as usize) > MAX_WITHDRAW_ITEMS {
        panic!("too many withdraw items");
    }

    let mut items = Vec::with_capacity(n as usize);
    for _ in 0..n {
        items.push(read_item());
    }

    Input {
        final_orchard_root,
        base_chain_id,
        bridge_contract,
        owallet_ovk_bytes,
        items,
    }
}

fn read_item() -> WithdrawItemWitness {
    let mut withdrawal_id = [0u8; 32];
    env::read_slice(&mut withdrawal_id);

    let mut recipient_raw_address = [0u8; 43];
    env::read_slice(&mut recipient_raw_address);

    let leaf_index: u32 = env::read();

    let mut auth_path = [[0u8; 32]; 32];
    env::read_slice(&mut auth_path);

    let action = read_action();

    WithdrawItemWitness {
        withdrawal_id,
        recipient_raw_address,
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
