#![no_main]

use orchard::keys::OutgoingViewingKey;
use withdraw_guest_core::{
    prove_withdraw_batch, OrchardActionWitness, WithdrawItemWitness, MAX_WITHDRAW_ITEMS,
};

sp1_zkvm::entrypoint!(main);

fn main() {
    let private_input = sp1_zkvm::io::read_vec();
    let input = read_input(&private_input);
    let ovk = OutgoingViewingKey::from(input.owallet_ovk_bytes);

    let journal = prove_withdraw_batch(
        input.final_orchard_root,
        input.base_chain_id,
        input.bridge_contract,
        &ovk,
        &input.items,
    )
    .expect("prove_withdraw_batch failed");

    sp1_zkvm::io::commit_slice(&journal);
}

struct Input {
    final_orchard_root: [u8; 32],
    base_chain_id: u32,
    bridge_contract: [u8; 20],
    owallet_ovk_bytes: [u8; 32],
    items: Vec<WithdrawItemWitness>,
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_exact(&mut self, n: usize) -> &'a [u8] {
        let end = self.offset + n;
        if end > self.data.len() {
            panic!("short private input");
        }
        let out = &self.data[self.offset..end];
        self.offset = end;
        out
    }

    fn read_u32_le(&mut self) -> u32 {
        let bytes = self.read_exact(4);
        u32::from_le_bytes(bytes.try_into().expect("u32 bytes"))
    }

    fn read_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(self.read_exact(N));
        out
    }

    fn finish(self) {
        if self.offset != self.data.len() {
            panic!("unexpected trailing private input bytes");
        }
    }
}

fn read_input(data: &[u8]) -> Input {
    let mut cursor = Cursor::new(data);

    let final_orchard_root = cursor.read_array::<32>();
    let base_chain_id = cursor.read_u32_le();
    let bridge_contract = cursor.read_array::<20>();
    let owallet_ovk_bytes = cursor.read_array::<32>();

    let n = cursor.read_u32_le() as usize;
    if n > MAX_WITHDRAW_ITEMS {
        panic!("too many withdraw items");
    }

    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        items.push(read_item(&mut cursor));
    }

    cursor.finish();

    Input {
        final_orchard_root,
        base_chain_id,
        bridge_contract,
        owallet_ovk_bytes,
        items,
    }
}

fn read_item(cursor: &mut Cursor<'_>) -> WithdrawItemWitness {
    let withdrawal_id = cursor.read_array::<32>();
    let recipient_raw_address = cursor.read_array::<43>();
    let leaf_index = cursor.read_u32_le();

    let mut auth_path = [[0u8; 32]; 32];
    for hash in auth_path.iter_mut() {
        *hash = cursor.read_array::<32>();
    }

    let action = read_action(cursor);

    WithdrawItemWitness {
        withdrawal_id,
        recipient_raw_address,
        leaf_index,
        auth_path,
        action,
    }
}

fn read_action(cursor: &mut Cursor<'_>) -> OrchardActionWitness {
    OrchardActionWitness {
        nf_bytes: cursor.read_array::<32>(),
        rk_bytes: cursor.read_array::<32>(),
        cmx_bytes: cursor.read_array::<32>(),
        epk_bytes: cursor.read_array::<32>(),
        enc_ciphertext: cursor.read_array::<580>(),
        out_ciphertext: cursor.read_array::<80>(),
        cv_net_bytes: cursor.read_array::<32>(),
    }
}
