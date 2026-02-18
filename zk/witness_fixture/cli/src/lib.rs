use deposit_guest_core::{
    DepositItemWitness, DepositMemoV1, OrchardActionWitness as DepositActionWitness,
};
use orchard::{
    keys::{IncomingViewingKey, OutgoingViewingKey},
    note::{ExtractedNoteCommitment, Note, Rho},
    note_encryption::OrchardDomain,
    primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
    tree::{MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
};
use zcash_note_encryption::NoteEncryption;

use withdraw_guest_core::{
    OrchardActionWitness as WithdrawActionWitness, WithdrawItemWitness, WithdrawalMemoV1,
};

pub const DEPOSIT_WITNESS_ITEM_LEN: usize = 4 + (32 * 32) + (32 * 5 + 580 + 80);
pub const WITHDRAW_WITNESS_ITEM_LEN: usize = 32 + 43 + 4 + (32 * 32) + (32 * 5 + 580 + 80);

const FIXED_LEAF_INDEX: u32 = 7;

#[derive(Debug, Clone, Copy)]
pub struct DepositFixtureParams {
    pub base_chain_id: u32,
    pub bridge_address: [u8; 20],
    pub base_recipient: [u8; 20],
    pub amount: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct WithdrawFixtureParams {
    pub base_chain_id: u32,
    pub bridge_address: [u8; 20],
    pub withdrawal_id: [u8; 32],
    pub net_amount: u64,
}

#[derive(Debug, Clone)]
pub struct DepositFixture {
    pub final_orchard_root: [u8; 32],
    pub deposit_id: [u8; 32],
    pub recipient_ua: [u8; 43],
    pub owallet_ivk: [u8; 64],
    pub witness_item: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WithdrawFixture {
    pub final_orchard_root: [u8; 32],
    pub recipient_ua: [u8; 43],
    pub owallet_ovk: [u8; 32],
    pub witness_item: Vec<u8>,
}

pub fn build_deposit_fixture(p: DepositFixtureParams) -> Result<DepositFixture, String> {
    let ivk_bytes = fixed_ivk_bytes();
    let ivk: IncomingViewingKey = Option::from(IncomingViewingKey::from_bytes(&ivk_bytes))
        .ok_or_else(|| "invalid fixed ivk bytes".to_string())?;
    let recipient = ivk.address_at(0u32);
    let recipient_ua = recipient.to_raw_address_bytes();

    let nf_bytes = le_u8_field(2);
    let rho = Option::from(Rho::from_bytes(&nf_bytes)).ok_or_else(|| "invalid rho".to_string())?;
    let rseed = find_valid_rseed(&rho).ok_or_else(|| "failed to find valid rseed".to_string())?;
    let note: Note = Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(p.amount),
        rho,
        rseed,
    ))
    .ok_or_else(|| "failed to build note".to_string())?;
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let cmx_bytes = cmx.to_bytes();

    let memo = DepositMemoV1 {
        base_chain_id: p.base_chain_id,
        bridge_addr: p.bridge_address,
        base_recipient: p.base_recipient,
        nonce: 0x0102_0304_0506_0708,
        flags: 0,
    }
    .encode();

    let ne = NoteEncryption::<OrchardDomain>::new(None, note, memo);
    let enc_ciphertext = ne.encrypt_note_plaintext();
    let epk_bytes = <OrchardDomain as zcash_note_encryption::Domain>::epk_bytes(ne.epk()).0;

    let rk_bytes = redpallas_rk_bytes()?;
    let cv_net_bytes = cv_net_bytes()?;
    let auth_path = auth_path_bytes();
    let root = compute_root(cmx, auth_path);
    let item = DepositItemWitness {
        leaf_index: FIXED_LEAF_INDEX,
        auth_path,
        action: DepositActionWitness {
            nf_bytes,
            rk_bytes,
            cmx_bytes,
            epk_bytes,
            enc_ciphertext,
            out_ciphertext: [0u8; 80],
            cv_net_bytes,
        },
    };
    let witness_item = encode_deposit_item(&item);
    if witness_item.len() != DEPOSIT_WITNESS_ITEM_LEN {
        return Err(format!(
            "deposit witness len={} want={}",
            witness_item.len(),
            DEPOSIT_WITNESS_ITEM_LEN
        ));
    }

    Ok(DepositFixture {
        final_orchard_root: root,
        deposit_id: deposit_guest_core::deposit_id(cmx_bytes, FIXED_LEAF_INDEX),
        recipient_ua,
        owallet_ivk: ivk_bytes,
        witness_item,
    })
}

pub fn build_withdraw_fixture(p: WithdrawFixtureParams) -> Result<WithdrawFixture, String> {
    let ivk_bytes = fixed_ivk_bytes();
    let ivk: IncomingViewingKey = Option::from(IncomingViewingKey::from_bytes(&ivk_bytes))
        .ok_or_else(|| "invalid fixed ivk bytes".to_string())?;
    let recipient = ivk.address_at(0u32);
    let recipient_ua = recipient.to_raw_address_bytes();
    let ovk_bytes = [9u8; 32];
    let ovk = OutgoingViewingKey::from(ovk_bytes);

    let nf_bytes = le_u8_field(2);
    let rho = Option::from(Rho::from_bytes(&nf_bytes)).ok_or_else(|| "invalid rho".to_string())?;
    let rseed = find_valid_rseed(&rho).ok_or_else(|| "failed to find valid rseed".to_string())?;
    let note: Note = Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(p.net_amount),
        rho,
        rseed,
    ))
    .ok_or_else(|| "failed to build note".to_string())?;
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let cmx_bytes = cmx.to_bytes();

    let memo = WithdrawalMemoV1 {
        base_chain_id: p.base_chain_id,
        bridge_addr: p.bridge_address,
        withdrawal_id: p.withdrawal_id,
        batch_id: fixed_batch_id(),
        flags: 0,
    }
    .encode();

    let ne = NoteEncryption::<OrchardDomain>::new(Some(ovk.clone()), note, memo);
    let enc_ciphertext = ne.encrypt_note_plaintext();
    let epk_bytes = <OrchardDomain as zcash_note_encryption::Domain>::epk_bytes(ne.epk()).0;

    let rk_bytes = redpallas_rk_bytes()?;
    let cv_net = cv_net()?;
    let cv_net_bytes = cv_net.to_bytes();
    let mut rng = ZeroRng;
    let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng);

    let auth_path = auth_path_bytes();
    let root = compute_root(cmx, auth_path);
    let item = WithdrawItemWitness {
        withdrawal_id: p.withdrawal_id,
        recipient_raw_address: recipient_ua,
        leaf_index: FIXED_LEAF_INDEX,
        auth_path,
        action: WithdrawActionWitness {
            nf_bytes,
            rk_bytes,
            cmx_bytes,
            epk_bytes,
            enc_ciphertext,
            out_ciphertext,
            cv_net_bytes,
        },
    };
    let witness_item = encode_withdraw_item(&item);
    if witness_item.len() != WITHDRAW_WITNESS_ITEM_LEN {
        return Err(format!(
            "withdraw witness len={} want={}",
            witness_item.len(),
            WITHDRAW_WITNESS_ITEM_LEN
        ));
    }

    Ok(WithdrawFixture {
        final_orchard_root: root,
        recipient_ua,
        owallet_ovk: ovk_bytes,
        witness_item,
    })
}

fn fixed_ivk_bytes() -> [u8; 64] {
    let mut ivk = [0u8; 64];
    ivk[..32].copy_from_slice(&[7u8; 32]);
    ivk[32] = 1;
    ivk
}

fn fixed_batch_id() -> [u8; 32] {
    core::array::from_fn(|i| (0x20u8).wrapping_add(i as u8))
}

fn redpallas_rk_bytes() -> Result<[u8; 32], String> {
    let sk =
        SigningKey::<SpendAuth>::try_from(le_u8_scalar(5)).map_err(|_| "invalid signing key")?;
    let rk = VerificationKey::from(&sk);
    Ok((&rk).into())
}

fn cv_net() -> Result<ValueCommitment, String> {
    let trapdoor = Option::from(ValueCommitTrapdoor::from_bytes([0u8; 32]))
        .ok_or_else(|| "invalid value commit trapdoor".to_string())?;
    Ok(ValueCommitment::derive(ValueSum::default(), trapdoor))
}

fn cv_net_bytes() -> Result<[u8; 32], String> {
    Ok(cv_net()?.to_bytes())
}

fn compute_root(cmx: ExtractedNoteCommitment, auth_path_bytes: [[u8; 32]; 32]) -> [u8; 32] {
    let auth_path_hashes = core::array::from_fn(|i| {
        Option::from(MerkleHashOrchard::from_bytes(&auth_path_bytes[i]))
            .expect("valid auth path hash")
    });
    let mp = MerklePath::from_parts(FIXED_LEAF_INDEX, auth_path_hashes);
    mp.root(cmx).to_bytes()
}

fn auth_path_bytes() -> [[u8; 32]; 32] {
    core::array::from_fn(|i| le_u8_field((i as u8).wrapping_add(10)))
}

fn le_u8_field(v: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = v;
    out
}

fn le_u8_scalar(v: u8) -> [u8; 32] {
    le_u8_field(v)
}

fn find_valid_rseed(rho: &orchard::note::Rho) -> Option<orchard::note::RandomSeed> {
    for i in 0u8..=u8::MAX {
        let mut rseed_bytes = [0u8; 32];
        rseed_bytes[0] = i;
        if let Some(rseed) = Option::from(orchard::note::RandomSeed::from_bytes(rseed_bytes, rho)) {
            return Some(rseed);
        }
    }
    None
}

struct ZeroRng;

impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn encode_deposit_item(item: &DepositItemWitness) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEPOSIT_WITNESS_ITEM_LEN);
    out.extend_from_slice(&item.leaf_index.to_le_bytes());
    for h in item.auth_path {
        out.extend_from_slice(&h);
    }
    out.extend_from_slice(&item.action.nf_bytes);
    out.extend_from_slice(&item.action.rk_bytes);
    out.extend_from_slice(&item.action.cmx_bytes);
    out.extend_from_slice(&item.action.epk_bytes);
    out.extend_from_slice(&item.action.enc_ciphertext);
    out.extend_from_slice(&item.action.out_ciphertext);
    out.extend_from_slice(&item.action.cv_net_bytes);
    out
}

fn encode_withdraw_item(item: &WithdrawItemWitness) -> Vec<u8> {
    let mut out = Vec::with_capacity(WITHDRAW_WITNESS_ITEM_LEN);
    out.extend_from_slice(&item.withdrawal_id);
    out.extend_from_slice(&item.recipient_raw_address);
    out.extend_from_slice(&item.leaf_index.to_le_bytes());
    for h in item.auth_path {
        out.extend_from_slice(&h);
    }
    out.extend_from_slice(&item.action.nf_bytes);
    out.extend_from_slice(&item.action.rk_bytes);
    out.extend_from_slice(&item.action.cmx_bytes);
    out.extend_from_slice(&item.action.epk_bytes);
    out.extend_from_slice(&item.action.enc_ciphertext);
    out.extend_from_slice(&item.action.out_ciphertext);
    out.extend_from_slice(&item.action.cv_net_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use deposit_guest_core::{
        DepositItemWitness, MintItem, abi_encode_deposit_journal, prove_deposit_batch,
    };
    use orchard::keys::{IncomingViewingKey, PreparedIncomingViewingKey};
    use tiny_keccak::Hasher as _;
    use withdraw_guest_core::{
        FinalizeItem, WithdrawItemWitness, abi_encode_withdraw_journal, prove_withdraw_batch,
    };

    #[test]
    fn deposit_fixture_round_trips_through_core_verifier() {
        let p = DepositFixtureParams {
            base_chain_id: 84532,
            bridge_address: [0x22; 20],
            base_recipient: [0x33; 20],
            amount: 100_000,
        };

        let fx = build_deposit_fixture(p).expect("build deposit fixture");
        assert_eq!(fx.witness_item.len(), DEPOSIT_WITNESS_ITEM_LEN);

        let ivk = Option::from(IncomingViewingKey::from_bytes(&fx.owallet_ivk)).expect("ivk bytes");
        let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);

        let item = decode_deposit_item(&fx.witness_item).expect("decode deposit witness item");
        let got = prove_deposit_batch(
            fx.final_orchard_root,
            p.base_chain_id,
            p.bridge_address,
            &prepared_ivk,
            &[item],
        )
        .expect("prove_deposit_batch");

        let want = abi_encode_deposit_journal(
            fx.final_orchard_root,
            p.base_chain_id,
            p.bridge_address,
            &[MintItem {
                deposit_id: fx.deposit_id,
                recipient: p.base_recipient,
                amount: p.amount,
            }],
        );
        assert_eq!(got, want);
    }

    #[test]
    fn withdraw_fixture_round_trips_through_core_verifier() {
        let p = WithdrawFixtureParams {
            base_chain_id: 84532,
            bridge_address: [0x22; 20],
            withdrawal_id: [0x44; 32],
            net_amount: 9_945,
        };

        let fx = build_withdraw_fixture(p).expect("build withdraw fixture");
        assert_eq!(fx.witness_item.len(), WITHDRAW_WITNESS_ITEM_LEN);

        let ovk = orchard::keys::OutgoingViewingKey::from(fx.owallet_ovk);
        let item = decode_withdraw_item(&fx.witness_item).expect("decode withdraw witness item");
        let got = prove_withdraw_batch(
            fx.final_orchard_root,
            p.base_chain_id,
            p.bridge_address,
            &ovk,
            &[item],
        )
        .expect("prove_withdraw_batch");

        let mut recipient_hash = [0u8; 32];
        let mut hasher = tiny_keccak::Keccak::v256();
        hasher.update(&fx.recipient_ua);
        hasher.finalize(&mut recipient_hash);

        let want = abi_encode_withdraw_journal(
            fx.final_orchard_root,
            p.base_chain_id,
            p.bridge_address,
            &[FinalizeItem {
                withdrawal_id: p.withdrawal_id,
                recipient_ua_hash: recipient_hash,
                net_amount: p.net_amount,
            }],
        );
        assert_eq!(got, want);
    }

    fn decode_deposit_item(b: &[u8]) -> Result<DepositItemWitness, String> {
        if b.len() != DEPOSIT_WITNESS_ITEM_LEN {
            return Err(format!(
                "deposit witness item len={} want={}",
                b.len(),
                DEPOSIT_WITNESS_ITEM_LEN
            ));
        }
        let mut o = 0usize;
        let leaf_index = u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        o += 4;
        let mut auth_path = [[0u8; 32]; 32];
        for slot in &mut auth_path {
            slot.copy_from_slice(&b[o..o + 32]);
            o += 32;
        }
        let mut nf_bytes = [0u8; 32];
        nf_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut rk_bytes = [0u8; 32];
        rk_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut cmx_bytes = [0u8; 32];
        cmx_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut epk_bytes = [0u8; 32];
        epk_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut enc_ciphertext = [0u8; 580];
        enc_ciphertext.copy_from_slice(&b[o..o + 580]);
        o += 580;
        let mut out_ciphertext = [0u8; 80];
        out_ciphertext.copy_from_slice(&b[o..o + 80]);
        o += 80;
        let mut cv_net_bytes = [0u8; 32];
        cv_net_bytes.copy_from_slice(&b[o..o + 32]);
        Ok(DepositItemWitness {
            leaf_index,
            auth_path,
            action: deposit_guest_core::OrchardActionWitness {
                nf_bytes,
                rk_bytes,
                cmx_bytes,
                epk_bytes,
                enc_ciphertext,
                out_ciphertext,
                cv_net_bytes,
            },
        })
    }

    fn decode_withdraw_item(b: &[u8]) -> Result<WithdrawItemWitness, String> {
        if b.len() != WITHDRAW_WITNESS_ITEM_LEN {
            return Err(format!(
                "withdraw witness item len={} want={}",
                b.len(),
                WITHDRAW_WITNESS_ITEM_LEN
            ));
        }
        let mut o = 0usize;
        let mut withdrawal_id = [0u8; 32];
        withdrawal_id.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut recipient_raw_address = [0u8; 43];
        recipient_raw_address.copy_from_slice(&b[o..o + 43]);
        o += 43;
        let leaf_index = u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        o += 4;
        let mut auth_path = [[0u8; 32]; 32];
        for slot in &mut auth_path {
            slot.copy_from_slice(&b[o..o + 32]);
            o += 32;
        }
        let mut nf_bytes = [0u8; 32];
        nf_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut rk_bytes = [0u8; 32];
        rk_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut cmx_bytes = [0u8; 32];
        cmx_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut epk_bytes = [0u8; 32];
        epk_bytes.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let mut enc_ciphertext = [0u8; 580];
        enc_ciphertext.copy_from_slice(&b[o..o + 580]);
        o += 580;
        let mut out_ciphertext = [0u8; 80];
        out_ciphertext.copy_from_slice(&b[o..o + 80]);
        o += 80;
        let mut cv_net_bytes = [0u8; 32];
        cv_net_bytes.copy_from_slice(&b[o..o + 32]);

        Ok(WithdrawItemWitness {
            withdrawal_id,
            recipient_raw_address,
            leaf_index,
            auth_path,
            action: withdraw_guest_core::OrchardActionWitness {
                nf_bytes,
                rk_bytes,
                cmx_bytes,
                epk_bytes,
                enc_ciphertext,
                out_ciphertext,
                cv_net_bytes,
            },
        })
    }
}
