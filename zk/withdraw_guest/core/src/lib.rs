#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use crc32fast::Hasher as Crc32;
use tiny_keccak::{Hasher as _, Keccak};

pub const MEMO_LEN: usize = 512;

const WITHDRAWAL_MAGIC_V1: [u8; 8] = [b'W', b'J', b'U', b'N', b'O', b'W', b'D', 0x01];

const WITHDRAWAL_V1_CRC_OFFSET: usize = 100;
const WITHDRAWAL_V1_PADDING_OFFSET: usize = 104;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoError {
    InvalidLength { got: usize },
    InvalidMagic,
    DomainMismatch,
    InvalidChecksum { want: u32, have: u32 },
    NonZeroPadding,
}

impl fmt::Display for MemoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoError::InvalidLength { got } => write!(f, "invalid memo length: got {got} want {MEMO_LEN}"),
            MemoError::InvalidMagic => write!(f, "invalid memo magic"),
            MemoError::DomainMismatch => write!(f, "memo domain mismatch"),
            MemoError::InvalidChecksum { want, have } => {
                write!(f, "invalid memo checksum: want 0x{want:08x} have 0x{have:08x}")
            }
            MemoError::NonZeroPadding => write!(f, "non-zero memo padding"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for MemoError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalMemoV1 {
    pub base_chain_id: u32,
    pub bridge_addr: [u8; 20],
    pub withdrawal_id: [u8; 32],
    pub batch_id: [u8; 32],
    pub flags: u32,
}

impl WithdrawalMemoV1 {
    /// Canonical 512-byte WithdrawalMemo v1 encoding.
    ///
    /// Spec (all integers big-endian):
    ///
    /// MAGIC[8] = "WJUNOWD\x01"
    /// baseChainId[4]
    /// bridgeAddr[20]
    /// withdrawalId[32]
    /// batchId[32]
    /// flags[4]
    /// crc32[4] over everything above (IEEE)
    /// padding[408] = zeros
    pub fn encode(&self) -> [u8; MEMO_LEN] {
        let mut out = [0u8; MEMO_LEN];

        let mut o = 0;
        out[o..o + 8].copy_from_slice(&WITHDRAWAL_MAGIC_V1);
        o += 8;
        out[o..o + 4].copy_from_slice(&self.base_chain_id.to_be_bytes());
        o += 4;
        out[o..o + 20].copy_from_slice(&self.bridge_addr);
        o += 20;
        out[o..o + 32].copy_from_slice(&self.withdrawal_id);
        o += 32;
        out[o..o + 32].copy_from_slice(&self.batch_id);
        o += 32;
        out[o..o + 4].copy_from_slice(&self.flags.to_be_bytes());

        // CRC covers bytes [0:WITHDRAWAL_V1_CRC_OFFSET].
        let mut h = Crc32::new();
        h.update(&out[..WITHDRAWAL_V1_CRC_OFFSET]);
        let crc = h.finalize();
        out[WITHDRAWAL_V1_CRC_OFFSET..WITHDRAWAL_V1_CRC_OFFSET + 4].copy_from_slice(&crc.to_be_bytes());
        out
    }
}

pub fn parse_withdrawal_memo_v1(
    b: &[u8],
    expected_base_chain_id: u32,
    expected_bridge_addr: [u8; 20],
) -> Result<WithdrawalMemoV1, MemoError> {
    if b.len() != MEMO_LEN {
        return Err(MemoError::InvalidLength { got: b.len() });
    }

    if b[..8] != WITHDRAWAL_MAGIC_V1 {
        return Err(MemoError::InvalidMagic);
    }

    let want_crc = u32::from_be_bytes(
        b[WITHDRAWAL_V1_CRC_OFFSET..WITHDRAWAL_V1_CRC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let mut h = Crc32::new();
    h.update(&b[..WITHDRAWAL_V1_CRC_OFFSET]);
    let have_crc = h.finalize();
    if want_crc != have_crc {
        return Err(MemoError::InvalidChecksum {
            want: want_crc,
            have: have_crc,
        });
    }

    if b[WITHDRAWAL_V1_PADDING_OFFSET..].iter().any(|&v| v != 0) {
        return Err(MemoError::NonZeroPadding);
    }

    let base_chain_id = u32::from_be_bytes(b[8..12].try_into().unwrap());
    if base_chain_id != expected_base_chain_id {
        return Err(MemoError::DomainMismatch);
    }

    let bridge_addr: [u8; 20] = b[12..32].try_into().unwrap();
    if bridge_addr != expected_bridge_addr {
        return Err(MemoError::DomainMismatch);
    }

    let withdrawal_id: [u8; 32] = b[32..64].try_into().unwrap();
    let batch_id: [u8; 32] = b[64..96].try_into().unwrap();
    let flags = u32::from_be_bytes(b[96..100].try_into().unwrap());

    Ok(WithdrawalMemoV1 {
        base_chain_id,
        bridge_addr,
        withdrawal_id,
        batch_id,
        flags,
    })
}

pub const MAX_WITHDRAW_ITEMS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizeItem {
    pub withdrawal_id: [u8; 32],
    pub recipient_ua_hash: [u8; 32],
    pub net_amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WithdrawError {
    TooManyItems { got: usize },
    InvalidNullifier,
    InvalidRk,
    InvalidCmx,
    InvalidCvNet,
    InvalidMerkleHash,
    RootMismatch,
    OutputRecoveryFailed,
    RecipientMismatch,
    WithdrawalIdMismatch,
    Memo(MemoError),
}

impl fmt::Display for WithdrawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WithdrawError::TooManyItems { got } => {
                write!(f, "too many withdraw items: got {got} max {MAX_WITHDRAW_ITEMS}")
            }
            WithdrawError::InvalidNullifier => write!(f, "invalid nullifier encoding"),
            WithdrawError::InvalidRk => write!(f, "invalid rk encoding"),
            WithdrawError::InvalidCmx => write!(f, "invalid cmx encoding"),
            WithdrawError::InvalidCvNet => write!(f, "invalid cv_net encoding"),
            WithdrawError::InvalidMerkleHash => write!(f, "invalid Merkle hash encoding"),
            WithdrawError::RootMismatch => write!(f, "merkle root mismatch"),
            WithdrawError::OutputRecoveryFailed => write!(f, "output recovery failed"),
            WithdrawError::RecipientMismatch => write!(f, "recipient mismatch"),
            WithdrawError::WithdrawalIdMismatch => write!(f, "withdrawal id mismatch"),
            WithdrawError::Memo(e) => write!(f, "memo invalid: {e}"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for WithdrawError {}

#[derive(Debug, Clone)]
pub struct OrchardActionWitness {
    pub nf_bytes: [u8; 32],
    pub rk_bytes: [u8; 32],
    pub cmx_bytes: [u8; 32],
    pub epk_bytes: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub cv_net_bytes: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct WithdrawItemWitness {
    pub withdrawal_id: [u8; 32],
    pub recipient_raw_address: [u8; 43],
    pub leaf_index: u32,
    pub auth_path: [[u8; 32]; 32],
    pub action: OrchardActionWitness,
}

impl OrchardActionWitness {
    fn to_action(&self) -> Result<orchard::Action<()>, WithdrawError> {
        use orchard::{
            note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
            primitives::redpallas::{SpendAuth, VerificationKey},
            value::ValueCommitment,
        };

        let nf = Option::from(Nullifier::from_bytes(&self.nf_bytes)).ok_or(WithdrawError::InvalidNullifier)?;
        let rk = VerificationKey::<SpendAuth>::try_from(self.rk_bytes).map_err(|_| WithdrawError::InvalidRk)?;
        let cmx =
            Option::from(ExtractedNoteCommitment::from_bytes(&self.cmx_bytes)).ok_or(WithdrawError::InvalidCmx)?;
        let cv_net = Option::from(ValueCommitment::from_bytes(&self.cv_net_bytes)).ok_or(WithdrawError::InvalidCvNet)?;

        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: self.epk_bytes,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
        };

        Ok(orchard::Action::from_parts(nf, rk, cmx, encrypted_note, cv_net, ()))
    }
}

pub fn verify_withdraw_item(
    expected_final_orchard_root: [u8; 32],
    expected_base_chain_id: u32,
    expected_bridge_contract: [u8; 20],
    ovk: &orchard::keys::OutgoingViewingKey,
    item: &WithdrawItemWitness,
) -> Result<FinalizeItem, WithdrawError> {
    use orchard::{
        note_encryption::OrchardDomain,
        tree::{MerkleHashOrchard, MerklePath},
    };

    let action = item.action.to_action()?;

    let default =
        Option::from(MerkleHashOrchard::from_bytes(&[0u8; 32])).ok_or(WithdrawError::InvalidMerkleHash)?;
    let mut auth_path = [default; 32];
    for (i, h_bytes) in item.auth_path.iter().enumerate() {
        auth_path[i] =
            Option::from(MerkleHashOrchard::from_bytes(h_bytes)).ok_or(WithdrawError::InvalidMerkleHash)?;
    }

    let mp = MerklePath::from_parts(item.leaf_index, auth_path);
    let anchor = mp.root(*action.cmx());
    if anchor.to_bytes() != expected_final_orchard_root {
        return Err(WithdrawError::RootMismatch);
    }

    let domain = OrchardDomain::for_action(&action);
    let (note, to, memo) = zcash_note_encryption::try_output_recovery_with_ovk(
        &domain,
        ovk,
        &action,
        action.cv_net(),
        &item.action.out_ciphertext,
    )
    .ok_or(WithdrawError::OutputRecoveryFailed)?;

    if to.to_raw_address_bytes() != item.recipient_raw_address {
        return Err(WithdrawError::RecipientMismatch);
    }

    let wm = parse_withdrawal_memo_v1(&memo, expected_base_chain_id, expected_bridge_contract)
        .map_err(WithdrawError::Memo)?;
    if wm.withdrawal_id != item.withdrawal_id {
        return Err(WithdrawError::WithdrawalIdMismatch);
    }

    Ok(FinalizeItem {
        withdrawal_id: item.withdrawal_id,
        recipient_ua_hash: keccak256(&item.recipient_raw_address),
        net_amount: note.value().inner(),
    })
}

pub fn prove_withdraw_batch(
    expected_final_orchard_root: [u8; 32],
    expected_base_chain_id: u32,
    expected_bridge_contract: [u8; 20],
    ovk: &orchard::keys::OutgoingViewingKey,
    items: &[WithdrawItemWitness],
) -> Result<Vec<u8>, WithdrawError> {
    if items.len() > MAX_WITHDRAW_ITEMS {
        return Err(WithdrawError::TooManyItems { got: items.len() });
    }

    let mut finalize_items = Vec::with_capacity(items.len());
    for item in items {
        finalize_items.push(verify_withdraw_item(
            expected_final_orchard_root,
            expected_base_chain_id,
            expected_bridge_contract,
            ovk,
            item,
        )?);
    }

    Ok(abi_encode_withdraw_journal(
        expected_final_orchard_root,
        expected_base_chain_id,
        expected_bridge_contract,
        &finalize_items,
    ))
}

fn keccak256(b: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(b);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Solidity `abi.encode(Bridge.WithdrawJournal)`.
pub fn abi_encode_withdraw_journal(
    final_orchard_root: [u8; 32],
    base_chain_id: u32,
    bridge_contract: [u8; 20],
    items: &[FinalizeItem],
) -> Vec<u8> {
    let n = items.len();
    // Outer: offset (32) + inner tuple:
    // head (4*32) + array len (32) + items (n*96).
    let inner_len = 4 * 32 + 32 + n * (3 * 32);
    let mut out = Vec::with_capacity(32 + inner_len);

    // Outer head: offset to inner tuple (0x20).
    out.extend_from_slice(&u256_from_u64(32));

    // Inner tuple head.
    out.extend_from_slice(&final_orchard_root);
    out.extend_from_slice(&u256_from_u64(base_chain_id as u64));
    out.extend_from_slice(&abi_encode_address(bridge_contract));
    out.extend_from_slice(&u256_from_u64((4 * 32) as u64)); // offset to items array

    // Inner tuple tail: items array.
    out.extend_from_slice(&u256_from_u64(n as u64));
    for it in items {
        out.extend_from_slice(&it.withdrawal_id);
        out.extend_from_slice(&it.recipient_ua_hash);
        out.extend_from_slice(&u256_from_u64(it.net_amount));
    }

    out
}

fn u256_from_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

fn abi_encode_address(addr: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&addr);
    out
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> std::vec::Vec<u8> {
        let s = s.trim();

        // Accept optional whitespace and optional "0x" prefix (handy for vectors copied
        // from tool output).
        let mut hex: std::vec::Vec<u8> = s
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if hex.len() >= 2 && hex[0] == b'0' && (hex[1] == b'x' || hex[1] == b'X') {
            hex.drain(..2);
        }

        assert!(hex.len() % 2 == 0, "hex length must be even");
        let mut out = std::vec::Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let hi = from_hex_nibble(hex[i]).unwrap();
            let lo = from_hex_nibble(hex[i + 1]).unwrap();
            out.push((hi << 4) | lo);
        }
        out
    }

    fn from_hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    #[test]
    fn withdrawal_memo_v1_golden_roundtrips() {
        let golden =
            decode_hex(include_str!("../../../../internal/memo/testdata/withdrawal_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        let got = parse_withdrawal_memo_v1(&golden, CHAIN_ID, bridge).unwrap();
        assert_eq!(got.base_chain_id, CHAIN_ID);
        assert_eq!(got.bridge_addr, bridge);
        assert_eq!(
            got.withdrawal_id,
            hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
        assert_eq!(
            got.batch_id,
            hex32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        );
        assert_eq!(got.flags, 0x1122_3344);

        let enc = got.encode();
        assert_eq!(enc.as_slice(), golden.as_slice());
    }

    #[test]
    fn withdrawal_memo_v1_rejects_invalid_length() {
        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");
        let err = parse_withdrawal_memo_v1(&[], CHAIN_ID, bridge).unwrap_err();
        assert!(matches!(err, MemoError::InvalidLength { .. }));
    }

    #[test]
    fn withdrawal_memo_v1_rejects_invalid_magic() {
        let mut golden =
            decode_hex(include_str!("../../../../internal/memo/testdata/withdrawal_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        golden[0] ^= 0xff;
        let err = parse_withdrawal_memo_v1(&golden, CHAIN_ID, bridge).unwrap_err();
        assert_eq!(err, MemoError::InvalidMagic);
    }

    #[test]
    fn withdrawal_memo_v1_rejects_domain_mismatch() {
        let golden =
            decode_hex(include_str!("../../../../internal/memo/testdata/withdrawal_v1_valid.hex"));
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        let err = parse_withdrawal_memo_v1(&golden, 1, bridge).unwrap_err();
        assert_eq!(err, MemoError::DomainMismatch);

        const CHAIN_ID: u32 = 8453;
        let wrong_bridge: [u8; 20] = hex20("0000000000000000000000000000000000000001");

        let err = parse_withdrawal_memo_v1(&golden, CHAIN_ID, wrong_bridge).unwrap_err();
        assert_eq!(err, MemoError::DomainMismatch);
    }

    #[test]
    fn withdrawal_memo_v1_rejects_invalid_checksum() {
        let mut golden =
            decode_hex(include_str!("../../../../internal/memo/testdata/withdrawal_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        // Flip a byte covered by the CRC.
        golden[40] ^= 0x01;

        let err = parse_withdrawal_memo_v1(&golden, CHAIN_ID, bridge).unwrap_err();
        assert!(matches!(err, MemoError::InvalidChecksum { .. }));
    }

    #[test]
    fn withdrawal_memo_v1_rejects_non_zero_padding() {
        let mut golden =
            decode_hex(include_str!("../../../../internal/memo/testdata/withdrawal_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        *golden.last_mut().unwrap() = 1;
        let err = parse_withdrawal_memo_v1(&golden, CHAIN_ID, bridge).unwrap_err();
        assert_eq!(err, MemoError::NonZeroPadding);
    }

    #[test]
    fn abi_encode_withdraw_journal_matches_vector() {
        let root = [0x11u8; 32];
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        let items = [FinalizeItem {
            withdrawal_id: [0x22u8; 32],
            recipient_ua_hash: [0x33u8; 32],
            net_amount: 100_000,
        }];

        let got = abi_encode_withdraw_journal(root, 8453, bridge, &items);
        let want = decode_hex(
            r#"
0x0000000000000000000000000000000000000000000000000000000000000020
1111111111111111111111111111111111111111111111111111111111111111
0000000000000000000000000000000000000000000000000000000000002105
0000000000000000000000001234567890abcdef1234567890abcdef12345678
0000000000000000000000000000000000000000000000000000000000000080
0000000000000000000000000000000000000000000000000000000000000001
2222222222222222222222222222222222222222222222222222222222222222
3333333333333333333333333333333333333333333333333333333333333333
00000000000000000000000000000000000000000000000000000000000186a0
"#,
        );

        assert_eq!(got, want);
    }

    #[test]
    fn prove_withdraw_batch_rejects_too_many_items() {
        use orchard::keys::OutgoingViewingKey;

        let dummy = WithdrawItemWitness {
            withdrawal_id: [0u8; 32],
            recipient_raw_address: [0u8; 43],
            leaf_index: 0,
            auth_path: [[0u8; 32]; 32],
            action: OrchardActionWitness {
                nf_bytes: [0u8; 32],
                rk_bytes: [0u8; 32],
                cmx_bytes: [0u8; 32],
                epk_bytes: [0u8; 32],
                enc_ciphertext: [0u8; 580],
                out_ciphertext: [0u8; 80],
                cv_net_bytes: [0u8; 32],
            },
        };

        let items = std::vec![dummy; MAX_WITHDRAW_ITEMS + 1];
        let ovk = OutgoingViewingKey::from([7u8; 32]);
        let err = prove_withdraw_batch([0u8; 32], 1, [0u8; 20], &ovk, &items).unwrap_err();
        assert_eq!(err, WithdrawError::TooManyItems { got: MAX_WITHDRAW_ITEMS + 1 });
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

    struct ValidWithdrawCase {
        chain_id: u32,
        bridge: [u8; 20],
        ovk: orchard::keys::OutgoingViewingKey,
        expected_root: [u8; 32],
        item: WithdrawItemWitness,
        amount: u64,
        recipient_raw: [u8; 43],
    }

    fn make_valid_case() -> ValidWithdrawCase {
        use orchard::{
            keys::{IncomingViewingKey, OutgoingViewingKey},
            note::{ExtractedNoteCommitment, Note, Rho},
            note_encryption::OrchardDomain,
            primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
            tree::{MerkleHashOrchard, MerklePath},
            value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
        };
        use zcash_note_encryption::NoteEncryption;

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");
        let withdrawal_id: [u8; 32] = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let batch_id: [u8; 32] = hex32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

        let ovk = OutgoingViewingKey::from([9u8; 32]);

        // Fixed, valid address for hermetic tests.
        let mut ivk_bytes = [0u8; 64];
        ivk_bytes[..32].copy_from_slice(&[7u8; 32]); // dk
        ivk_bytes[32] = 1; // ivk scalar (little-endian) = 1
        let ivk: IncomingViewingKey = Option::from(IncomingViewingKey::from_bytes(&ivk_bytes)).unwrap();

        let nf_bytes = le_u8_field(2);
        let rho = Option::from(Rho::from_bytes(&nf_bytes)).unwrap();
        let rseed = find_valid_rseed(&rho);

        let recipient = ivk.address_at(0u32);
        let recipient_raw = recipient.to_raw_address_bytes();

        let amount = 123_456u64;
        let note: Note =
            Option::from(Note::from_parts(recipient, NoteValue::from_raw(amount), rho, rseed)).unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let cmx_bytes = cmx.to_bytes();

        let memo = WithdrawalMemoV1 {
            base_chain_id: CHAIN_ID,
            bridge_addr: bridge,
            withdrawal_id,
            batch_id,
            flags: 0,
        }
        .encode();

        let ne = NoteEncryption::<OrchardDomain>::new(Some(ovk.clone()), note, memo);
        let enc_ciphertext = ne.encrypt_note_plaintext();
        let epk_bytes = <OrchardDomain as zcash_note_encryption::Domain>::epk_bytes(ne.epk()).0;

        let sk = SigningKey::<SpendAuth>::try_from(le_u8_scalar(5)).unwrap();
        let rk = VerificationKey::from(&sk);
        let rk_bytes: [u8; 32] = (&rk).into();

        let trapdoor = Option::from(ValueCommitTrapdoor::from_bytes([0u8; 32])).unwrap();
        let cv_net = ValueCommitment::derive(ValueSum::default(), trapdoor);
        let cv_net_bytes = cv_net.to_bytes();

        // `encrypt_outgoing_plaintext` only uses the RNG for `ovk = ⊥`, but requires it either way.
        let mut rng = ZeroRng;
        let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng);

        let leaf_index = 7u32;
        let auth_path_bytes = core::array::from_fn(|i| le_u8_field((i as u8).wrapping_add(10)));
        let auth_path_hashes = core::array::from_fn(|i| {
            Option::from(MerkleHashOrchard::from_bytes(&auth_path_bytes[i])).unwrap()
        });
        let mp = MerklePath::from_parts(leaf_index, auth_path_hashes);
        let expected_root = mp.root(cmx).to_bytes();

        let item = WithdrawItemWitness {
            withdrawal_id,
            recipient_raw_address: recipient_raw,
            leaf_index,
            auth_path: auth_path_bytes,
            action: OrchardActionWitness {
                nf_bytes,
                rk_bytes,
                cmx_bytes,
                epk_bytes,
                enc_ciphertext,
                out_ciphertext,
                cv_net_bytes,
            },
        };

        ValidWithdrawCase {
            chain_id: CHAIN_ID,
            bridge,
            ovk,
            expected_root,
            item,
            amount,
            recipient_raw,
        }
    }

    #[test]
    fn verify_withdraw_item_happy_path() {
        let c = make_valid_case();
        let got = verify_withdraw_item(c.expected_root, c.chain_id, c.bridge, &c.ovk, &c.item).unwrap();
        assert_eq!(got.withdrawal_id, c.item.withdrawal_id);
        assert_eq!(got.net_amount, c.amount);
        assert_eq!(got.recipient_ua_hash, keccak256(&c.recipient_raw));
    }

    #[test]
    fn verify_withdraw_item_rejects_wrong_root() {
        let c = make_valid_case();
        let mut wrong_root = c.expected_root;
        wrong_root[0] ^= 0x01;
        let err = verify_withdraw_item(wrong_root, c.chain_id, c.bridge, &c.ovk, &c.item).unwrap_err();
        assert_eq!(err, WithdrawError::RootMismatch);
    }

    #[test]
    fn verify_withdraw_item_rejects_wrong_recipient() {
        let c = make_valid_case();
        let mut bad = c.item.clone();
        bad.recipient_raw_address[0] ^= 0x01;
        let err = verify_withdraw_item(c.expected_root, c.chain_id, c.bridge, &c.ovk, &bad).unwrap_err();
        assert_eq!(err, WithdrawError::RecipientMismatch);
    }

    #[test]
    fn verify_withdraw_item_rejects_wrong_withdrawal_id() {
        let c = make_valid_case();
        let mut bad = c.item.clone();
        bad.withdrawal_id[0] ^= 0x01;
        let err = verify_withdraw_item(c.expected_root, c.chain_id, c.bridge, &c.ovk, &bad).unwrap_err();
        assert_eq!(err, WithdrawError::WithdrawalIdMismatch);
    }

    #[test]
    fn verify_withdraw_item_propagates_memo_domain_mismatch() {
        let c = make_valid_case();
        let err = verify_withdraw_item(c.expected_root, c.chain_id + 1, c.bridge, &c.ovk, &c.item).unwrap_err();
        assert_eq!(err, WithdrawError::Memo(MemoError::DomainMismatch));
    }

    fn keccak256(b: &[u8]) -> [u8; 32] {
        let mut h = Keccak::v256();
        h.update(b);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    }

    fn hex20(s: &str) -> [u8; 20] {
        let b = decode_hex(s);
        b.as_slice().try_into().unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let b = decode_hex(s);
        b.as_slice().try_into().unwrap()
    }

    fn le_u8_field(v: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = v;
        out
    }

    fn le_u8_scalar(v: u8) -> [u8; 32] {
        // Pallas scalar uses the same little-endian encoding as base elements.
        le_u8_field(v)
    }

    fn find_valid_rseed(rho: &orchard::note::Rho) -> orchard::note::RandomSeed {
        for i in 0u8..=u8::MAX {
            let mut rseed_bytes = [0u8; 32];
            rseed_bytes[0] = i;
            if let Some(rseed) = Option::from(orchard::note::RandomSeed::from_bytes(rseed_bytes, rho)) {
                return rseed;
            }
        }
        panic!("no valid rseed found");
    }
}
