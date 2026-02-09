#![no_std]

use core::fmt;

use crc32fast::Hasher as Crc32;
use tiny_keccak::{Hasher as _, Keccak};

pub const MEMO_LEN: usize = 512;

const DEPOSIT_MAGIC_V1: [u8; 8] = [b'W', b'J', b'U', b'N', b'O', 0x01, 0x00, 0x00];

const DEPOSIT_V1_CRC_OFFSET: usize = 64;
const DEPOSIT_V1_PADDING_OFFSET: usize = 68;

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
pub struct DepositMemoV1 {
    pub base_chain_id: u32,
    pub bridge_addr: [u8; 20],
    pub base_recipient: [u8; 20],
    pub nonce: u64,
    pub flags: u32,
}

impl DepositMemoV1 {
    /// Canonical 512-byte DepositMemo v1 encoding.
    ///
    /// Spec (all integers big-endian):
    ///
    /// MAGIC[8] = "WJUNO\x01\x00\x00"
    /// baseChainId[4]
    /// bridgeAddr[20]
    /// baseRecipient[20]
    /// nonce[8]
    /// flags[4]
    /// crc32[4] over everything above (IEEE)
    /// padding[444] = zeros
    pub fn encode(&self) -> [u8; MEMO_LEN] {
        let mut out = [0u8; MEMO_LEN];

        let mut o = 0;
        out[o..o + 8].copy_from_slice(&DEPOSIT_MAGIC_V1);
        o += 8;
        out[o..o + 4].copy_from_slice(&self.base_chain_id.to_be_bytes());
        o += 4;
        out[o..o + 20].copy_from_slice(&self.bridge_addr);
        o += 20;
        out[o..o + 20].copy_from_slice(&self.base_recipient);
        o += 20;
        out[o..o + 8].copy_from_slice(&self.nonce.to_be_bytes());
        o += 8;
        out[o..o + 4].copy_from_slice(&self.flags.to_be_bytes());

        // CRC covers bytes [0:DEPOSIT_V1_CRC_OFFSET].
        let mut h = Crc32::new();
        h.update(&out[..DEPOSIT_V1_CRC_OFFSET]);
        let crc = h.finalize();
        out[DEPOSIT_V1_CRC_OFFSET..DEPOSIT_V1_CRC_OFFSET + 4].copy_from_slice(&crc.to_be_bytes());
        out
    }
}

pub fn parse_deposit_memo_v1(
    b: &[u8],
    expected_base_chain_id: u32,
    expected_bridge_addr: [u8; 20],
) -> Result<DepositMemoV1, MemoError> {
    if b.len() != MEMO_LEN {
        return Err(MemoError::InvalidLength { got: b.len() });
    }

    if b[..8] != DEPOSIT_MAGIC_V1 {
        return Err(MemoError::InvalidMagic);
    }

    let want_crc = u32::from_be_bytes(b[DEPOSIT_V1_CRC_OFFSET..DEPOSIT_V1_CRC_OFFSET + 4].try_into().unwrap());
    let mut h = Crc32::new();
    h.update(&b[..DEPOSIT_V1_CRC_OFFSET]);
    let have_crc = h.finalize();
    if want_crc != have_crc {
        return Err(MemoError::InvalidChecksum {
            want: want_crc,
            have: have_crc,
        });
    }

    if b[DEPOSIT_V1_PADDING_OFFSET..].iter().any(|&v| v != 0) {
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

    let base_recipient: [u8; 20] = b[32..52].try_into().unwrap();
    let nonce = u64::from_be_bytes(b[52..60].try_into().unwrap());
    let flags = u32::from_be_bytes(b[60..64].try_into().unwrap());

    Ok(DepositMemoV1 {
        base_chain_id,
        bridge_addr,
        base_recipient,
        nonce,
        flags,
    })
}

/// `depositId = keccak256("deposit" || cmx || leafIndexBE32)`
pub fn deposit_id(cmx: [u8; 32], leaf_index: u32) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(b"deposit");
    h.update(&cmx);
    h.update(&leaf_index.to_be_bytes());
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> std::vec::Vec<u8> {
        let s = s.trim();
        assert!(s.len() % 2 == 0, "hex length must be even");
        let mut out = std::vec::Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        for i in (0..b.len()).step_by(2) {
            let hi = from_hex_nibble(b[i]).unwrap();
            let lo = from_hex_nibble(b[i + 1]).unwrap();
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
    fn deposit_memo_v1_golden_roundtrips() {
        let golden =
            decode_hex(include_str!("../../../internal/memo/testdata/deposit_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        let got = parse_deposit_memo_v1(&golden, CHAIN_ID, bridge).unwrap();
        assert_eq!(got.base_chain_id, CHAIN_ID);
        assert_eq!(got.bridge_addr, bridge);
        assert_eq!(
            got.base_recipient,
            hex20("90f8bf6a479f320ead074411a4b0e7944ea8c9c1")
        );
        assert_eq!(got.nonce, 0x0102_0304_0506_0708);
        assert_eq!(got.flags, 0xAABB_CCDD);

        let enc = got.encode();
        assert_eq!(enc.as_slice(), golden.as_slice());
    }

    #[test]
    fn deposit_memo_v1_rejects_invalid_length() {
        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");
        let err = parse_deposit_memo_v1(&[], CHAIN_ID, bridge).unwrap_err();
        assert!(matches!(err, MemoError::InvalidLength { .. }));
    }

    #[test]
    fn deposit_memo_v1_rejects_invalid_magic() {
        let mut golden =
            decode_hex(include_str!("../../../internal/memo/testdata/deposit_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        golden[0] ^= 0xff;
        let err = parse_deposit_memo_v1(&golden, CHAIN_ID, bridge).unwrap_err();
        assert_eq!(err, MemoError::InvalidMagic);
    }

    #[test]
    fn deposit_memo_v1_rejects_domain_mismatch() {
        let golden =
            decode_hex(include_str!("../../../internal/memo/testdata/deposit_v1_valid.hex"));
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        let err = parse_deposit_memo_v1(&golden, 1, bridge).unwrap_err();
        assert_eq!(err, MemoError::DomainMismatch);

        const CHAIN_ID: u32 = 8453;
        let wrong_bridge: [u8; 20] = hex20("0000000000000000000000000000000000000001");

        let err = parse_deposit_memo_v1(&golden, CHAIN_ID, wrong_bridge).unwrap_err();
        assert_eq!(err, MemoError::DomainMismatch);
    }

    #[test]
    fn deposit_memo_v1_rejects_invalid_checksum() {
        let mut golden =
            decode_hex(include_str!("../../../internal/memo/testdata/deposit_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        // Flip a byte covered by the CRC.
        golden[40] ^= 0x01;

        let err = parse_deposit_memo_v1(&golden, CHAIN_ID, bridge).unwrap_err();
        assert!(matches!(err, MemoError::InvalidChecksum { .. }));
    }

    #[test]
    fn deposit_memo_v1_rejects_non_zero_padding() {
        let mut golden =
            decode_hex(include_str!("../../../internal/memo/testdata/deposit_v1_valid.hex"));

        const CHAIN_ID: u32 = 8453;
        let bridge: [u8; 20] = hex20("1234567890abcdef1234567890abcdef12345678");

        *golden.last_mut().unwrap() = 1;
        let err = parse_deposit_memo_v1(&golden, CHAIN_ID, bridge).unwrap_err();
        assert_eq!(err, MemoError::NonZeroPadding);
    }

    #[test]
    fn deposit_id_matches_vector() {
        let cmx: [u8; 32] = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let leaf_index = 0x0102_0304;
        let got = deposit_id(cmx, leaf_index);
        let want: [u8; 32] = hex32("bc0d27e33687de6a88da7055aa24664601360166e373ebc9b7b7c22fe212c187");
        assert_eq!(got, want);
    }

    fn hex20(s: &str) -> [u8; 20] {
        let b = decode_hex(s);
        b.as_slice().try_into().unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let b = decode_hex(s);
        b.as_slice().try_into().unwrap()
    }
}

