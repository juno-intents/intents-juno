use anyhow::{anyhow, bail, Context, Result};
use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use orchard::keys::{FullViewingKey, Scope};
use std::env;

const HRP_JUNO_UFVK_PREFIX: &str = "jview";
const TYPECODE_ORCHARD: u64 = 3;
const ORCHARD_FVK_LEN: usize = 96;
const PADDING_LEN: usize = 16;

const BECH32_GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

pub enum Bech32mUnlimited {}

impl Checksum for Bech32mUnlimited {
    type MidstateRepr = u32;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = BECH32_GEN;
    const TARGET_RESIDUE: u32 = 0x2bc8_30a3;
}

fn read_compact_size(input: &mut &[u8]) -> Result<u64> {
    let first = *input.first().ok_or_else(|| anyhow!("tlv_invalid"))?;
    *input = &input[1..];

    match first {
        n @ 0..=252 => Ok(n as u64),
        253 => {
            if input.len() < 2 {
                bail!("tlv_invalid")
            }
            let v = u16::from_le_bytes([input[0], input[1]]) as u64;
            *input = &input[2..];
            Ok(v)
        }
        254 => {
            if input.len() < 4 {
                bail!("tlv_invalid")
            }
            let v = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as u64;
            *input = &input[4..];
            Ok(v)
        }
        255 => {
            if input.len() < 8 {
                bail!("tlv_invalid")
            }
            let v = u64::from_le_bytes([
                input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            ]);
            *input = &input[8..];
            Ok(v)
        }
    }
}

fn decode_zip316_bech32m(hrp_expected: &str, s: &str) -> Result<Vec<u8>> {
    let checked = CheckedHrpstring::new::<Bech32mUnlimited>(s).context("bech32_decode_failed")?;
    if checked.hrp().as_str() != hrp_expected {
        bail!("hrp_mismatch")
    }

    let mut bytes = checked.byte_iter().collect::<Vec<_>>();
    f4jumble::f4jumble_inv_mut(&mut bytes).context("f4jumble_failed")?;
    if bytes.len() < PADDING_LEN {
        bail!("padding_invalid")
    }

    let padding = &bytes[bytes.len() - PADDING_LEN..];
    if !padding[..hrp_expected.len()].eq(hrp_expected.as_bytes()) {
        bail!("padding_invalid")
    }
    if padding[hrp_expected.len()..].iter().any(|b| *b != 0) {
        bail!("padding_invalid")
    }

    bytes.truncate(bytes.len() - PADDING_LEN);
    Ok(bytes)
}

fn decode_tlv_container(hrp_expected: &str, s: &str) -> Result<Vec<(u64, Vec<u8>)>> {
    let bytes = decode_zip316_bech32m(hrp_expected, s)?;
    let mut rest = bytes.as_slice();
    let mut out = Vec::new();
    while !rest.is_empty() {
        let typecode = read_compact_size(&mut rest)?;
        let len = read_compact_size(&mut rest)? as usize;
        if rest.len() < len {
            bail!("tlv_invalid")
        }
        let (value, next) = rest.split_at(len);
        out.push((typecode, value.to_vec()));
        rest = next;
    }
    Ok(out)
}

fn parse_orchard_fvk_from_ufvk(ufvk: &str) -> Result<FullViewingKey> {
    let ufvk = ufvk.trim();
    if ufvk.is_empty() {
        bail!("ufvk_invalid")
    }

    let (ufvk_hrp, _) = ufvk.split_once('1').ok_or_else(|| anyhow!("ufvk_invalid"))?;
    if !ufvk_hrp.starts_with(HRP_JUNO_UFVK_PREFIX) {
        bail!("ufvk_invalid")
    }

    let items = decode_tlv_container(ufvk_hrp, ufvk)?;
    let orchard_item = items
        .into_iter()
        .find(|(typecode, _)| *typecode == TYPECODE_ORCHARD)
        .ok_or_else(|| anyhow!("ufvk_missing_orchard_receiver"))?;

    if orchard_item.1.len() != ORCHARD_FVK_LEN {
        bail!("ufvk_orchard_fvk_len_invalid")
    }

    let mut fvk_bytes = [0u8; ORCHARD_FVK_LEN];
    fvk_bytes.copy_from_slice(&orchard_item.1);
    FullViewingKey::from_bytes(&fvk_bytes).ok_or_else(|| anyhow!("ufvk_orchard_fvk_bytes_invalid"))
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let ufvk = args
        .next()
        .ok_or_else(|| anyhow!("usage: ufvk-derive-keys <ufvk>"))?;

    let fvk = parse_orchard_fvk_from_ufvk(&ufvk)?;
    let ivk_external = fvk.to_ivk(Scope::External);
    let ovk_external = fvk.to_ovk(Scope::External);

    let ivk_bytes = ivk_external.to_bytes();
    let ovk_bytes: [u8; 32] = *ovk_external.as_ref();

    println!("SP1_DEPOSIT_OWALLET_IVK_HEX=0x{}", hex::encode(ivk_bytes));
    println!("SP1_WITHDRAW_OWALLET_OVK_HEX=0x{}", hex::encode(ovk_bytes));
    Ok(())
}
