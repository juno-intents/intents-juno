use std::{env, process};

use guest_witness_fixture::{
    DepositFixtureParams, WithdrawFixtureParams, build_deposit_fixture, build_withdraw_fixture,
};
use serde_json::json;

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let Some(cmd) = args.first().cloned() else {
        return Err(usage());
    };
    match cmd.as_str() {
        "deposit" => run_deposit(&args[1..]),
        "withdraw" => run_withdraw(&args[1..]),
        "-h" | "--help" => {
            println!("{}", usage());
            Ok(())
        }
        _ => Err(format!("unknown command {cmd}\n{}", usage())),
    }
}

fn run_deposit(args: &[String]) -> Result<(), String> {
    let base_chain_id = parse_u32_flag(args, "--base-chain-id")?;
    let bridge_address = parse_hex_fixed::<20>(args, "--bridge-address")?;
    let base_recipient = parse_hex_fixed::<20>(args, "--base-recipient")?;
    let amount = parse_u64_flag(args, "--amount")?;

    let fx = build_deposit_fixture(DepositFixtureParams {
        base_chain_id,
        bridge_address,
        base_recipient,
        amount,
    })?;

    let out = json!({
        "pipeline": "deposit",
        "base_chain_id": base_chain_id,
        "bridge_address": encode_hex(&bridge_address),
        "base_recipient": encode_hex(&base_recipient),
        "amount": amount.to_string(),
        "final_orchard_root": encode_hex(&fx.final_orchard_root),
        "deposit_id": encode_hex(&fx.deposit_id),
        "recipient_ua": encode_hex(&fx.recipient_ua),
        "owallet_ivk": encode_hex(&fx.owallet_ivk),
        "witness_item": encode_hex(&fx.witness_item),
    });
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| format!("serialize output: {e}"))?
    );
    Ok(())
}

fn run_withdraw(args: &[String]) -> Result<(), String> {
    let base_chain_id = parse_u32_flag(args, "--base-chain-id")?;
    let bridge_address = parse_hex_fixed::<20>(args, "--bridge-address")?;
    let withdrawal_id = parse_hex_fixed::<32>(args, "--withdrawal-id")?;
    let net_amount = parse_u64_flag(args, "--net-amount")?;

    let fx = build_withdraw_fixture(WithdrawFixtureParams {
        base_chain_id,
        bridge_address,
        withdrawal_id,
        net_amount,
    })?;

    let out = json!({
        "pipeline": "withdraw",
        "base_chain_id": base_chain_id,
        "bridge_address": encode_hex(&bridge_address),
        "withdrawal_id": encode_hex(&withdrawal_id),
        "net_amount": net_amount.to_string(),
        "final_orchard_root": encode_hex(&fx.final_orchard_root),
        "recipient_ua": encode_hex(&fx.recipient_ua),
        "owallet_ovk": encode_hex(&fx.owallet_ovk),
        "witness_item": encode_hex(&fx.witness_item),
    });
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| format!("serialize output: {e}"))?
    );
    Ok(())
}

fn parse_u32_flag(args: &[String], flag: &str) -> Result<u32, String> {
    let raw = read_flag_value(args, flag)?;
    raw.parse::<u32>()
        .map_err(|e| format!("{flag} must be a u32 integer: {e}"))
}

fn parse_u64_flag(args: &[String], flag: &str) -> Result<u64, String> {
    let raw = read_flag_value(args, flag)?;
    raw.parse::<u64>()
        .map_err(|e| format!("{flag} must be a u64 integer: {e}"))
}

fn parse_hex_fixed<const N: usize>(args: &[String], flag: &str) -> Result<[u8; N], String> {
    let raw = read_flag_value(args, flag)?;
    let bytes = decode_hex(&raw).map_err(|e| format!("{flag}: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{flag} must be {N} bytes hex"))
}

fn read_flag_value(args: &[String], flag: &str) -> Result<String, String> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == flag {
            if i + 1 >= args.len() {
                return Err(format!("missing value for {flag}"));
            }
            return Ok(args[i + 1].clone());
        }
        i += 1;
    }
    Err(format!("{flag} is required"))
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("hex value must not be empty".to_string());
    }
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    hex::decode(normalized).map_err(|e| format!("invalid hex: {e}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn usage() -> String {
    [
        "Usage:",
        "  guest-witness-fixture deposit --base-chain-id <u32> --bridge-address <0x20-bytes> --base-recipient <0x20-bytes> --amount <u64>",
        "  guest-witness-fixture withdraw --base-chain-id <u32> --bridge-address <0x20-bytes> --withdrawal-id <0x32-bytes> --net-amount <u64>",
    ]
    .join("\n")
}
