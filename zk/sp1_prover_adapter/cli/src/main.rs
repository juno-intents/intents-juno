use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

const VERSION_BOUNDLESS_SUBMIT_OFFCHAIN: &str = "boundless.submit.offchain.v1";
const VERSION_BOUNDLESS_SUBMIT_ONCHAIN: &str = "boundless.submit.onchain.v1";
const VERSION_BOUNDLESS_SUBMIT_RESPONSE: &str = "boundless.submit.response.v1";
const VERSION_BOUNDLESS_BALANCE_REQUEST: &str = "boundless.balance.request.v1";
const VERSION_BOUNDLESS_BALANCE_RESPONSE: &str = "boundless.balance.response.v1";
const VERSION_BOUNDLESS_TOPUP_REQUEST: &str = "boundless.topup.request.v1";
const VERSION_BOUNDLESS_TOPUP_RESPONSE: &str = "boundless.topup.response.v1";
const VERSION_PROVER_REQUEST: &str = "prover.request.v1";
const VERSION_PROVER_RESPONSE: &str = "prover.response.v1";

#[derive(Clone, Copy)]
enum PipelineKind {
    Deposit,
    Withdraw,
}

impl PipelineKind {
    fn from_name(raw: &str) -> Result<Self> {
        let value = raw.trim().to_ascii_lowercase();
        match value.as_str() {
            "deposit" => Ok(Self::Deposit),
            "withdraw" => Ok(Self::Withdraw),
            _ => bail!("unsupported pipeline: {raw}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdraw => "withdraw",
        }
    }
}

#[derive(Deserialize)]
struct BoundlessSubmitRequest {
    #[allow(dead_code)]
    version: String,
    #[serde(default)]
    request_id: u64,
    pipeline: String,
    image_id: String,
    journal: String,
    private_input: String,
}

#[derive(Deserialize)]
struct ProverRequest {
    #[allow(dead_code)]
    version: String,
    #[serde(rename = "imageId")]
    image_id: String,
    journal: String,
    #[serde(rename = "privateInput")]
    private_input: String,
}

#[derive(Serialize)]
struct BoundlessSubmitResponse {
    version: &'static str,
    request_id: u64,
    submission_path: String,
    seal: String,
    metadata: BoundlessMetadata,
    tx_hash: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error_code: String,
    retryable: bool,
}

#[derive(Serialize)]
struct BoundlessMetadata {
    provider: String,
    proof_type: String,
    pipeline: String,
    program_source: String,
}

#[derive(Serialize)]
struct BalanceResponse {
    version: &'static str,
    balance_wei: String,
}

#[derive(Serialize)]
struct TopupResponse {
    version: &'static str,
    tx_hash: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error_code: String,
}

#[derive(Serialize)]
struct ProverResponse {
    version: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    seal: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[tokio::main]
async fn main() {
    let exit_code = match run().await {
        Ok(()) => 0,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "{err:#}");
            1
        }
    };
    std::process::exit(exit_code);
}

async fn run() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("read stdin request")?;
    if input.is_empty() {
        bail!("empty request");
    }

    let value: Value = serde_json::from_slice(&input).context("decode request json")?;
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("request missing version"))?;

    match version {
        VERSION_BOUNDLESS_SUBMIT_OFFCHAIN | VERSION_BOUNDLESS_SUBMIT_ONCHAIN => {
            let req: BoundlessSubmitRequest =
                serde_json::from_value(value).context("decode boundless submit request")?;
            handle_boundless_submit(req).await
        }
        VERSION_BOUNDLESS_BALANCE_REQUEST => handle_balance_request(),
        VERSION_BOUNDLESS_TOPUP_REQUEST => handle_topup_request(),
        VERSION_PROVER_REQUEST => {
            let req: ProverRequest =
                serde_json::from_value(value).context("decode prover request")?;
            handle_prover_request(req).await
        }
        other => bail!("unsupported request version: {other}"),
    }
}

async fn handle_boundless_submit(req: BoundlessSubmitRequest) -> Result<()> {
    let request_id = req.request_id;
    let pipeline = match PipelineKind::from_name(&req.pipeline) {
        Ok(p) => p,
        Err(err) => {
            let resp = BoundlessSubmitResponse {
                version: VERSION_BOUNDLESS_SUBMIT_RESPONSE,
                request_id,
                submission_path: String::new(),
                seal: String::new(),
                metadata: BoundlessMetadata {
                    provider: "sp1".to_owned(),
                    proof_type: "groth16".to_owned(),
                    pipeline: req.pipeline,
                    program_source: String::new(),
                },
                tx_hash: String::new(),
                error: err.to_string(),
                error_code: "sp1_invalid_pipeline".to_owned(),
                retryable: false,
            };
            return write_json(&resp);
        }
    };

    let image_id = normalize_hex_32(&req.image_id)?;
    let journal = decode_hex_bytes(&req.journal).context("decode submit journal")?;
    let private_input = decode_hex_bytes(&req.private_input).context("decode submit private_input")?;

    match prove_once(pipeline, &image_id, journal.as_slice(), private_input).await {
        Ok((seal, program_source)) => {
            let resp = BoundlessSubmitResponse {
                version: VERSION_BOUNDLESS_SUBMIT_RESPONSE,
                request_id,
                submission_path: "sp1-groth16-local".to_owned(),
                seal: encode_hex(&seal),
                metadata: BoundlessMetadata {
                    provider: "sp1".to_owned(),
                    proof_type: "groth16".to_owned(),
                    pipeline: pipeline.name().to_owned(),
                    program_source,
                },
                tx_hash: String::new(),
                error: String::new(),
                error_code: String::new(),
                retryable: false,
            };
            write_json(&resp)
        }
        Err(err) => {
            let resp = BoundlessSubmitResponse {
                version: VERSION_BOUNDLESS_SUBMIT_RESPONSE,
                request_id,
                submission_path: String::new(),
                seal: String::new(),
                metadata: BoundlessMetadata {
                    provider: "sp1".to_owned(),
                    proof_type: "groth16".to_owned(),
                    pipeline: pipeline.name().to_owned(),
                    program_source: String::new(),
                },
                tx_hash: String::new(),
                error: err.to_string(),
                error_code: "sp1_prove_failed".to_owned(),
                retryable: true,
            };
            write_json(&resp)
        }
    }
}

fn handle_balance_request() -> Result<()> {
    // Keep compatibility with existing proof-funder loops; local SP1 proving doesn't require
    // maintaining market balances, so return a high synthetic value.
    let resp = BalanceResponse {
        version: VERSION_BOUNDLESS_BALANCE_RESPONSE,
        balance_wei: "1000000000000000000000000000000".to_owned(),
    };
    write_json(&resp)
}

fn handle_topup_request() -> Result<()> {
    let resp = TopupResponse {
        version: VERSION_BOUNDLESS_TOPUP_RESPONSE,
        tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        error: String::new(),
        error_code: String::new(),
    };
    write_json(&resp)
}

async fn handle_prover_request(req: ProverRequest) -> Result<()> {
    let image_id = normalize_hex_32(&req.image_id)?;
    let journal = decode_hex_bytes(&req.journal).context("decode prover journal")?;
    let private_input = decode_hex_bytes(&req.private_input).context("decode prover private_input")?;

    let pipeline = pipeline_for_image_id(&image_id)?;
    let response = match prove_once(pipeline, &image_id, journal.as_slice(), private_input).await {
        Ok((seal, _)) => ProverResponse {
            version: VERSION_PROVER_RESPONSE,
            seal: encode_hex(&seal),
            error: String::new(),
        },
        Err(err) => ProverResponse {
            version: VERSION_PROVER_RESPONSE,
            seal: String::new(),
            error: err.to_string(),
        },
    };
    write_json(&response)
}

fn pipeline_for_image_id(image_id: &str) -> Result<PipelineKind> {
    let deposit_vkey = read_pipeline_vkey(PipelineKind::Deposit)?;
    if image_id == deposit_vkey {
        return Ok(PipelineKind::Deposit);
    }
    let withdraw_vkey = read_pipeline_vkey(PipelineKind::Withdraw)?;
    if image_id == withdraw_vkey {
        return Ok(PipelineKind::Withdraw);
    }
    bail!("unsupported image id: {image_id}");
}

async fn prove_once(
    pipeline: PipelineKind,
    expected_image_id: &str,
    expected_journal: &[u8],
    private_input: Vec<u8>,
) -> Result<(Vec<u8>, String)> {
    let (elf_bytes, program_source) = load_program_elf(pipeline).await?;

    let client = ProverClient::from_env().await;
    let proving_key = client.setup(elf_bytes.into()).await.context("sp1 setup failed")?;
    let actual_vkey = normalize_hex_32(&proving_key.verifying_key().bytes32())?;
    if actual_vkey != expected_image_id {
        bail!("program vkey mismatch: got={actual_vkey} expected={expected_image_id}");
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(private_input);

    let proof = client
        .prove(&proving_key, stdin)
        .groth16()
        .await
        .context("sp1 groth16 prove failed")?;

    let public_values = proof.public_values.to_vec();
    if public_values != expected_journal {
        bail!(
            "journal mismatch: got={}bytes expected={}bytes",
            public_values.len(),
            expected_journal.len()
        );
    }

    Ok((proof.bytes(), program_source))
}

async fn load_program_elf(pipeline: PipelineKind) -> Result<(Vec<u8>, String)> {
    if let Some(path) = pipeline_env_path(pipeline)? {
        let bytes = fs::read(&path).with_context(|| format!("read ELF path {}", path.display()))?;
        return Ok((bytes, path.to_string_lossy().to_string()));
    }
    let url = pipeline_env_url(pipeline)?;
    let cache_path = cache_path_for_url(pipeline, &url);
    if cache_path.exists() {
        let bytes =
            fs::read(&cache_path).with_context(|| format!("read cached ELF {}", cache_path.display()))?;
        return Ok((bytes, url));
    }

    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create cache dir {}", parent.display()))?;
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("build http client")?;
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("download ELF from {url}"))?;
    if !response.status().is_success() {
        bail!("download ELF from {url} failed with status {}", response.status());
    }
    let bytes = response.bytes().await.context("read ELF body")?.to_vec();
    fs::write(&cache_path, &bytes)
        .with_context(|| format!("write cached ELF {}", cache_path.display()))?;
    Ok((bytes, url))
}

fn pipeline_env_path(pipeline: PipelineKind) -> Result<Option<PathBuf>> {
    let env_name = match pipeline {
        PipelineKind::Deposit => "SP1_DEPOSIT_ELF_PATH",
        PipelineKind::Withdraw => "SP1_WITHDRAW_ELF_PATH",
    };
    let raw = std::env::var(env_name).unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(trimmed)))
}

fn pipeline_env_url(pipeline: PipelineKind) -> Result<String> {
    let (primary, compat) = match pipeline {
        PipelineKind::Deposit => ("SP1_DEPOSIT_PROGRAM_URL", "BOUNDLESS_DEPOSIT_PROGRAM_URL"),
        PipelineKind::Withdraw => ("SP1_WITHDRAW_PROGRAM_URL", "BOUNDLESS_WITHDRAW_PROGRAM_URL"),
    };
    let primary_val = std::env::var(primary).unwrap_or_default();
    let compat_val = std::env::var(compat).unwrap_or_default();
    let raw = if !primary_val.trim().is_empty() {
        primary_val
    } else {
        compat_val
    };
    let url = raw.trim();
    if url.is_empty() {
        bail!("{primary} (or {compat}) is required");
    }
    Ok(url.to_owned())
}

fn read_pipeline_vkey(pipeline: PipelineKind) -> Result<String> {
    let (primary, compat) = match pipeline {
        PipelineKind::Deposit => ("SP1_DEPOSIT_PROGRAM_VKEY", "BRIDGE_DEPOSIT_IMAGE_ID"),
        PipelineKind::Withdraw => ("SP1_WITHDRAW_PROGRAM_VKEY", "BRIDGE_WITHDRAW_IMAGE_ID"),
    };
    let primary_val = std::env::var(primary).unwrap_or_default();
    let compat_val = std::env::var(compat).unwrap_or_default();
    let raw = if !primary_val.trim().is_empty() {
        primary_val
    } else {
        compat_val
    };
    normalize_hex_32(&raw)
}

fn cache_path_for_url(pipeline: PipelineKind, url: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    let hash = hasher.finish();
    let base_dir = std::env::var("SP1_PROGRAM_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("sp1-prover-adapter"));
    base_dir.join(format!("{}-{hash:016x}.elf", pipeline.name()))
}

fn normalize_hex_32(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("expected 32-byte hex, got {raw}");
    }
    Ok(format!("0x{}", trimmed.to_ascii_lowercase()))
}

fn decode_hex_bytes(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(trimmed).with_context(|| format!("invalid hex bytes: {raw}"))
}

fn encode_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

fn write_json<T: Serialize>(value: &T) -> Result<()> {
    serde_json::to_writer(std::io::stdout(), value).context("encode response json")?;
    std::io::stdout().write_all(b"\n").context("write response newline")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hex_32_accepts_prefixed_and_unprefixed() {
        let raw = "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa";
        let got = normalize_hex_32(raw).expect("normalize with prefix");
        assert_eq!(
            got,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        let no_prefix = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let got_no_prefix = normalize_hex_32(no_prefix).expect("normalize without prefix");
        assert_eq!(
            got_no_prefix,
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn normalize_hex_32_rejects_invalid_length() {
        let err = normalize_hex_32("0x1234").expect_err("expected invalid length");
        assert!(err.to_string().contains("expected 32-byte hex"));
    }

    #[test]
    fn decode_hex_bytes_handles_empty_and_data() {
        let empty = decode_hex_bytes("0x").expect("decode empty");
        assert!(empty.is_empty());

        let decoded = decode_hex_bytes("0x0102aB").expect("decode bytes");
        assert_eq!(decoded, vec![0x01, 0x02, 0xAB]);
    }

    #[test]
    fn cache_path_for_url_is_stable_per_pipeline() {
        let url = "https://example.invalid/program.elf";
        let deposit_a = cache_path_for_url(PipelineKind::Deposit, url);
        let deposit_b = cache_path_for_url(PipelineKind::Deposit, url);
        let withdraw = cache_path_for_url(PipelineKind::Withdraw, url);

        assert_eq!(deposit_a, deposit_b);
        assert_ne!(deposit_a, withdraw);
    }
}
