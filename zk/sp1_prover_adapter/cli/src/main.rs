use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_sdk::network::signer::NetworkSigner;
use sp1_sdk::network::NetworkMode;
use sp1_sdk::prelude::*;
use sp1_sdk::{NetworkProver, ProveRequest, ProverClient};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

const VERSION_SP1_BALANCE_REQUEST: &str = "sp1.balance.request.v1";
const VERSION_SP1_BALANCE_RESPONSE: &str = "sp1.balance.response.v1";
const VERSION_PROVER_REQUEST: &str = "prover.request.v1";
const VERSION_PROVER_RESPONSE: &str = "prover.response.v1";

#[derive(Clone, Copy)]
enum PipelineKind {
    Deposit,
    Withdraw,
}

impl PipelineKind {
    fn name(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdraw => "withdraw",
        }
    }
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

#[derive(Deserialize)]
struct BalanceRequest {
    #[allow(dead_code)]
    version: String,
    #[allow(dead_code)]
    requestor_address: Option<String>,
}

#[derive(Serialize)]
struct BalanceResponse {
    version: &'static str,
    balance_wei: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
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
        VERSION_PROVER_REQUEST => {
            let req: ProverRequest =
                serde_json::from_value(value).context("decode prover request")?;
            handle_prover_request(req).await
        }
        VERSION_SP1_BALANCE_REQUEST => {
            let req: BalanceRequest =
                serde_json::from_value(value).context("decode balance request")?;
            handle_balance_request(req).await
        }
        other => bail!("unsupported request version: {other}"),
    }
}

async fn handle_balance_request(_req: BalanceRequest) -> Result<()> {
    let prover = build_network_prover().await?;
    let response = match prover.get_balance().await {
        Ok(balance) => BalanceResponse {
            version: VERSION_SP1_BALANCE_RESPONSE,
            balance_wei: balance.to_string(),
            error: String::new(),
        },
        Err(err) => BalanceResponse {
            version: VERSION_SP1_BALANCE_RESPONSE,
            balance_wei: "0".to_owned(),
            error: render_error_chain(&err),
        },
    };
    write_json(&response)
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
            error: render_error_chain(&err),
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
    let prover = build_network_prover().await?;

    let proving_key = prover
        .setup(elf_bytes.into())
        .await
        .context("sp1 setup failed")?;
    let actual_vkey = normalize_hex_32(&proving_key.verifying_key().bytes32())?;
    if actual_vkey != expected_image_id {
        bail!("program vkey mismatch: got={actual_vkey} expected={expected_image_id}");
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(private_input);

    let mut req = prover
        .prove(&proving_key, stdin)
        .groth16()
        .min_auction_period(read_u64_env("SP1_MIN_AUCTION_PERIOD", 1)?)
        .auction_timeout(Duration::from_secs(read_u64_env(
            "SP1_AUCTION_TIMEOUT_SECONDS",
            300,
        )?))
        .timeout(Duration::from_secs(read_u64_env(
            "SP1_REQUEST_TIMEOUT_SECONDS",
            1800,
        )?));

    if let Some(max_gas_limit) = read_pipeline_max_gas_limit(pipeline)? {
        eprintln!(
            "applying SP1 gas limit cap for {} pipeline: {} PGUs",
            pipeline.name(),
            max_gas_limit
        );
        req = req.gas_limit(max_gas_limit);
    }

    if let Some(max_price_per_pgu) = read_optional_u64_env("SP1_MAX_PRICE_PER_PGU")? {
        req = req.max_price_per_pgu(max_price_per_pgu);
    }

    let proof = req.await.context("sp1 network groth16 prove failed")?;

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

async fn build_network_prover() -> Result<NetworkProver> {
    let private_key = read_required_private_key()?;
    let signer = NetworkSigner::local(&private_key).context("invalid NETWORK_PRIVATE_KEY")?;

    let mut builder = ProverClient::builder()
        .network_for(NetworkMode::Mainnet)
        .signer(signer);

    if let Some(rpc_url) = read_env_nonempty("SP1_NETWORK_RPC_URL")
        .or_else(|| read_env_nonempty("NETWORK_RPC_URL"))
    {
        builder = builder.rpc_url(&rpc_url);
    }

    Ok(builder.build().await)
}

fn read_required_private_key() -> Result<String> {
    read_required_private_key_from(|name| read_env_nonempty(name))
}

fn render_error_chain(err: &anyhow::Error) -> String {
    format!("{err:#}")
}

fn read_required_private_key_from<F>(mut read_env: F) -> Result<String>
where
    F: FnMut(&str) -> Option<String>,
{
    for env_name in [
        "NETWORK_PRIVATE_KEY",
        "SP1_NETWORK_PRIVATE_KEY",
        "PROOF_REQUESTOR_KEY",
        "PROOF_FUNDER_KEY",
        "SP1_REQUESTOR_PRIVATE_KEY",
    ] {
        if let Some(value) = read_env(env_name) {
            return Ok(value);
        }
    }
    bail!("NETWORK_PRIVATE_KEY is required")
}

fn read_env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn read_u64_env(name: &str, default_value: u64) -> Result<u64> {
    let Some(raw) = read_env_nonempty(name) else {
        return Ok(default_value);
    };
    raw.parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn read_optional_u64_env(name: &str) -> Result<Option<u64>> {
    let Some(raw) = read_env_nonempty(name) else {
        return Ok(None);
    };
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))?;
    Ok(Some(value))
}

fn read_optional_u64_env_from<F>(name: &str, mut read_env: F) -> Result<Option<u64>>
where
    F: FnMut(&str) -> Option<String>,
{
    let Some(raw) = read_env(name) else {
        return Ok(None);
    };
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))?;
    Ok(Some(value))
}

fn read_pipeline_max_gas_limit(pipeline: PipelineKind) -> Result<Option<u64>> {
    read_pipeline_max_gas_limit_from(pipeline, |name| read_env_nonempty(name))
}

fn read_pipeline_max_gas_limit_from<F>(pipeline: PipelineKind, mut read_env: F) -> Result<Option<u64>>
where
    F: FnMut(&str) -> Option<String>,
{
    let specific_name = match pipeline {
        PipelineKind::Deposit => "SP1_DEPOSIT_MAX_GAS_LIMIT",
        PipelineKind::Withdraw => "SP1_WITHDRAW_MAX_GAS_LIMIT",
    };
    if let Some(limit) = read_optional_u64_env_from(specific_name, &mut read_env)? {
        return Ok(Some(limit));
    }
    read_optional_u64_env_from("SP1_MAX_GAS_LIMIT", read_env)
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
    let env_name = match pipeline {
        PipelineKind::Deposit => "SP1_DEPOSIT_PROGRAM_URL",
        PipelineKind::Withdraw => "SP1_WITHDRAW_PROGRAM_URL",
    };
    let url = read_env_nonempty(env_name).ok_or_else(|| anyhow!("{env_name} is required"))?;
    Ok(url)
}

fn read_pipeline_vkey(pipeline: PipelineKind) -> Result<String> {
    let env_name = match pipeline {
        PipelineKind::Deposit => "SP1_DEPOSIT_PROGRAM_VKEY",
        PipelineKind::Withdraw => "SP1_WITHDRAW_PROGRAM_VKEY",
    };
    let raw = read_env_nonempty(env_name).ok_or_else(|| anyhow!("{env_name} is required"))?;
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
    use std::collections::HashMap;

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

    #[test]
    fn read_required_private_key_prefers_network_private_key() {
        let mut envs = HashMap::new();
        envs.insert("PROOF_FUNDER_KEY", "funder-key".to_owned());
        envs.insert("NETWORK_PRIVATE_KEY", "network-key".to_owned());
        let got = read_required_private_key_from(|name| envs.get(name).cloned())
            .expect("resolve key from env map");
        assert_eq!(got, "network-key");
    }

    #[test]
    fn read_required_private_key_supports_funder_fallback() {
        let mut envs = HashMap::new();
        envs.insert("PROOF_FUNDER_KEY", "funder-key".to_owned());
        let got = read_required_private_key_from(|name| envs.get(name).cloned())
            .expect("resolve fallback key");
        assert_eq!(got, "funder-key");
    }

    #[test]
    fn read_required_private_key_errors_when_missing() {
        let envs: HashMap<&str, String> = HashMap::new();
        let err =
            read_required_private_key_from(|name| envs.get(name).cloned()).expect_err("missing key");
        assert!(err.to_string().contains("NETWORK_PRIVATE_KEY is required"));
    }

    #[test]
    fn read_pipeline_max_gas_limit_prefers_pipeline_specific_value() {
        let mut envs = HashMap::new();
        envs.insert("SP1_MAX_GAS_LIMIT", "1000000".to_owned());
        envs.insert("SP1_DEPOSIT_MAX_GAS_LIMIT", "123456".to_owned());

        let got = read_pipeline_max_gas_limit_from(PipelineKind::Deposit, |name| envs.get(name).cloned())
            .expect("resolve pipeline-specific gas limit")
            .expect("gas limit should be set");
        assert_eq!(got, 123456);
    }

    #[test]
    fn read_pipeline_max_gas_limit_uses_global_fallback() {
        let mut envs = HashMap::new();
        envs.insert("SP1_MAX_GAS_LIMIT", "7654321".to_owned());

        let got = read_pipeline_max_gas_limit_from(PipelineKind::Withdraw, |name| envs.get(name).cloned())
            .expect("resolve global gas limit")
            .expect("gas limit should be set");
        assert_eq!(got, 7654321);
    }

    #[test]
    fn read_pipeline_max_gas_limit_rejects_invalid_values() {
        let mut envs = HashMap::new();
        envs.insert("SP1_WITHDRAW_MAX_GAS_LIMIT", "not-a-number".to_owned());

        let err = read_pipeline_max_gas_limit_from(PipelineKind::Withdraw, |name| envs.get(name).cloned())
            .expect_err("invalid gas limit should error");
        assert!(err.to_string().contains("SP1_WITHDRAW_MAX_GAS_LIMIT"));
    }

    #[test]
    fn render_error_chain_includes_context_and_cause() {
        let err = anyhow::anyhow!("inner error").context("outer error");
        let rendered = render_error_chain(&err);
        assert!(rendered.contains("outer error"));
        assert!(rendered.contains("inner error"));
    }

}
