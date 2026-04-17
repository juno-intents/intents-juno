use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_prover::worker::SP1LightNode;
use sp1_sdk::network::signer::NetworkSigner;
use sp1_sdk::network::{
    Address, FulfillmentStrategy, NetworkClient, NetworkMode,
    proto::{
        GetProofRequestParamsResponse, auction_network::prover_network_client::ProverNetworkClient,
        auction_types::GetProversByUptimeRequest, types::ProofMode,
    },
};
use sp1_sdk::prelude::*;
use sp1_sdk::{NetworkProver, ProverClient, ProvingKey, SP1Context, SP1ProofMode};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use tonic::transport::{ClientTlsConfig, Endpoint};

const VERSION_SP1_BALANCE_REQUEST: &str = "sp1.balance.request.v1";
const VERSION_SP1_BALANCE_RESPONSE: &str = "sp1.balance.response.v1";
const VERSION_PROVER_REQUEST: &str = "prover.request.v1";
const VERSION_PROVER_RESPONSE: &str = "prover.response.v1";
const DEFAULT_NETWORK_GAS_LIMIT: u64 = 1_000_000_000;
const DEFAULT_GAS_LIMIT_HEADROOM_BPS: u64 = 1_000;

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
    let private_input =
        decode_hex_bytes(&req.private_input).context("decode prover private_input")?;

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
    let network_rpc_url =
        read_network_rpc_url().unwrap_or_else(|| "https://rpc.mainnet.succinct.xyz".to_owned());
    let client = build_network_client_with_rpc_url(network_rpc_url.clone())?;

    let proving_key = prover
        .setup(elf_bytes.into())
        .await
        .context("sp1 setup failed")?;
    let request_vk_hash = prover
        .register_program(proving_key.verifying_key(), proving_key.elf())
        .await
        .context("sp1 register program failed")?;
    let actual_vkey = normalize_hex_32(&proving_key.verifying_key().bytes32())?;
    if actual_vkey != expected_image_id {
        bail!("program vkey mismatch: got={actual_vkey} expected={expected_image_id}");
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(private_input);

    let gas_limit_cap = read_pipeline_max_gas_limit(pipeline)?;
    let gas_limit_headroom_bps = read_pipeline_gas_limit_headroom_bps(pipeline)?;
    let (simulated_cycle_limit, simulated_gas_limit, committed_value_digest) =
        simulate_execution_limits(proving_key.elf(), &stdin).await?;
    let (cycle_limit, gas_limit, public_values_hash) = resolve_execution_limits(
        simulated_cycle_limit,
        simulated_gas_limit,
        committed_value_digest,
        gas_limit_cap,
        gas_limit_headroom_bps,
    );
    let min_auction_period = read_u64_env("SP1_MIN_AUCTION_PERIOD", 1)?;
    let auction_timeout = Duration::from_secs(read_u64_env("SP1_AUCTION_TIMEOUT_SECONDS", 300)?);
    let request_timeout = Duration::from_secs(read_u64_env("SP1_REQUEST_TIMEOUT_SECONDS", 1800)?);
    let request_version = read_request_circuit_version();

    if let Some(max_gas_limit) = gas_limit_cap {
        eprintln!(
            "applying SP1 gas limit cap for {} pipeline: {} PGUs",
            pipeline.name(),
            max_gas_limit
        );
    } else if let Some(simulated_gas_limit) = simulated_gas_limit {
        if gas_limit_headroom_bps > 0 {
            eprintln!(
                "applying SP1 gas limit headroom for {} pipeline: simulated={} padded={} headroom_bps={}",
                pipeline.name(),
                simulated_gas_limit,
                gas_limit,
                gas_limit_headroom_bps
            );
        }
    }

    let params = prover
        .get_proof_request_params(SP1ProofMode::Groth16)
        .await
        .context("get proof request params")?;
    let GetProofRequestParamsResponse::Auction(params) = params else {
        bail!("proof request params unsupported in non-mainnet mode");
    };
    let base_fee = params
        .base_fee
        .parse::<u64>()
        .context("invalid base fee from proof request params")?;
    let default_max_price_per_pgu = params
        .max_price_per_pgu
        .parse::<u64>()
        .context("invalid max price per pgu from proof request params")?;
    let max_price_per_pgu =
        read_optional_u64_env("SP1_MAX_PRICE_PER_PGU")?.unwrap_or(default_max_price_per_pgu);

    eprintln!(
        "requesting {} proof with compat circuit version {} (setup image id {})",
        pipeline.name(),
        request_version,
        actual_vkey
    );

    let strategy = FulfillmentStrategy::Auction;
    let auctioneer = address_from_bytes(&params.auctioneer)?;
    let executor = address_from_bytes(&params.executor)?;
    let verifier = address_from_bytes(&params.verifier)?;
    let treasury = address_from_bytes(&params.treasury)?;
    let mut whitelist: Option<Vec<Address>> = None;

    let proof = loop {
        let response = client
            .request_proof(
                request_vk_hash,
                &stdin,
                ProofMode::Groth16,
                &request_version,
                strategy,
                request_timeout.as_secs(),
                cycle_limit,
                gas_limit,
                min_auction_period,
                whitelist.clone(),
                auctioneer,
                executor,
                verifier,
                treasury,
                Some(public_values_hash.clone()),
                base_fee,
                max_price_per_pgu,
                params.domain.clone(),
            )
            .await
            .context("sp1 request proof failed")?;

        let request_id = sp1_sdk::network::B256::from_slice(response.request_id());
        match prover
            .wait_proof(request_id, Some(request_timeout), Some(auction_timeout))
            .await
        {
            Ok(proof) => break proof,
            Err(err)
                if should_retry_with_fallback_whitelist(
                    &err,
                    NetworkMode::Mainnet,
                    strategy,
                    whitelist.as_deref(),
                ) =>
            {
                let fallback_whitelist = fetch_high_availability_provers(&network_rpc_url)
                    .await
                    .context("fetch fallback high availability provers")?;
                if fallback_whitelist.is_empty() {
                    return Err(err).context("sp1 network groth16 prove failed");
                }
                eprintln!(
                    "retrying {} proof request {} with {} fallback high-availability provers after {}",
                    pipeline.name(),
                    request_id,
                    fallback_whitelist.len(),
                    err
                );
                whitelist = Some(fallback_whitelist);
            }
            Err(err) => return Err(err).context("sp1 network groth16 prove failed"),
        }
    };

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
    let signer = build_network_signer()?;

    let mut builder = ProverClient::builder()
        .network_for(NetworkMode::Mainnet)
        .signer(signer);

    if let Some(rpc_url) = read_network_rpc_url() {
        builder = builder.rpc_url(&rpc_url);
    }

    Ok(builder.build().await)
}

fn build_network_client_with_rpc_url(rpc_url: String) -> Result<NetworkClient> {
    Ok(NetworkClient::new(
        build_network_signer()?,
        rpc_url,
        NetworkMode::Mainnet,
    ))
}

fn build_network_signer() -> Result<NetworkSigner> {
    let private_key = read_required_private_key()?;
    NetworkSigner::local(&private_key).context("invalid NETWORK_PRIVATE_KEY")
}

fn read_required_private_key() -> Result<String> {
    read_required_private_key_from(|name| read_env_nonempty(name))
}

fn render_error_chain(err: &anyhow::Error) -> String {
    format!("{err:#}")
}

fn should_retry_with_fallback_whitelist(
    err: &anyhow::Error,
    network_mode: NetworkMode,
    strategy: FulfillmentStrategy,
    whitelist: Option<&[Address]>,
) -> bool {
    if network_mode != NetworkMode::Mainnet
        || strategy != FulfillmentStrategy::Auction
        || whitelist.is_some()
    {
        return false;
    }
    matches!(
        err.downcast_ref::<sp1_sdk::network::Error>(),
        Some(
            sp1_sdk::network::Error::RequestUnfulfillable { .. }
                | sp1_sdk::network::Error::RequestTimedOut { .. }
                | sp1_sdk::network::Error::RequestAuctionTimedOut { .. }
        )
    )
}

async fn fetch_high_availability_provers(rpc_url: &str) -> Result<Vec<Address>> {
    let channel = configure_grpc_endpoint(rpc_url)?
        .connect()
        .await
        .with_context(|| format!("connect fallback prover client to {rpc_url}"))?;
    let mut rpc = ProverNetworkClient::new(channel);
    let response = rpc
        .get_provers_by_uptime(GetProversByUptimeRequest {
            high_availability_only: true,
        })
        .await
        .context("get high availability provers")?;
    decode_prover_addresses(response.into_inner().provers)
}

fn decode_prover_addresses(raw_provers: Vec<Vec<u8>>) -> Result<Vec<Address>> {
    raw_provers
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            address_from_bytes(&bytes).with_context(|| format!("decode fallback prover #{index}"))
        })
        .collect()
}

fn configure_grpc_endpoint(addr: &str) -> Result<Endpoint> {
    let mut endpoint = Endpoint::new(addr.to_owned())
        .with_context(|| format!("invalid gRPC endpoint {addr}"))?
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(15))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .tcp_nodelay(true);

    if addr.starts_with("https://") {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .with_context(|| format!("configure TLS for {addr}"))?;
    }

    Ok(endpoint)
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

fn read_network_rpc_url() -> Option<String> {
    read_env_nonempty("SP1_NETWORK_RPC_URL").or_else(|| read_env_nonempty("NETWORK_RPC_URL"))
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

fn read_request_circuit_version() -> String {
    read_request_circuit_version_from(|name| read_env_nonempty(name))
}

fn read_request_circuit_version_from<F>(mut read_env: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    read_env("SP1_REQUEST_CIRCUIT_VERSION")
        .unwrap_or_else(|| sp1_sdk::SP1_CIRCUIT_VERSION.trim().to_owned())
}

async fn simulate_execution_limits(
    elf: &[u8],
    stdin: &SP1Stdin,
) -> Result<(u64, Option<u64>, Vec<u8>)> {
    let execute_result = SP1LightNode::new()
        .await
        .execute(
            elf,
            stdin.clone(),
            SP1Context::builder().calculate_gas(true).build(),
        )
        .await
        .context("sp1 simulation failed")?;
    let (_, committed_value_digest, report) = execute_result;
    Ok((
        report.total_instruction_count(),
        report.gas(),
        committed_value_digest.to_vec(),
    ))
}

fn resolve_execution_limits(
    simulated_cycle_limit: u64,
    simulated_gas_limit: Option<u64>,
    simulated_public_values_hash: Vec<u8>,
    gas_limit_override: Option<u64>,
    gas_limit_headroom_bps: u64,
) -> (u64, u64, Vec<u8>) {
    (
        simulated_cycle_limit,
        gas_limit_override.unwrap_or_else(|| {
            simulated_gas_limit
                .map(|gas| apply_gas_limit_headroom(gas, gas_limit_headroom_bps))
                .unwrap_or(DEFAULT_NETWORK_GAS_LIMIT)
        }),
        simulated_public_values_hash,
    )
}

fn apply_gas_limit_headroom(gas_limit: u64, headroom_bps: u64) -> u64 {
    if gas_limit == 0 || headroom_bps == 0 {
        return gas_limit;
    }
    let extra = gas_limit.saturating_mul(headroom_bps).saturating_add(9_999) / 10_000;
    gas_limit.saturating_add(extra)
}

fn address_from_bytes(bytes: &[u8]) -> Result<Address> {
    if bytes.len() != 20 {
        bail!("expected 20-byte address, got {}", bytes.len());
    }
    Ok(Address::from_slice(bytes))
}

fn read_pipeline_max_gas_limit(pipeline: PipelineKind) -> Result<Option<u64>> {
    read_pipeline_max_gas_limit_from(pipeline, |name| read_env_nonempty(name))
}

fn read_pipeline_max_gas_limit_from<F>(
    pipeline: PipelineKind,
    mut read_env: F,
) -> Result<Option<u64>>
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

fn read_pipeline_gas_limit_headroom_bps(pipeline: PipelineKind) -> Result<u64> {
    read_pipeline_gas_limit_headroom_bps_from(pipeline, |name| read_env_nonempty(name))
}

fn read_pipeline_gas_limit_headroom_bps_from<F>(
    pipeline: PipelineKind,
    mut read_env: F,
) -> Result<u64>
where
    F: FnMut(&str) -> Option<String>,
{
    let specific_name = match pipeline {
        PipelineKind::Deposit => "SP1_DEPOSIT_GAS_LIMIT_HEADROOM_BPS",
        PipelineKind::Withdraw => "SP1_WITHDRAW_GAS_LIMIT_HEADROOM_BPS",
    };
    if let Some(value) = read_optional_u64_env_from(specific_name, &mut read_env)? {
        return Ok(value);
    }
    Ok(
        read_optional_u64_env_from("SP1_GAS_LIMIT_HEADROOM_BPS", read_env)?
            .unwrap_or(DEFAULT_GAS_LIMIT_HEADROOM_BPS),
    )
}

async fn load_program_elf(pipeline: PipelineKind) -> Result<(Vec<u8>, String)> {
    if let Some(path) = pipeline_env_path(pipeline)? {
        let bytes = fs::read(&path).with_context(|| format!("read ELF path {}", path.display()))?;
        return Ok((bytes, path.to_string_lossy().to_string()));
    }
    let url = pipeline_env_url(pipeline)?;
    let cache_path = cache_path_for_url(pipeline, &url);
    if cache_path.exists() {
        let bytes = fs::read(&cache_path)
            .with_context(|| format!("read cached ELF {}", cache_path.display()))?;
        return Ok((bytes, url));
    }

    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create cache dir {}", parent.display()))?;
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
        bail!(
            "download ELF from {url} failed with status {}",
            response.status()
        );
    }
    let bytes = response.bytes().await.context("read ELF body")?.to_vec();
    write_cache_bytes_atomically(&cache_path, &bytes)?;
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

fn write_cache_bytes_atomically(cache_path: &PathBuf, bytes: &[u8]) -> Result<()> {
    write_cache_bytes_atomically_with_hook(cache_path, bytes, |_| Ok(()))
}

fn write_cache_bytes_atomically_with_hook<F>(
    cache_path: &PathBuf,
    bytes: &[u8],
    before_rename: F,
) -> Result<()>
where
    F: FnOnce(&PathBuf) -> Result<()>,
{
    let parent = cache_path
        .parent()
        .ok_or_else(|| anyhow!("cache path missing parent: {}", cache_path.display()))?;
    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("cache temp timestamp")?
        .as_nanos();
    let temp_path = parent.join(format!(
        ".{}.{unique_suffix}.tmp",
        cache_path
            .file_name()
            .ok_or_else(|| anyhow!("cache path missing file name: {}", cache_path.display()))?
            .to_string_lossy()
    ));

    fs::write(&temp_path, bytes)
        .with_context(|| format!("write cached ELF temp file {}", temp_path.display()))?;

    let rename_result = (|| -> Result<()> {
        before_rename(&temp_path)?;
        fs::rename(&temp_path, cache_path).with_context(|| {
            format!(
                "rename cached ELF temp file {} -> {}",
                temp_path.display(),
                cache_path.display()
            )
        })?;
        Ok(())
    })();

    if rename_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    rename_result
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
    std::io::stdout()
        .write_all(b"\n")
        .context("write response newline")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::path::PathBuf;

    fn dependency_version(contents: &str, dep_name: &str) -> Option<String> {
        contents
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(dep_name))
            .and_then(|line| {
                if line.contains("version") {
                    line.split("version")
                        .nth(1)
                        .and_then(|tail| tail.split('"').nth(1))
                        .map(|value| value.trim_start_matches('=').to_owned())
                } else {
                    line.split('"')
                        .nth(1)
                        .map(|value| value.trim_start_matches('=').to_owned())
                }
            })
    }

    fn lockfile_versions(contents: &str) -> BTreeMap<String, BTreeSet<String>> {
        let mut versions = BTreeMap::new();
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;

        for line in contents.lines().map(str::trim) {
            if line == "[[package]]" {
                if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                    versions
                        .entry(name)
                        .or_insert_with(BTreeSet::new)
                        .insert(version);
                }
                continue;
            }
            if let Some(name) = line
                .strip_prefix("name = ")
                .and_then(|value| value.trim_matches('"').split('"').next())
            {
                current_name = Some(name.to_owned());
                continue;
            }
            if let Some(version) = line
                .strip_prefix("version = ")
                .and_then(|value| value.trim_matches('"').split('"').next())
            {
                current_version = Some(version.to_owned());
            }
        }

        if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
            versions
                .entry(name)
                .or_insert_with(BTreeSet::new)
                .insert(version);
        }

        versions
    }

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
    fn write_cache_bytes_atomically_hides_partial_file_until_rename() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time")
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sp1-cache-test-{unique_suffix}"));
        fs::create_dir_all(&base_dir).expect("create temp dir");
        let cache_path = base_dir.join("withdraw.elf");

        let before_rename = |temp_path: &PathBuf| -> Result<()> {
            assert!(temp_path.exists(), "temp file should exist before rename");
            assert!(
                !cache_path.exists(),
                "final cache path must stay hidden until rename completes"
            );
            Ok(())
        };

        write_cache_bytes_atomically_with_hook(&cache_path, b"elf-bytes", before_rename)
            .expect("atomic cache write");

        let written = fs::read(&cache_path).expect("read cached file");
        assert_eq!(written, b"elf-bytes");

        fs::remove_file(&cache_path).expect("remove cached file");
        fs::remove_dir(&base_dir).expect("remove temp dir");
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
        let err = read_required_private_key_from(|name| envs.get(name).cloned())
            .expect_err("missing key");
        assert!(err.to_string().contains("NETWORK_PRIVATE_KEY is required"));
    }

    #[test]
    fn read_request_circuit_version_prefers_explicit_override() {
        let mut envs = HashMap::new();
        envs.insert("SP1_REQUEST_CIRCUIT_VERSION", "v6.1.0".to_owned());

        let got = read_request_circuit_version_from(|name| envs.get(name).cloned());
        assert_eq!(got, "v6.1.0");
    }

    #[test]
    fn read_request_circuit_version_defaults_to_local_sp1_circuit_version() {
        let envs: HashMap<&str, String> = HashMap::new();

        let got = read_request_circuit_version_from(|name| envs.get(name).cloned());
        assert_eq!(got, sp1_sdk::SP1_CIRCUIT_VERSION.trim());
    }

    #[test]
    fn resolve_execution_limits_prefers_pipeline_gas_cap_and_keeps_public_values_hash() {
        let (cycles, gas, public_values_hash) =
            resolve_execution_limits(12345, Some(67890), vec![1, 2, 3], Some(444), 1_000);

        assert_eq!(cycles, 12345);
        assert_eq!(gas, 444);
        assert_eq!(public_values_hash, vec![1, 2, 3]);
    }

    #[test]
    fn resolve_execution_limits_applies_gas_headroom_when_no_override_is_present() {
        let (_, gas, _) = resolve_execution_limits(12345, Some(67890), vec![1, 2, 3], None, 1_000);
        assert_eq!(gas, 74679);
    }

    #[test]
    fn resolve_execution_limits_uses_simulated_gas_when_headroom_is_zero() {
        let (_, gas, _) = resolve_execution_limits(12345, Some(67890), vec![1, 2, 3], None, 0);
        assert_eq!(gas, 67890);
    }

    #[test]
    fn read_pipeline_max_gas_limit_prefers_pipeline_specific_value() {
        let mut envs = HashMap::new();
        envs.insert("SP1_MAX_GAS_LIMIT", "1000000".to_owned());
        envs.insert("SP1_DEPOSIT_MAX_GAS_LIMIT", "123456".to_owned());

        let got =
            read_pipeline_max_gas_limit_from(PipelineKind::Deposit, |name| envs.get(name).cloned())
                .expect("resolve pipeline-specific gas limit")
                .expect("gas limit should be set");
        assert_eq!(got, 123456);
    }

    #[test]
    fn read_pipeline_max_gas_limit_uses_global_fallback() {
        let mut envs = HashMap::new();
        envs.insert("SP1_MAX_GAS_LIMIT", "7654321".to_owned());

        let got = read_pipeline_max_gas_limit_from(PipelineKind::Withdraw, |name| {
            envs.get(name).cloned()
        })
        .expect("resolve global gas limit")
        .expect("gas limit should be set");
        assert_eq!(got, 7654321);
    }

    #[test]
    fn read_pipeline_max_gas_limit_rejects_invalid_values() {
        let mut envs = HashMap::new();
        envs.insert("SP1_WITHDRAW_MAX_GAS_LIMIT", "not-a-number".to_owned());

        let err = read_pipeline_max_gas_limit_from(PipelineKind::Withdraw, |name| {
            envs.get(name).cloned()
        })
        .expect_err("invalid gas limit should error");
        assert!(err.to_string().contains("SP1_WITHDRAW_MAX_GAS_LIMIT"));
    }

    #[test]
    fn read_pipeline_gas_limit_headroom_prefers_pipeline_specific_value() {
        let mut envs = HashMap::new();
        envs.insert("SP1_GAS_LIMIT_HEADROOM_BPS", "400".to_owned());
        envs.insert("SP1_WITHDRAW_GAS_LIMIT_HEADROOM_BPS", "750".to_owned());

        let got = read_pipeline_gas_limit_headroom_bps_from(PipelineKind::Withdraw, |name| {
            envs.get(name).cloned()
        })
        .expect("resolve pipeline-specific gas headroom");
        assert_eq!(got, 750);
    }

    #[test]
    fn read_pipeline_gas_limit_headroom_uses_global_fallback() {
        let mut envs = HashMap::new();
        envs.insert("SP1_GAS_LIMIT_HEADROOM_BPS", "650".to_owned());

        let got = read_pipeline_gas_limit_headroom_bps_from(PipelineKind::Deposit, |name| {
            envs.get(name).cloned()
        })
        .expect("resolve global gas headroom");
        assert_eq!(got, 650);
    }

    #[test]
    fn read_pipeline_gas_limit_headroom_defaults_when_unset() {
        let envs: HashMap<&str, String> = HashMap::new();

        let got = read_pipeline_gas_limit_headroom_bps_from(PipelineKind::Deposit, |name| {
            envs.get(name).cloned()
        })
        .expect("resolve default gas headroom");
        assert_eq!(got, DEFAULT_GAS_LIMIT_HEADROOM_BPS);
    }

    #[test]
    fn read_pipeline_gas_limit_headroom_rejects_invalid_values() {
        let mut envs = HashMap::new();
        envs.insert(
            "SP1_WITHDRAW_GAS_LIMIT_HEADROOM_BPS",
            "not-a-number".to_owned(),
        );

        let err = read_pipeline_gas_limit_headroom_bps_from(PipelineKind::Withdraw, |name| {
            envs.get(name).cloned()
        })
        .expect_err("invalid gas headroom should error");
        assert!(
            err.to_string()
                .contains("SP1_WITHDRAW_GAS_LIMIT_HEADROOM_BPS")
        );
    }

    #[test]
    fn render_error_chain_includes_context_and_cause() {
        let err = anyhow::anyhow!("inner error").context("outer error");
        let rendered = render_error_chain(&err);
        assert!(rendered.contains("outer error"));
        assert!(rendered.contains("inner error"));
    }

    #[test]
    fn retry_gate_matches_mainnet_auction_unfulfillable_without_whitelist() {
        let err = anyhow::Error::new(sp1_sdk::network::Error::RequestUnfulfillable {
            request_id: vec![1, 2, 3],
        });

        assert!(should_retry_with_fallback_whitelist(
            &err,
            NetworkMode::Mainnet,
            FulfillmentStrategy::Auction,
            None,
        ));
    }

    #[test]
    fn retry_gate_rejects_non_retryable_error_classes() {
        let err = anyhow::Error::new(sp1_sdk::network::Error::RequestUnexecutable {
            request_id: vec![1, 2, 3],
        });

        assert!(!should_retry_with_fallback_whitelist(
            &err,
            NetworkMode::Mainnet,
            FulfillmentStrategy::Auction,
            None,
        ));
    }

    #[test]
    fn retry_gate_rejects_existing_whitelist_and_non_mainnet_paths() {
        let err = anyhow::Error::new(sp1_sdk::network::Error::RequestTimedOut {
            request_id: vec![1, 2, 3],
        });
        let existing_whitelist = [Address::from_slice(&[7u8; 20])];

        assert!(!should_retry_with_fallback_whitelist(
            &err,
            NetworkMode::Mainnet,
            FulfillmentStrategy::Auction,
            Some(&existing_whitelist),
        ));
        assert!(!should_retry_with_fallback_whitelist(
            &err,
            NetworkMode::Reserved,
            FulfillmentStrategy::Auction,
            None,
        ));
        assert!(!should_retry_with_fallback_whitelist(
            &err,
            NetworkMode::Mainnet,
            FulfillmentStrategy::Hosted,
            None,
        ));
    }

    #[test]
    fn decode_prover_addresses_rejects_invalid_address_lengths() {
        let err = decode_prover_addresses(vec![vec![1, 2, 3]])
            .expect_err("invalid fallback prover address should fail");
        assert!(err.to_string().contains("decode fallback prover #0"));
    }

    #[test]
    fn compat_request_path_registers_program_before_request() {
        let source = include_str!("main.rs");
        assert!(
            source.contains(".register_program("),
            "compat request path must register the program before requesting proof"
        );
    }

    #[test]
    fn compat_request_path_uses_committed_value_digest_for_public_values_hash() {
        let source = include_str!("main.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source before tests");
        assert!(
            production_source.contains("committed_value_digest.to_vec()"),
            "compat request path must submit the committed-value digest from execution"
        );
    }

    #[test]
    fn adapter_sp1_sdk_version_matches_guest_toolchain_versions() {
        let adapter = include_str!("../Cargo.toml");
        let deposit_guest = include_str!("../../../deposit_guest/guest/Cargo.toml");
        let withdraw_guest = include_str!("../../../withdraw_guest/guest/Cargo.toml");

        let adapter_version =
            dependency_version(adapter, "sp1-sdk").expect("adapter sp1-sdk version");
        let prover_version =
            dependency_version(adapter, "sp1-prover").expect("adapter sp1-prover version");
        let deposit_version =
            dependency_version(deposit_guest, "sp1-zkvm").expect("deposit guest sp1-zkvm version");
        let withdraw_version = dependency_version(withdraw_guest, "sp1-zkvm")
            .expect("withdraw guest sp1-zkvm version");

        assert_eq!(adapter_version, prover_version);
        assert_eq!(adapter_version, deposit_version);
        assert_eq!(adapter_version, withdraw_version);
    }

    #[test]
    fn lockfile_keeps_sp1_and_slop_toolchain_on_adapter_release_line() {
        let lockfile = include_str!("../../../Cargo.lock");
        let versions = lockfile_versions(lockfile);
        let adapter = include_str!("../Cargo.toml");
        let expected_version =
            dependency_version(adapter, "sp1-sdk").expect("adapter sp1-sdk version");

        let mismatches: Vec<String> = versions
            .into_iter()
            .filter(|(name, _)| {
                (name.starts_with("sp1-") || name.starts_with("slop-"))
                    && name != "sp1-prover-adapter"
            })
            .filter(|(_, found_versions)| {
                found_versions.len() != 1 || !found_versions.contains(expected_version.as_str())
            })
            .map(|(name, found_versions)| {
                format!(
                    "{name}={}",
                    found_versions.into_iter().collect::<Vec<_>>().join(",")
                )
            })
            .collect();

        assert!(
            mismatches.is_empty(),
            "expected SP1/slop toolchain lockfile to stay on {}, found mismatches: {}",
            expected_version,
            mismatches.join("; ")
        );
    }

    #[test]
    fn guest_release_line_matches_adapter_release_line() {
        let adapter = include_str!("../Cargo.toml");
        let expected_version =
            dependency_version(adapter, "sp1-sdk").expect("adapter sp1-sdk version");
        let deposit_guest = include_str!("../../../deposit_guest/guest/Cargo.toml");
        let withdraw_guest = include_str!("../../../withdraw_guest/guest/Cargo.toml");

        let deposit_version =
            dependency_version(deposit_guest, "sp1-zkvm").expect("deposit guest sp1-zkvm version");
        let withdraw_version = dependency_version(withdraw_guest, "sp1-zkvm")
            .expect("withdraw guest sp1-zkvm version");

        assert_eq!(deposit_version, expected_version);
        assert_eq!(withdraw_version, expected_version);
    }

    #[test]
    fn bridge_guest_release_workflow_pins_sp1_toolchain_to_adapter_release_line() {
        let adapter = include_str!("../Cargo.toml");
        let expected_version = format!(
            "sp1up --version v{}",
            dependency_version(adapter, "sp1-sdk").expect("adapter sp1-sdk version")
        );
        let workflow =
            include_str!("../../../../.github/workflows/release-bridge-guest-programs.yml");

        assert!(
            workflow.contains(&expected_version),
            "expected bridge guest release workflow to pin SP1 toolchain with `{expected_version}`"
        );
    }
}
