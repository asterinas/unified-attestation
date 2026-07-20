//! relying-party: RP client + hydra TCP listener.
//!
//! Two flows run in one process:
//! - gRPC-based remote attestation (background-check / passport) via CLI subcommand,
//!   forwarding to attester and (background-check) verifier gRPC endpoints.
//! - Hydra TCP listener: receives PublicContext broadcasts from verifier and
//!   EvidenceReply frames from attesters, verifies them with rely_party_verification.

mod hydra_listener;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use clap::{Parser, Subcommand};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use protos::attester_service_client::AttesterServiceClient;
use protos::verifier_service_client::VerifierServiceClient;
use protos::verify_request::Wasm;
use protos::{AttestationMode, GetEvidenceRequest, TeeType, VerifyRequest};
use serde_json::Value;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "unified-attestation relying-party")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(long)]
    attester: Option<String>,
    #[arg(long)]
    verifier: Option<String>,
    #[arg(long, value_parser = parse_tee_type)]
    tee_type: Option<TeeType>,
    #[arg(long)]
    pubkey: Option<PathBuf>,
    #[arg(long, default_value = "background-check")]
    mode: String,
    #[arg(long)]
    ear_out: Option<PathBuf>,
    /// Hydra TCP listener address; when set, RP also accepts PublicContext + EvidenceReply frames.
    #[arg(long)]
    hydra_listen: Option<String>,
    /// Hydra data directory (PublicContext cache lives here).
    #[arg(long, default_value = "workspace-data/relying-party")]
    hydra_data_dir: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run only the hydra TCP listener (no gRPC attestation flow).
    HydraServe,
}

fn parse_tee_type(s: &str) -> Result<TeeType, String> {
    match s {
        "mock" => Ok(TeeType::Mock),
        "cca" => Ok(TeeType::Cca),
        "cca-hydra" => Ok(TeeType::CcaHydra),
        "csv" => Ok(TeeType::Csv),
        "csv-hydra" => Ok(TeeType::CsvHydra),
        "tdx" => Ok(TeeType::Tdx),
        "tdx-hydra" => Ok(TeeType::TdxHydra),
        "itrustee" => Ok(TeeType::Itrustee),
        "itrustee-hydra" => Ok(TeeType::ItrusteeHydra),
        "virtcca" => Ok(TeeType::Virtcca),
        "virtcca-hydra" => Ok(TeeType::VirtccaHydra),
        other => Err(format!("invalid tee_type '{other}'")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();

    if matches!(cli.command, Some(Command::HydraServe)) {
        let addr = cli
            .hydra_listen
            .clone()
            .unwrap_or_else(|| "127.0.0.1:7002".to_string());
        return hydra_listener::run(hydra_listener::HydraListenerConfig {
            listen_addr: addr,
            data_dir: cli.hydra_data_dir.clone(),
        })
        .await;
    }

    // If --hydra-listen is set, spawn the hydra TCP listener alongside the gRPC flow.
    // It receives PublicContext from verifier and EvidenceReply from attesters.
    // Independent from the gRPC attestation flow; failures are logged, not fatal.
    if let Some(addr) = cli.hydra_listen.clone() {
        let data_dir = cli.hydra_data_dir.clone();
        tokio::spawn(async move {
            if let Err(err) =
                hydra_listener::run(hydra_listener::HydraListenerConfig {
                    listen_addr: addr,
                    data_dir,
                })
                .await
            {
                eprintln!("hydra listener exited: {:#}", err);
            }
        });
    }

    let attester = cli.attester.context("--attester required")?;
    let verifier = cli.verifier.context("--verifier required")?;
    let tee_type = cli.tee_type.context("--tee-type required")?;
    let pubkey = cli.pubkey.context("--pubkey required")?;
    let is_passport = cli.mode == "passport";

    let pem =
        std::fs::read(&pubkey).with_context(|| format!("read pubkey {}", pubkey.display()))?;
    let key = DecodingKey::from_ec_pem(&pem).context("parse pubkey as EC PEM")?;

    let request_nonce: Vec<u8>;
    let nonce_b64: String;
    if is_passport {
        request_nonce = Vec::new();
        nonce_b64 = String::new();
    } else {
        let mut buf = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut buf);
        request_nonce = buf.to_vec();
        nonce_b64 = B64URL.encode(&request_nonce);
        info!(nonce = %nonce_b64, "generated nonce");
    }

    let mode = if is_passport {
        AttestationMode::Passport
    } else {
        AttestationMode::BackgroundCheck
    };
    let mut att = AttesterServiceClient::connect(attester.clone())
        .await
        .with_context(|| format!("connect attester {attester}"))?;
    let evidence = att
        .get_evidence(GetEvidenceRequest {
            tee_type: tee_type as i32,
            nonce: request_nonce.clone(),
            mode: mode as i32,
        })
        .await
        .context("attester GetEvidence")?
        .into_inner();

    let (verify_nonce, verify_nonce_b64) = if is_passport {
        let gn = evidence.generated_nonce;
        let b64 = B64URL.encode(&gn);
        info!(nonce = %b64, "received passport nonce from attester");
        (gn, b64)
    } else {
        (request_nonce, nonce_b64)
    };

    let ear_jwt = if is_passport {
        if evidence.ear.is_empty() {
            bail!("passport mode requires verifier_endpoint configured on attester");
        }
        evidence.ear
    } else {
        let mut ver = VerifierServiceClient::connect(verifier.clone())
            .await
            .with_context(|| format!("connect verifier {verifier}"))?;
        let resp = ver
            .verify(VerifyRequest {
                tee_type: tee_type as i32,
                nonce: verify_nonce,
                evidence: evidence.evidence,
                wasm: Some(Wasm::WasmComponent(evidence.wasm_component)),
            })
            .await
            .context("verifier Verify")?
            .into_inner();
        resp.ear
    };

    if let Some(path) = &cli.ear_out {
        std::fs::write(path, &ear_jwt).with_context(|| format!("write {}", path.display()))?;
    }

    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    let data = jsonwebtoken::decode::<Value>(ear_jwt.trim(), &key, &validation)
        .context("decode/verify EAR")?;

    if is_passport {
        let iat = data.claims.get("iat").and_then(Value::as_i64).unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if (now - iat) > 300 {
            bail!("EAR expired: iat={iat}, now={now}, delta={}", now - iat);
        }
    } else {
        let eat_nonce = data
            .claims
            .get("eat_nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing eat_nonce"))?;
        if eat_nonce != verify_nonce_b64 {
            bail!("eat_nonce mismatch: ear={eat_nonce}, expected={verify_nonce_b64}");
        }
    }

    println!("{}", serde_json::to_string_pretty(&data.claims)?);
    let trust_vector = data
        .claims
        .get("trust_vector")
        .ok_or_else(|| anyhow!("missing trust_vector"))?;
    let executables = trust_vector
        .get("executables")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if executables < 2 {
        bail!("EAR not affirming: executables = {executables}");
    }
    println!("\nverdict: ACCEPTED");
    Ok(())
}
