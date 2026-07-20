//! Attester entry point.
//!
//! Runs two services in one process:
//! - gRPC (AttesterService.GetEvidence): TEE evidence via wasm appraisers (passport / background-check)
//! - Hydra TCP client task: submits SignedDeviceClientInfor to the verifier's TCP daemon,
//!   receives encrypted ResponseDeviceInfor + PublicContext, persists a session, and
//!   optionally ships an EvidenceReply to configured relying-party addresses.
//!
//! The hydra path is orthogonal to the gRPC path: enabled per `attester.toml` `[hydra]` section.

mod config;
mod evidence;
mod hydra_client;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use protos::attester_service_server::{AttesterService, AttesterServiceServer};
use protos::verifier_service_client::VerifierServiceClient;
use protos::verify_request::Wasm;
use protos::{GetEvidenceRequest, GetEvidenceResponse, TeeType, VerifyRequest};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::{Request, Response, Status, transport::Server};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "unified-attestation attester (gRPC)")]
struct Cli {
    #[arg(short, long, default_value = "config/attester.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Build an EvidenceReply from a saved hydra session and ship it to relying-party
    /// TCP addresses. Session must have been bootstrapped by a prior daemon run.
    HydraEvidence {
        /// Session directory. Omit to use the latest session recorded by the daemon.
        #[arg(long)]
        session: Option<PathBuf>,
        /// Relying-party TCP addresses. Falls back to `[hydra] relying_party_addrs`
        /// in the config file when empty.
        #[arg(long = "rp")]
        rp: Vec<String>,
    },
}

struct Svc {
    cfg: config::Config,
    wasm_bytes: Vec<u8>,
}

#[tonic::async_trait]
impl AttesterService for Svc {
    async fn get_evidence(
        &self,
        req: Request<GetEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        let req = req.into_inner();
        let tee = TeeType::try_from(req.tee_type)
            .map_err(|_| Status::invalid_argument("invalid tee_type"))?;
        if tee != self.cfg.tee_type {
            return Err(Status::invalid_argument(format!(
                "tee_type mismatch: request={tee:?}, configured={:?}",
                self.cfg.tee_type
            )));
        }
        let mode = protos::AttestationMode::try_from(req.mode)
            .unwrap_or(protos::AttestationMode::BackgroundCheck);

        // Nonce handling: passport → attester generates its own; background-check → RP provides
        let effective_nonce: Vec<u8>;
        let generated_nonce: Vec<u8>;
        if matches!(mode, protos::AttestationMode::Passport) && req.nonce.is_empty() {
            let mut buf = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut buf);
            generated_nonce = buf.to_vec();
            effective_nonce = generated_nonce.clone();
        } else {
            if req.nonce.is_empty() {
                return Err(Status::invalid_argument("nonce required for background-check mode"));
            }
            generated_nonce = Vec::new();
            effective_nonce = req.nonce;
        }

        // Collect TEE evidence (via AA REST or mock payload)
        let evidence = evidence::build_evidence(
            self.cfg.tee_type,
            &effective_nonce,
            &self.cfg.aa_endpoint,
        )
        .await
        .map_err(|e| {
            warn!(error = %e, "build evidence failed");
            Status::internal(e.to_string())
        })?;

        // Passport mode: attester calls verifier gRPC internally, returns EAR directly to RP
        if matches!(mode, protos::AttestationMode::Passport) {
            let verifier_ep = self.cfg.verifier_endpoint.as_deref().ok_or_else(|| {
                Status::internal("verifier_endpoint must be configured for passport mode")
            })?;
            let mut ver = VerifierServiceClient::connect(format!("http://{verifier_ep}"))
                .await
                .map_err(|e| Status::internal(format!("connect verifier: {e}")))?;
            let resp = ver
                .verify(VerifyRequest {
                    tee_type: self.cfg.tee_type as i32,
                    nonce: effective_nonce,
                    evidence,
                    wasm: Some(Wasm::WasmComponent(self.wasm_bytes.clone())),
                })
                .await
                .map_err(|e| Status::internal(format!("verifier Verify: {e}")))?
                .into_inner();
            return Ok(Response::new(GetEvidenceResponse {
                evidence: Vec::new(),
                wasm_component: Vec::new(),
                generated_nonce,
                ear: resp.ear,
            }));
        }

        Ok(Response::new(GetEvidenceResponse {
            evidence,
            wasm_component: self.wasm_bytes.clone(),
            generated_nonce,
            ear: String::new(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    let cfg = config::Config::load(&cli.config)?;

    if let Some(Command::HydraEvidence { session, rp }) = cli.command {
        let hydra_cfg = cfg
            .hydra
            .as_ref()
            .context("hydra-evidence requires [hydra] section in config")?;
        let addrs: Vec<String> = if rp.is_empty() {
            hydra_cfg.relying_party_addrs.clone()
        } else {
            rp
        };
        if addrs.is_empty() {
            anyhow::bail!("no relying-party addresses; pass --rp or configure [hydra].relying_party_addrs");
        }
        return hydra_client::send_evidence_from_session(&hydra_cfg.data_dir, session, &addrs).await;
    }

    let wasm_bytes = std::fs::read(&cfg.wasm_component_path)
        .with_context(|| format!("read wasm component {}", cfg.wasm_component_path.display()))?;
    info!(
        wasm_path = %cfg.wasm_component_path.display(),
        size = wasm_bytes.len(),
        "loaded wasm component"
    );

    // Spawn the hydra TCP client if configured. Runs the demo flow once, then keeps the
    // verifier connection open for PublicContext updates.
    if let Some(hydra_cfg) = cfg.hydra.clone() {
        tokio::spawn(async move {
            if let Err(err) = hydra_client::run(hydra_cfg).await {
                eprintln!("hydra client exited: {:#}", err);
            }
        });
    }

    let listen = cfg.listen.clone();
    let svc = Arc::new(Svc { cfg, wasm_bytes });

    let addr = listen.parse().with_context(|| format!("parse listen addr '{listen}'"))?;
    info!(%addr, "attester gRPC listening");
    Server::builder()
        .add_service(AttesterServiceServer::from_arc(svc))
        .serve(addr)
        .await?;
    Ok(())
}
