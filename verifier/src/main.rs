//! Verifier entry point.
//!
//! Runs two servers in one process:
//! - gRPC (evidence Verify → EAR JWT), listening on `config.listen`
//! - Hydra TCP daemon (SignedDeviceClientInfor → encrypted response + PublicContext broadcast),
//!   listening on `config.hydra.listen`
//!
//! The two are independent: gRPC handles wasm-based TEE evidence; the TCP daemon owns the
//! shrubs tree, batch scheduling, and PublicContext distribution.

mod cca_native;
mod config;
mod csv_native;
mod ear;
mod grpc;
mod itrustee_native;
mod virtcca_native;
mod wasm_host;

use anyhow::{Context, Result};
use clap::Parser;
use protos::verifier_service_server::VerifierServiceServer;
use std::path::PathBuf;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "unified-attestation verifier")]
struct Cli {
    #[arg(short, long, default_value = "config/verifier.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let config = config::Config::load(&cli.config)
        .with_context(|| format!("load config from {}", cli.config.display()))?;

    let host = wasm_host::WasmHost::new(&config).await?;
    let signing = ear::SigningContext::new(&config.ear)?;

    let cca_verifier = cca_native::CcaVerifier::load(&config.policy.cca)?;
    cca_native::warn_no_store(&config.policy.cca);
    let csv_verifier = csv_native::CsvVerifier::load(&config.policy.csv);
    if !config.policy.csv.enabled {
        tracing::warn!(
            "CSV policy disabled (policy.csv.enabled=false); host-side CSV verification skipped."
        );
    }

    // Spawn the hydra TCP daemon alongside gRPC. The two are independent: gRPC handles
    // wasm-based TEE evidence; the TCP daemon owns the shrubs tree, batch scheduling, and
    // PublicContext distribution. Failures in the daemon are logged but do not tear down gRPC.
    let hydra_cfg = verifier::hydra_daemon::HydraDaemonConfig {
        listen_addr: config.hydra.listen.clone(),
        relying_party_addrs: config.hydra.relying_party_addrs.clone(),
        data_dir: config.hydra.data_dir.clone(),
    };
    tokio::spawn(async move {
        if let Err(err) = verifier::hydra_daemon::run(hydra_cfg).await {
            eprintln!("hydra daemon exited: {:#}", err);
        }
    });

    let state = Arc::new(grpc::AppState {
        host,
        signing,
        cca_policy: config.policy.cca,
        tdx_policy: config.policy.tdx,
        cca_verifier,
        csv_verifier,
    });

    let addr = config
        .listen
        .parse()
        .with_context(|| format!("parse listen '{}'", config.listen))?;
    info!(%addr, "verifier gRPC listening");
    Server::builder()
        .add_service(VerifierServiceServer::from_arc(state))
        .serve(addr)
        .await?;
    Ok(())
}
