//! Hydra TCP listener — merges verifier PublicContext broadcasts and attester EvidenceReply
//! frames. ponytail: reduced from hydra reference relying-party/src/main.rs, single-flight
//! per accepted connection.

use anyhow::{Context, Result};
use hydra_toolkit::{
    MSG_EVIDENCE, MSG_PUBLIC_CONTEXT, PUBLIC_CONTEXT_FILE, PublicContext, decode_evidence_message,
    decode_public_context_message, load_public_context, save_public_context, tcp_read_frame,
    tcp_send_frame,
};
use relying_party::{
    rely_party_verification, verify_evidence_reply_attester_freshness,
    verify_evidence_reply_attester_signature,
    verify_evidence_reply_proof_timestamp_period_signature,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Configuration for the RP-side hydra TCP listener.
pub struct HydraListenerConfig {
    /// TCP listen address (default 127.0.0.1:7002)
    pub listen_addr: String,
    /// Directory for caching the latest `public_context.bin`
    pub data_dir: PathBuf,
}

/// Entry point for the RP hydra TCP listener. Binds `listen_addr`, loads any
/// previously-cached PublicContext, then enters an accept loop. Each incoming
/// TCP connection is handled in a spawned task — either a verifier pushing
/// PublicContext or an attester submitting EvidenceReply.
pub async fn run(cfg: HydraListenerConfig) -> Result<()> {
    fs::create_dir_all(&cfg.data_dir).context("create hydra data dir failed")?;
    let context_path = cfg.data_dir.join(PUBLIC_CONTEXT_FILE);
    let initial = load_public_context(&context_path).ok();
    let state = Arc::new(Mutex::new(initial));

    let listener = TcpListener::bind(&cfg.listen_addr)
        .await
        .with_context(|| format!("hydra listen failed: {}", cfg.listen_addr))?;
    println!("hydra: RP listening on {}", cfg.listen_addr);

    loop {
        let (mut socket, peer) = listener.accept().await.context("accept TCP failed")?;
        println!("hydra: RP accepted {}", peer);
        let state = Arc::clone(&state);
        let context_path = context_path.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(&mut socket, &state, &context_path).await {
                eprintln!("hydra: RP handle failed: {:#}", err);
                let _ = tcp_send_frame(&mut socket, format!("error: {:#}", err).as_bytes()).await;
            }
        });
    }
}

async fn handle(
    socket: &mut TcpStream,
    state: &Arc<Mutex<Option<PublicContext>>>,
    context_path: &std::path::Path,
) -> Result<()> {
    let message = tcp_read_frame(socket).await?;

    if message.starts_with(MSG_PUBLIC_CONTEXT) {
        let ctx = decode_public_context_message(&message)
            .context("decode PublicContext failed")?;
        save_public_context(context_path, &ctx).context("save PublicContext failed")?;
        *state.lock().await = Some(ctx);
        return Ok(());
    }

    if message.starts_with(MSG_EVIDENCE) {
        let (reply, sig) =
            decode_evidence_message(&message).context("decode EvidenceReply failed")?;

        // Three pre-checks before the heavy Groth16 verify:
        verify_evidence_reply_attester_freshness(&reply)?;         // timestamp_attester not expired
        verify_evidence_reply_proof_timestamp_period_signature(&reply)?; // proof freshness sig
        verify_evidence_reply_attester_signature(&reply, &sig)?;   // attester signed this reply

        // Must have a cached PublicContext from the verifier
        let ctx_owned = state.lock().await.clone();
        let Some(ctx) = ctx_owned else {
            tcp_send_frame(socket, b"verification failed: missing PublicContext").await?;
            anyhow::bail!("missing PublicContext");
        };

        // Core: Groth16 verify + verifier authorization sig check
        let verified = rely_party_verification(&ctx.root, &reply, sig, &ctx.verifier_pk)?;
        let ack: &[u8] = if verified {
            b"verification success"
        } else {
            b"verification failed"
        };
        tcp_send_frame(socket, ack).await?;
        return Ok(());
    }

    anyhow::bail!("unknown message type, first 4 bytes: {:?}", message.get(..4));
}
