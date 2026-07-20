//! Hydra TCP client task — runs alongside the attester gRPC service.
//!
//! Two entry points:
//! - [`run`]: long-lived task, spawned by main when `[hydra]` is present. Bootstraps a session
//!   (submit → encrypted response → save DeviceConfigInfor + PublicContext) then loops on
//!   verifier updates. Does NOT auto-ship evidence.
//! - [`send_evidence_from_session`]: called by the `hydra-evidence` CLI subcommand to build
//!   an EvidenceReply from a saved session and ship it to relying-party addresses.

use crate::config::HydraClientConfig;
use anyhow::{Context, Result, bail};
use attester::{
    DeviceConfigInfor, generate_device_evidence_from_config, load_device_config_infor,
    save_device_config_infor,
};
use hydra_toolkit::{
    ATTESTER_KEY_FILE, DEVICE_CONFIG_FILE, DEVICE_INFOR_FILE, KeyInfor, MSG_PUBLIC_CONTEXT,
    PUBLIC_CONTEXT_FILE, VERIFIER_RESPONSE_FILE, decode_encrypted_verifier_response,
    decode_public_context_message, default_hasher, encode_evidence_message,
    encode_signed_device_client_infor_message, generate_device_client_infor, load_key_infor,
    load_public_context, save_device_client_infor, save_key_infor, save_public_context,
    save_response_device_infor, sign_device_client_infor_to_wire, tcp_read_frame, tcp_send_frame,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

const LATEST_SESSION_FILE: &str = "attester_latest_session.txt";

/// Run the attester's hydra client task: load or generate an attester key,
/// create a session directory, build a SignedDeviceClientInfor, connect to
/// the verifier TCP daemon, submit, and loop on encrypted responses +
/// PublicContext refreshes. This task does NOT auto-ship EvidenceReply — use
/// the `hydra-evidence` subcommand for that.
pub async fn run(cfg: HydraClientConfig) -> Result<()> {
    fs::create_dir_all(&cfg.data_dir).context("create hydra data dir failed")?;
    let key_path = cfg.data_dir.join(ATTESTER_KEY_FILE);
    let dev_key = if key_path.exists() {
        println!("hydra: loading attester key from {}", key_path.display());
        load_key_infor(&key_path).context("load attester key failed")?
    } else {
        let key = KeyInfor::new();
        save_key_infor(&key_path, &key).context("save attester key failed")?;
        println!("hydra: generated attester key at {}", key_path.display());
        key
    };

    let session_dir = create_session_dir(&cfg.data_dir)?;
    println!("hydra: session path {}", session_dir.display());
    write_latest_session(&cfg.data_dir, &session_dir)?;

    let hasher_dev = default_hasher();
    let dev_infor = generate_device_client_infor(&dev_key, &hasher_dev);
    save_device_client_infor(session_dir.join(DEVICE_INFOR_FILE), &dev_infor)
        .context("save DeviceClientInfor failed")?;

    let signed_dev_infor = sign_device_client_infor_to_wire(&dev_infor, &dev_key)?;
    let signed_msg = encode_signed_device_client_infor_message(&signed_dev_infor)?;

    let mut stream = TcpStream::connect(&cfg.verifier_addr)
        .await
        .with_context(|| format!("connect verifier failed: {}", cfg.verifier_addr))?;
    tcp_send_frame(&mut stream, &signed_msg)
        .await
        .context("send SignedDeviceClientInfor failed")?;
    println!("hydra: sent SignedDeviceClientInfor to {}", cfg.verifier_addr);

    // First response: encrypted ResponseDeviceInfor + PublicContext, build DeviceConfigInfor.
    // The auto-loop no longer ships evidence — use the `hydra-evidence` CLI subcommand for that.
    read_response_and_persist(
        &mut stream,
        &dev_key,
        &dev_infor,
        &hasher_dev,
        &session_dir,
    )
    .await
    .context("read initial hydra response failed")?;

    // Subsequent messages: PublicContext-only refresh, or another encrypted response when
    // path/tag changes on a later batch. Loop forever until the stream closes.
    loop {
        if let Err(err) = read_response_and_persist(
            &mut stream,
            &dev_key,
            &dev_infor,
            &hasher_dev,
            &session_dir,
        )
        .await
        {
            eprintln!("hydra: update loop stopped: {:#}", err);
            return Ok(());
        }
    }
}

fn create_session_dir(data_dir: &Path) -> Result<std::path::PathBuf> {
    let base = data_dir.join("attester-runs");
    fs::create_dir_all(&base).context("create attester-runs dir failed")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")?
        .as_nanos();
    let pid = std::process::id();
    for counter in 0..1000u32 {
        let dir = base.join(format!("attester-{}-{}-{}", now, pid, counter));
        if !dir.exists() {
            fs::create_dir_all(&dir).context("create session dir failed")?;
            return Ok(dir);
        }
    }
    bail!("failed to create a unique session dir")
}

/// Read one frame from the verifier TCP stream. Two possible payloads:
/// 1. Plaintext PublicContext (prefix "PUBC") — root/verifier_pk refresh, no path change.
/// 2. AES-GCM ciphertext — encrypted ResponseDeviceInfor + PublicContext, decoded with
///    attester's ECDH key. Triggers a DeviceConfigInfor rebuild.
async fn read_response_and_persist(
    stream: &mut TcpStream,
    dev_key: &KeyInfor,
    dev_infor: &hydra_toolkit::DeviceClientInfor,
    hasher: &hydra_toolkit::Poseidon<hydra_toolkit::BlsScalar>,
    session_dir: &Path,
) -> Result<()> {
    let bytes = tcp_read_frame(stream).await.context("read verifier update failed")?;

    // Verifier rejection: close the connection
    if bytes.starts_with(b"verification failed:") || bytes.starts_with(b"error:") {
        bail!(
            "verifier rejected DeviceClientInfor: {}",
            String::from_utf8_lossy(&bytes)
        );
    }

    // Plaintext PublicContext refresh: root changed but our path/tag did not.
    // Only update the cached public_context.bin; dev_config.bin stays unchanged.
    if bytes.starts_with(MSG_PUBLIC_CONTEXT) {
        let ctx = decode_public_context_message(&bytes)
            .context("decode PublicContext failed")?;
        save_public_context(session_dir.join(PUBLIC_CONTEXT_FILE), &ctx)
            .context("save PublicContext failed")?;
        println!("hydra: PublicContext refresh; root_len={}", ctx.root.len());
        return Ok(());
    }

    // Encrypted response: path/tag changed (first batch or shrubs restructure).
    // Decrypt with our ECDH key → rebuild DeviceConfigInfor → persist everything.
    let (dev_res, public_context) =
        decode_encrypted_verifier_response(&bytes, dev_key)
            .context("decrypt verifier response failed")?;
    save_response_device_infor(session_dir.join(VERIFIER_RESPONSE_FILE), &dev_res)
        .context("save ResponseDeviceInfor failed")?;
    save_public_context(session_dir.join(PUBLIC_CONTEXT_FILE), &public_context)
        .context("save PublicContext failed")?;

    // Rebuild DeviceConfigInfor from the fresh verifier response
    let dev_config = DeviceConfigInfor::new(dev_key, dev_infor, &dev_res, hasher);
    save_device_config_infor(session_dir.join(DEVICE_CONFIG_FILE), &dev_config)
        .context("save DeviceConfigInfor failed")?;
    println!(
        "hydra: encrypted response saved; root_len={}, has_path={}, has_tag={}, has_sig={}",
        public_context.root.len(),
        dev_res.shrubs_path.is_some(),
        dev_res.shrubs_tag.is_some(),
        dev_res.sig.is_some()
    );

    Ok(())
}

/// Ship an EvidenceReply built from a saved session to the given relying-party addresses.
/// Called by the `hydra-evidence` CLI subcommand. `session_dir = None` → read the latest
/// session pointer written by the auto-loop.
pub async fn send_evidence_from_session(
    data_dir: &Path,
    session_dir: Option<PathBuf>,
    relying_party_addrs: &[String],
) -> Result<()> {
    let session_dir = match session_dir {
        Some(path) => {
            if !path.exists() {
                bail!("attester session path does not exist: {}", path.display());
            }
            path
        }
        None => read_latest_session(data_dir)?,
    };
    println!("hydra: sending evidence from session {}", session_dir.display());

    let hasher = default_hasher();
    let dev_config = load_device_config_infor(session_dir.join(DEVICE_CONFIG_FILE))
        .context("load DeviceConfigInfor failed; run the attester daemon first")?;
    let public_context = load_public_context(session_dir.join(PUBLIC_CONTEXT_FILE))
        .context("load PublicContext failed; run the attester daemon first")?;

    let (reply, sig) =
        generate_device_evidence_from_config(&public_context.root, &dev_config, &hasher);
    let msg = encode_evidence_message(&reply, &sig)?;

    for addr in relying_party_addrs {
        if let Err(err) = ship_evidence_to_rp(addr, &msg).await {
            eprintln!("hydra: ship evidence to {} failed: {:#}", addr, err);
        }
    }
    Ok(())
}

fn write_latest_session(data_dir: &Path, session_dir: &Path) -> Result<()> {
    fs::write(
        data_dir.join(LATEST_SESSION_FILE),
        session_dir.to_string_lossy().as_bytes(),
    )
    .context("write latest session pointer failed")
}

fn read_latest_session(data_dir: &Path) -> Result<PathBuf> {
    let contents = fs::read_to_string(data_dir.join(LATEST_SESSION_FILE)).context(
        "read latest session pointer failed; pass --session <path> or run the daemon first",
    )?;
    let path = PathBuf::from(contents.trim());
    if !path.exists() {
        bail!("latest session path does not exist: {}", path.display());
    }
    Ok(path)
}

async fn ship_evidence_to_rp(addr: &str, msg: &[u8]) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect relying-party failed: {}", addr))?;
    tcp_send_frame(&mut stream, msg)
        .await
        .context("send evidence failed")?;
    let ack = tcp_read_frame(&mut stream).await.context("read RP ack failed")?;
    println!(
        "hydra: relying-party {} evidence result: {}",
        addr,
        String::from_utf8_lossy(&ack)
    );
    Ok(())
}
