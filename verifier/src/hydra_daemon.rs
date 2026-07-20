//! Hydra TCP daemon — runs alongside gRPC in the same verifier process.
//!
//! ponytail: copied wholesale from /data/home/likozhang/Codes/rats_workspace/hydra/verifier/src/main.rs
//! (batch window, encrypted response, PublicContext broadcast). Data directory is passed in
//! instead of derived from CARGO_MANIFEST_DIR.

use anyhow::{Context, Result};
use hydra_toolkit::shurbstree::{affected_indices, create_batch_devices};
use hydra_toolkit::{
    BlsScalar, KeyInfor, MSG_DEVICE_INFOR, Poseidon, PublicContext, VERIFIER_KEY_FILE,
    decode_signed_device_client_infor_message, default_hasher, encode_encrypted_verifier_response,
    encode_public_context_message, find_device_shrubs_path_tag, generate_device_authoried_infor,
    insert_batch_devices, load_key_infor, save_key_infor, save_response_device_infor,
    tcp_read_frame, tcp_send_frame, verify_device_client_infor_freshness,
    verify_signed_device_client_infor_wire,
};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::verifier_compute_sig;

const BATCH_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// Configuration for the hydra TCP daemon, assembled from `[hydra]` section in verifier.toml.
pub struct HydraDaemonConfig {
    /// TCP listen address (default 127.0.0.1:7001)
    pub listen_addr: String,
    /// Relying-party endpoints that receive PublicContext on every batch
    pub relying_party_addrs: Vec<String>,
    /// Persistent directory: `verifier_key.bin`, and `verifier-responses/` cache
    pub data_dir: PathBuf,
}

/// Entry point for the hydra TCP daemon. Binds `listen_addr`, loads or generates
/// the verifier secp256k1 key, then enters an accept loop. Each incoming attester
/// TCP connection is handled in a spawned task. The daemon runs indefinitely;
/// callers should spawn it with `tokio::spawn`.
pub async fn run(config: HydraDaemonConfig) -> Result<()> {
    fs::create_dir_all(&config.data_dir).context("create hydra data dir failed")?;
    let key_path = config.data_dir.join(VERIFIER_KEY_FILE);
    let verifier_key = if key_path.exists() {
        println!("loading verifier key from: {}", key_path.display());
        load_key_infor(&key_path).context("load verifier key failed")?
    } else {
        let key = KeyInfor::new();
        save_key_infor(&key_path, &key).context("save generated verifier key failed")?;
        println!("generated verifier key at: {}", key_path.display());
        key
    };
    let verifier_key = Arc::new(verifier_key);

    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("hydra TCP listen failed: {}", config.listen_addr))?;
    println!(
        "hydra daemon started, listening on: {} (batch {}s)",
        config.listen_addr,
        BATCH_INTERVAL.as_secs()
    );

    let state = Arc::new(Mutex::new(VerifierState::new()));
    let data_dir = Arc::new(config.data_dir);
    loop {
        let (socket, peer) = listener.accept().await.context("accept TCP failed")?;
        println!("hydra: accepted connection from {}", peer);
        let request_state = Arc::clone(&state);
        let request_verifier_key = Arc::clone(&verifier_key);
        let request_relying_party_addrs = config.relying_party_addrs.clone();
        let request_data_dir = Arc::clone(&data_dir);
        tokio::spawn(async move {
            if let Err(err) = handle_request(
                socket,
                request_state,
                request_verifier_key,
                request_relying_party_addrs,
                request_data_dir,
            )
            .await
            {
                eprintln!("hydra: handle request failed: {:#}", err);
            }
        });
    }
}

#[derive(Clone)]
struct AttesterSession {
    socket: Arc<Mutex<TcpStream>>,
    dev_infor: hydra_toolkit::DeviceClientInfor,
    merkle_leaf: BlsScalar,
    response: Option<hydra_toolkit::ResponseDeviceInfor>,
    attester_addr: String,
}

struct VerifierState {
    root: Vec<BlsScalar>,
    old_leaves: Vec<BlsScalar>,
    pending: Vec<AttesterSession>,
    active: Vec<AttesterSession>,
    has_created_tree: bool,
    batch_timer_running: bool,
}

impl VerifierState {
    fn new() -> Self {
        Self {
            root: Vec::new(),
            old_leaves: Vec::new(),
            pending: Vec::new(),
            active: Vec::new(),
            has_created_tree: false,
            batch_timer_running: false,
        }
    }
}

async fn handle_request(
    mut socket: TcpStream,
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
    data_dir: Arc<PathBuf>,
) -> Result<()> {
    let peer_addr = socket
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let message = tcp_read_frame(&mut socket).await?;

    if message.starts_with(MSG_DEVICE_INFOR) {
        let signed_dev_infor = decode_signed_device_client_infor_message(&message)
            .context("decode signed attester DeviceClientInfor failed")?;
        let dev_infor = verify_signed_device_client_infor_wire(&signed_dev_infor)
            .context("verify attester DeviceClientInfor signature failed")?;
        verify_device_client_infor_freshness(&dev_infor)
            .context("verify DeviceClientInfor freshness failed")?;
        return queue_attester(
            socket,
            state,
            verifier_key,
            relying_party_addrs,
            data_dir,
            dev_infor,
            peer_addr,
        )
        .await;
    }

    anyhow::bail!("unknown hydra message type: {:?}", message.get(..4));
}

async fn queue_attester(
    socket: TcpStream,
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
    data_dir: Arc<PathBuf>,
    dev_infor: hydra_toolkit::DeviceClientInfor,
    attester_addr: String,
) -> Result<()> {
    let merkle_leaf = dev_infor.merkle_leaf;

    // Atomically push into pending queue and check whether we need to start a
    // batch timer. Only the first attester in an empty batch starts the timer;
    // subsequent attesters during the window are silently queued. This prevents
    // multiple concurrent timers from racing on the same state.
    let should_start_timer = {
        let mut state = state.lock().await;
        state.pending.push(AttesterSession {
            socket: Arc::new(Mutex::new(socket)),
            dev_infor,
            merkle_leaf,
            response: None,
            attester_addr,
        });
        println!("hydra: queued attester; pending={}", state.pending.len());
        if state.batch_timer_running {
            false
        } else {
            state.batch_timer_running = true;
            true
        }
    };

    if should_start_timer {
        tokio::spawn(async move {
            tokio::time::sleep(BATCH_INTERVAL).await;
            process_batch(state, verifier_key, relying_party_addrs, data_dir).await;
        });
    }
    Ok(())
}

struct ComputedResponse {
    index: usize,
    socket: Arc<Mutex<TcpStream>>,
    attester_addr: String,
    response: hydra_toolkit::ResponseDeviceInfor,
    encrypted: Vec<u8>,
}

type AttesterSnapshot = (usize, AttesterSession);

/// Batch processing: drain pending attesters → insert leaves into shrubs → compute new
/// root → build path/tag per attester → send encrypted responses to affected attesters,
/// PublicContext-only to unaffected ones, and PublicContext to all relying-parties.
async fn process_batch(
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
    data_dir: Arc<PathBuf>,
) {
    let hasher_vfy = default_hasher();
    let (
        affected_old_snapshots,
        unaffected_old_snapshots,
        new_snapshots,
        root,
        leaves,
        public_context,
    ) = {
        let mut state = state.lock().await;

        if state.pending.is_empty() {
            state.batch_timer_running = false;
            println!("hydra: batch window closed; no pending");
            return;
        }

        let old_total = state.active.len();
        let mut pending = std::mem::take(&mut state.pending);
        state.batch_timer_running = false;
        let inserted = pending.len();
        // Collect all merkle leaves from the pending batch
        let batch_leaves: Vec<BlsScalar> = pending.iter().map(|item| item.merkle_leaf).collect();

        // Insert batch leaves into the shrubs tree
        if state.has_created_tree {
            // Subsequent batch: incremental insert into existing tree
            let old_leaves_before_insert = state.old_leaves.clone();
            let mut new_leaves = batch_leaves.clone();
            insert_batch_devices(
                &mut state.root,
                &old_leaves_before_insert,
                &mut new_leaves,
                &hasher_vfy,
            );
            state.old_leaves.extend(batch_leaves);
        } else {
            // First batch: build the shrubs tree from scratch with all current leaves
            state.old_leaves.extend(batch_leaves);
            state.root.clear();
            let leaves = state.old_leaves.clone();
            create_batch_devices(&mut state.root, &leaves, &hasher_vfy);
            state.has_created_tree = true;
        }

        state.active.append(&mut pending);

        // Compute which old attesters are affected by the tree restructure
        let affected_old: Vec<usize> = if old_total == 0 {
            Vec::new() // no old attesters, nothing to affect
        } else {
            affected_indices(old_total, inserted)
                .into_iter()
                .map(|index| index - 1) // convert 1-based to 0-based
                .collect()
        };
        let mut needs_path_refresh = vec![false; old_total];
        for index in &affected_old {
            if let Some(value) = needs_path_refresh.get_mut(*index) {
                *value = true;
            }
        }

        let new_indices = old_total..old_total + inserted;
        let public_context = PublicContext {
            root: state.root.clone(),
            verifier_pk: verifier_key.verifying_key,
        };
        let affected_old_snapshots = affected_old
            .into_iter()
            .filter_map(|index| state.active.get(index).cloned().map(|item| (index, item)))
            .collect::<Vec<_>>();
        let unaffected_old_snapshots = state
            .active
            .iter()
            .take(old_total)
            .cloned()
            .enumerate()
            .filter(|(index, _)| !needs_path_refresh[*index])
            .collect::<Vec<_>>();
        let new_snapshots = new_indices
            .filter_map(|index| state.active.get(index).cloned().map(|item| (index, item)))
            .collect::<Vec<_>>();

        (
            affected_old_snapshots,
            unaffected_old_snapshots,
            new_snapshots,
            state.root.clone(),
            state.old_leaves.clone(),
            public_context,
        )
    };

    // Send order matters: affected old attesters first (they waited the longest),
    // then RP gets the new PublicContext so it can verify evidence from new attesters,
    // then new attesters receive their encrypted responses.
    //
    // 1. Affected old attesters: path/tag shifted by the insert → recompute and re-encrypt
    compute_store_and_send_responses(
        "affected old attester",
        &affected_old_snapshots,
        &state,
        &root,
        &leaves,
        &hasher_vfy,
        &verifier_key,
        &public_context,
        &data_dir,
    )
    .await;

    // 2. Unaffected old attesters: only root changed, path/tag unchanged. Sending
    // a full encrypted response would waste computation — PublicContext alone suffices.
    send_context_only_refreshes(&unaffected_old_snapshots, &public_context).await;

    // 3. RP must receive the new root *before* any evidence from this batch arrives,
    // otherwise evidence verification would fail against the stale cached root.
    publish_public_context_to_all(&relying_party_addrs, &public_context).await;

    // 4. New attesters: first-ever path/tag computation → full encrypted response
    compute_store_and_send_responses(
        "new attester",
        &new_snapshots,
        &state,
        &root,
        &leaves,
        &hasher_vfy,
        &verifier_key,
        &public_context,
        &data_dir,
    )
    .await;
}

async fn compute_store_and_send_responses(
    label: &str,
    snapshots: &[AttesterSnapshot],
    state: &Arc<Mutex<VerifierState>>,
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    hasher_vfy: &Poseidon<BlsScalar>,
    verifier_key: &KeyInfor,
    public_context: &PublicContext,
    data_dir: &Path,
) {
    if snapshots.is_empty() {
        return;
    }

    let computed: Vec<Result<ComputedResponse>> = snapshots
        .par_iter()
        .map(|(index, item)| {
            build_encrypted_attester_response(
                *index,
                item,
                root,
                leaves,
                hasher_vfy,
                verifier_key,
                public_context,
            )
        })
        .collect();

    let mut send_jobs = Vec::new();
    {
        let mut state = state.lock().await;
        for result in computed {
            match result {
                Ok(computed) => {
                    if let Err(err) = persist_response(data_dir, &computed.response) {
                        eprintln!("hydra: persist verifier response failed: {:#}", err);
                    }
                    if let Some(session) = state.active.get_mut(computed.index) {
                        session.response = Some(computed.response);
                    }
                    send_jobs.push((computed.socket, computed.attester_addr, computed.encrypted));
                }
                Err(err) => eprintln!("hydra: build verifier response failed: {:#}", err),
            }
        }
    }

    for (socket, attester_addr, encrypted) in send_jobs {
        let mut socket = socket.lock().await;
        if let Err(err) = tcp_send_frame(&mut socket, &encrypted).await {
            eprintln!("hydra: send response to {} failed: {:#}", attester_addr, err);
        } else {
            println!("hydra: sent {} response to {}", label, attester_addr);
        }
    }
}

async fn send_context_only_refreshes(
    snapshots: &[AttesterSnapshot],
    public_context: &PublicContext,
) {
    if snapshots.is_empty() {
        return;
    }
    let message = match encode_public_context_message(public_context) {
        Ok(message) => message,
        Err(err) => {
            eprintln!("hydra: build public context message failed: {:#}", err);
            return;
        }
    };
    for (_, item) in snapshots {
        let socket = Arc::clone(&item.socket);
        let message = message.clone();
        let mut socket = socket.lock().await;
        if let Err(err) = tcp_send_frame(&mut socket, &message).await {
            eprintln!("hydra: send public context to attester failed: {:#}", err);
        }
    }
}

fn build_encrypted_attester_response(
    index: usize,
    item: &AttesterSession,
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    hasher_vfy: &Poseidon<BlsScalar>,
    verifier_key: &KeyInfor,
    public_context: &PublicContext,
) -> Result<ComputedResponse> {
    let mut dev_res = item
        .response
        .clone()
        .unwrap_or_else(|| hydra_toolkit::ResponseDeviceInfor::new(item.dev_infor.verifying_key));
    dev_res.attester_addr = item.attester_addr.clone();

    let (merkel_path, merkel_tag) =
        find_device_shrubs_path_tag(root, leaves, &item.merkle_leaf, hasher_vfy);
    dev_res.shrubs_path = merkel_path;
    dev_res.shrubs_tag = merkel_tag;

    let device_author_infor =
        generate_device_authoried_infor(&item.dev_infor, &dev_res, hasher_vfy);
    let sig = verifier_compute_sig(verifier_key, &dev_res, &device_author_infor);
    dev_res.set_signature(&sig);

    let encrypted = encode_encrypted_verifier_response(
        &dev_res,
        public_context,
        &item.dev_infor.verifying_key,
    )?;

    Ok(ComputedResponse {
        index,
        socket: Arc::clone(&item.socket),
        attester_addr: item.attester_addr.clone(),
        response: dev_res,
        encrypted,
    })
}

fn persist_response(
    data_dir: &Path,
    response: &hydra_toolkit::ResponseDeviceInfor,
) -> Result<()> {
    let dir = data_dir.join("verifier-responses");
    fs::create_dir_all(&dir).context("create verifier response store failed")?;
    let safe_name: String = response
        .attester_addr
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    save_response_device_infor(dir.join(format!("{}.bin", safe_name)), response)
}

async fn publish_public_context_to_all(addrs: &[String], public_context: &PublicContext) {
    for addr in addrs {
        if let Err(err) = publish_public_context(addr, public_context).await {
            eprintln!("hydra: publish public context to {} failed: {:#}", addr, err);
        }
    }
}

async fn publish_public_context(addr: &str, public_context: &PublicContext) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect relying-party failed: {}", addr))?;
    let message = encode_public_context_message(public_context)?;
    tcp_send_frame(&mut stream, &message)
        .await
        .context("publish PublicContext to relying-party failed")?;
    Ok(())
}
