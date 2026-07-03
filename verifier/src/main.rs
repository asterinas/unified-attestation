use anyhow::{Context, Result};
use chrono::Utc;
use hydra_toolkit::device_vc::{
    DeviceVCCache, IotaPublishConfig, build_background_check_record, default_device_vc_cache_path,
    publish_device_vc_to_iota, refresh_record_documents,
};
use hydra_toolkit::shurbstree::{affected_indices, create_batch_devices};
use hydra_toolkit::{
    BlsScalar, DATA_DIR_NAME, DEFAULT_RELYING_PARTY_ADDR, DEFAULT_VERIFIER_ADDR, KeyInfor,
    MSG_DEVICE_INFOR, MSG_RELYING_PARTY_DEVICE_INFOR, Model, Poseidon, PublicContext,
    decode_relying_party_signed_device_client_infor_message,
    decode_signed_device_client_infor_message, default_hasher, encode_encrypted_verifier_response,
    encode_public_context_message, find_device_shrubs_path_tag, generate_device_authoried_infor,
    insert_batch_devices, save_response_device_infor, tcp_read_frame, tcp_send_frame,
    verify_device_client_infor_freshness, verify_relying_party_signed_device_client_infor_wire,
    verify_signed_device_client_infor_wire,
};
use rayon::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use verifier::verifier_compute_sig;

const BATCH_INTERVAL: Duration = Duration::from_secs(2 * 60);
const VC_EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const IOTA_NETWORK: &str = "tst";

fn role_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DATA_DIR_NAME)
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

fn parse_args() -> (String, Vec<String>) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verifier_addr = args
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string());
    let relying_party_addrs = if args.len() > 1 {
        args[1..].to_vec()
    } else {
        vec![DEFAULT_RELYING_PARTY_ADDR.to_string()]
    };
    (verifier_addr, relying_party_addrs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let (verifier_addr, relying_party_addrs) = parse_args();

    let listener = TcpListener::bind(&verifier_addr)
        .await
        .with_context(|| format!("verifier listen failed: {}", verifier_addr))?;

    let state = Arc::new(Mutex::new(VerifierState::new()));
    let verifier_key = Arc::new(KeyInfor::new());
    schedule_device_vc_expiration_task();

    println!("verifier started, listening on: {}", verifier_addr);
    println!("relying-party addresses: {:?}", relying_party_addrs);
    println!("batch interval: {} seconds", BATCH_INTERVAL.as_secs());

    loop {
        let (socket, peer) = listener.accept().await.context("accept TCP failed")?;
        println!("accepted attester/relying-party connection from {}", peer);

        let request_state = Arc::clone(&state);
        let request_verifier_key = Arc::clone(&verifier_key);
        let request_relying_party_addrs = relying_party_addrs.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_request(
                socket,
                request_state,
                request_verifier_key,
                request_relying_party_addrs,
            )
            .await
            {
                eprintln!("handle verifier request failed: {:#}", err);
            }
        });
    }
}

async fn handle_request(
    mut socket: TcpStream,
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
) -> Result<()> {
    let peer_addr = socket
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let message = tcp_read_frame(&mut socket).await?;

    if message.starts_with(MSG_DEVICE_INFOR) {
        let signed_dev_infor = decode_signed_device_client_infor_message(&message)
            .context("decode signed attester DeviceClientInfor failed")?;

        match signed_dev_infor.device.mode {
            Model::Passport => {
                let dev_infor = verify_signed_device_client_infor_wire(&signed_dev_infor)
                    .context("verify attester DeviceClientInfor signature failed")?;
                verify_device_client_infor_freshness(&dev_infor)
                    .context("verify passport DeviceClientInfor freshness failed")?;
                if dev_infor.evidence_cmw_json.is_empty() {
                    tcp_send_frame(
                        &mut socket,
                        b"verification failed: passport DeviceClientInfor evidence_cmw_json verification failed",
                    )
                    .await
                    .context("send passport evidence_cmw_json validation error failed")?;
                    return Ok(());
                }
                return queue_passport_attester(
                    socket,
                    state,
                    verifier_key,
                    relying_party_addrs,
                    dev_infor,
                    peer_addr,
                )
                .await;
            }
            Model::BackgroundCheck => {
                tcp_send_frame(
                    &mut socket,
                    b"error: background_check DeviceClientInfor must be signed and forwarded by relying-party",
                )
                .await
                .context("send background_check direct-to-verifier error failed")?;
                return Ok(());
            }
        }
    }

    if message.starts_with(MSG_RELYING_PARTY_DEVICE_INFOR) {
        let relying_party_signed =
            decode_relying_party_signed_device_client_infor_message(&message)
                .context("decode relying-party signed DeviceClientInfor failed")?;

        if relying_party_signed.signed_device.device.mode != Model::BackgroundCheck {
            anyhow::bail!(
                "relying-party signed DeviceClientInfor is only accepted for background_check"
            );
        }

        verify_relying_party_signed_device_client_infor_wire(&relying_party_signed)
            .context("verify relying-party DeviceClientInfor signature failed")?;
        let dev_infor = verify_signed_device_client_infor_wire(&relying_party_signed.signed_device)
            .context("verify attester DeviceClientInfor signature failed")?;
        verify_device_client_infor_freshness(&dev_infor)
            .context("verify background_check DeviceClientInfor freshness failed")?;

        println!("background_check relying-party and attester signatures verified");
        let vc_result = match process_background_check_device_vc(&dev_infor) {
            Ok(message) => message,
            Err(err) => {
                let message = format!("background_check VC publish failed: {err:#}");
                eprintln!("{message}");
                message
            }
        };
        tcp_send_frame(&mut socket, vc_result.as_bytes())
            .await
            .context("send background_check verifier ack failed")?;
        return Ok(());
    }

    anyhow::bail!("unknown verifier message type: {:?}", message.get(..4));
}

fn process_background_check_device_vc(dev_infor: &hydra_toolkit::DeviceClientInfor) -> Result<String> {
    let now = Utc::now();
    let config = IotaPublishConfig::from_env()?;
    expire_cached_device_vcs(now, &config)?;

    let cache_path =
        default_device_vc_cache_path(PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path());
    let mut cache = DeviceVCCache::load_or_default(&cache_path)?;
    let mut record = build_background_check_record(dev_infor, IOTA_NETWORK, now)?;
    let object_id = publish_device_vc_to_iota(&record, &config)?;
    record.chain_object_id = object_id.clone();
    let status = record.vc_info.status;
    let device_did = record.vc_info.device_did.clone();
    cache.upsert(record);
    cache.save(&cache_path)?;

    Ok(format!(
        "background_check VC published; did={device_did}; status={status:?}; object_id={}",
        object_id.unwrap_or_else(|| "unknown".to_string())
    ))
}

fn schedule_device_vc_expiration_task() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(VC_EXPIRATION_CHECK_INTERVAL).await;
            let Ok(config) = IotaPublishConfig::from_env() else {
                eprintln!(
                    "skip device VC expiration check: IOTA_DEVICE_VC_PACKAGE_ID is not configured"
                );
                continue;
            };
            if let Err(err) = expire_cached_device_vcs(Utc::now(), &config) {
                eprintln!("device VC expiration check failed: {:#}", err);
            }
        }
    });
}

fn expire_cached_device_vcs(now: chrono::DateTime<Utc>, config: &IotaPublishConfig) -> Result<()> {
    let cache_path =
        default_device_vc_cache_path(PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path());
    let mut cache = DeviceVCCache::load_or_default(&cache_path)?;
    let expired_records = cache.expire_trusted(now);

    for mut expired in expired_records {
        refresh_record_documents(&mut expired, IOTA_NETWORK)?;
        match publish_device_vc_to_iota(&expired, config) {
            Ok(object_id) => {
                expired.chain_object_id = object_id;
                cache.upsert(expired);
            }
            Err(err) => eprintln!("publish expired device VC failed: {:#}", err),
        }
    }

    cache.save(&cache_path)
}

async fn queue_passport_attester(
    socket: TcpStream,
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
    dev_infor: hydra_toolkit::DeviceClientInfor,
    attester_addr: String,
) -> Result<()> {
    let merkle_leaf = dev_infor
        .merkle_leaf
        .context("passport mode requires merkle_leaf")?;

    let should_start_timer = {
        let mut state = state.lock().await;
        state.pending.push(AttesterSession {
            socket: Arc::new(Mutex::new(socket)),
            dev_infor,
            merkle_leaf,
            response: None,
            attester_addr,
        });
        println!(
            "queued passport attester; pending count: {}",
            state.pending.len()
        );

        if state.batch_timer_running {
            false
        } else {
            state.batch_timer_running = true;
            true
        }
    };

    if should_start_timer {
        schedule_passport_batch(state, verifier_key, relying_party_addrs);
    }

    Ok(())
}

fn schedule_passport_batch(
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
) {
    tokio::spawn(async move {
        tokio::time::sleep(BATCH_INTERVAL).await;
        process_passport_batch(
            Arc::clone(&state),
            Arc::clone(&verifier_key),
            relying_party_addrs,
        )
        .await;
    });
}

struct ComputedResponse {
    index: usize,
    socket: Arc<Mutex<TcpStream>>,
    attester_addr: String,
    response: hydra_toolkit::ResponseDeviceInfor,
    encrypted: Vec<u8>,
}

type AttesterSnapshot = (usize, AttesterSession);

async fn process_passport_batch(
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
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
            println!("passport batch window closed; no pending passport attesters");
            return;
        }

        let old_total = state.active.len();
        let mut pending = std::mem::take(&mut state.pending);
        state.batch_timer_running = false;
        let inserted = pending.len();
        let batch_leaves: Vec<BlsScalar> = pending.iter().map(|item| item.merkle_leaf).collect();

        if state.has_created_tree {
            let old_leaves_before_insert = state.old_leaves.clone();
            let mut new_leaves = batch_leaves.clone();
            insert_batch_devices(
                &mut state.root,
                &old_leaves_before_insert,
                &mut new_leaves,
                &hasher_vfy,
            );
            state.old_leaves.extend(batch_leaves);
            println!(
                "inserted batch into existing tree; total leaves: {}",
                state.old_leaves.len()
            );
        } else {
            state.old_leaves.extend(batch_leaves);
            state.root.clear();
            let leaves = state.old_leaves.clone();
            create_batch_devices(&mut state.root, &leaves, &hasher_vfy);
            state.has_created_tree = true;
            println!(
                "created initial tree; total leaves: {}",
                state.old_leaves.len()
            );
        }

        state.active.append(&mut pending);

        let affected_old: Vec<usize> = if old_total == 0 {
            Vec::new()
        } else {
            affected_indices(old_total, inserted)
                .into_iter()
                .map(|index| index - 1)
                .collect()
        };
        let affected_old_count = affected_old.len();
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

        println!(
            "passport batch refresh set; old_total={}, inserted={}, affected_old={}, unaffected_old_context={}, new_attesters={}",
            old_total,
            inserted,
            affected_old_count,
            unaffected_old_snapshots.len(),
            new_snapshots.len()
        );

        (
            affected_old_snapshots,
            unaffected_old_snapshots,
            new_snapshots,
            state.root.clone(),
            state.old_leaves.clone(),
            public_context,
        )
    };

    compute_store_and_send_responses(
        "affected old attester",
        &affected_old_snapshots,
        &state,
        &root,
        &leaves,
        &hasher_vfy,
        &verifier_key,
        &public_context,
    )
    .await;

    send_context_only_refreshes(&unaffected_old_snapshots, &public_context).await;

    publish_public_context_to_all(&relying_party_addrs, &public_context).await;

    compute_store_and_send_responses(
        "new attester",
        &new_snapshots,
        &state,
        &root,
        &leaves,
        &hasher_vfy,
        &verifier_key,
        &public_context,
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
) {
    if snapshots.is_empty() {
        println!("no {} responses to send", label);
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
                    if let Err(err) = persist_response(&computed.response) {
                        eprintln!("persist verifier response failed: {:#}", err);
                    }
                    if let Some(session) = state.active.get_mut(computed.index) {
                        session.response = Some(computed.response);
                    }
                    send_jobs.push((computed.socket, computed.attester_addr, computed.encrypted));
                }
                Err(err) => eprintln!("build verifier response failed: {:#}", err),
            }
        }
    }

    for (socket, attester_addr, encrypted) in send_jobs {
        let mut socket = socket.lock().await;
        if let Err(err) = tcp_send_frame(&mut socket, &encrypted)
            .await
            .context("send encrypted dev_res to attester failed")
        {
            eprintln!("send verifier response failed: {:#}", err);
        } else {
            println!(
                "sent encrypted verifier response to {}: {}",
                label, attester_addr
            );
        }
    }
}

async fn send_context_only_refreshes(
    snapshots: &[AttesterSnapshot],
    public_context: &PublicContext,
) {
    if snapshots.is_empty() {
        println!("no unaffected old attester context refreshes to send");
        return;
    }

    let message = match encode_public_context_message(public_context) {
        Ok(message) => message,
        Err(err) => {
            eprintln!("build public context message failed: {:#}", err);
            return;
        }
    };

    let mut send_jobs = Vec::new();
    for (_, item) in snapshots {
        send_jobs.push((Arc::clone(&item.socket), message.clone()));
    }

    for (socket, message) in send_jobs {
        let mut socket = socket.lock().await;
        if let Err(err) = tcp_send_frame(&mut socket, &message)
            .await
            .context("send public context to attester failed")
        {
            eprintln!("send public context to attester failed: {:#}", err);
        } else {
            println!("sent latest public context to unaffected old attester");
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
    let mut dev_res = item.response.clone().unwrap_or_else(|| {
        hydra_toolkit::ResponseDeviceInfor::new_with_mode(
            item.dev_infor.mode,
            item.dev_infor.verifying_key,
        )
    });
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

fn response_store_path(attester_addr: &str) -> PathBuf {
    let safe_name: String = attester_addr
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    role_data_dir()
        .join("verifier-responses")
        .join(format!("{}.bin", safe_name))
}

fn persist_response(response: &hydra_toolkit::ResponseDeviceInfor) -> Result<()> {
    let dir = role_data_dir().join("verifier-responses");
    fs::create_dir_all(&dir).context("create verifier response store failed")?;
    save_response_device_infor(response_store_path(&response.attester_addr), response)
}

async fn publish_public_context_to_all(addrs: &[String], public_context: &PublicContext) {
    for addr in addrs {
        if let Err(err) = publish_public_context(addr, public_context).await {
            eprintln!("publish public context to {} failed: {:#}", addr, err);
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
        .context("publish root/verifier public key to relying-party failed")?;
    println!("published public root and verifier public key to {}", addr);
    Ok(())
}
