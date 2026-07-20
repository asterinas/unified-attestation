pub mod poseidon;
pub mod shurbstree;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, bail};
use ark_bls12_381::Bls12_381;
pub use ark_bls12_381::Fr as BlsScalar;
use ark_groth16::{Proof, VerifyingKey as ArkVerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use arkworks_native_gadgets::poseidon::FieldHasher;
pub use arkworks_native_gadgets::poseidon::Poseidon;
use ecdsa::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use k256::ecdsa::{
    Signature,
    signature::{Signer, Verifier},
};
use k256::{PublicKey, Secp256k1, sha2::Sha256};
use num_bigint::BigUint;
use rand_core::{OsRng, RngCore};
use shurbstree::{exponents_of_two, find_interval_index, find_shrubs_path, insert_shrubs_tree};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const DATA_DIR_NAME: &str = "workspace-data";
pub const ATTESTER_KEY_FILE: &str = "attester_key.bin";
pub const DEVICE_INFOR_FILE: &str = "dev_infor.bin";
pub const DEVICE_CONFIG_FILE: &str = "dev_config.bin";
pub const VERIFIER_KEY_FILE: &str = "verifier_key.bin";
pub const VERIFIER_RESPONSE_FILE: &str = "dev_res.bin";
pub const PUBLIC_CONTEXT_FILE: &str = "public_context.bin";
pub const EVIDENCE_FILE: &str = "evidence.bin";

pub const DEFAULT_VERIFIER_ADDR: &str = "127.0.0.1:7001";
pub const DEFAULT_RELYING_PARTY_ADDR: &str = "127.0.0.1:7002";
pub const MAX_TCP_FRAME_LEN: u64 = 512 * 1024 * 1024;
pub const MSG_DEVICE_INFOR: &[u8; 4] = b"DINF";
pub const MSG_PUBLIC_CONTEXT: &[u8; 4] = b"PUBC";
pub const MSG_EVIDENCE: &[u8; 4] = b"EVID";
pub const EVIDENCE_REPLY_ATTESTER_PERIOD_SECS: u64 = 2 * 60;

pub fn project_root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Create all parent directories for a given path if they don't already exist.
fn ensure_parent_dir(path: impl AsRef<Path>) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directory failed")?;
    }
    Ok(())
}

/// Read the device measurement file. Panics if `example.txt` is absent — measurement
/// is mandatory for hydra sessions; the attester cannot participate without it.
pub fn read_measurement_file() -> String {
    fs::read_to_string(project_root_dir().join("example.txt"))
        .expect("read measurement file failed")
}

/// Default Poseidon hasher for BLS12-381 (width=3, exp=5).
/// Width-3 2-to-1 compression matches both the shrubs accumulator and the
/// authorization commitment `H(H(H(pk,ar),time),period)`. Changing parameters
/// would break hash compatibility between prover and verifier.
pub fn default_hasher() -> Poseidon<BlsScalar> {
    crate::poseidon::poseidon_setup(arkworks_utils::Curve::Bls381, 5, 3)
}

/// Groth16 evidence bundle sent from attester to relying-party.
///
/// Fields:
/// - `proof`, `vk` — Groth16 proof and verifying key (BLS12-381)
/// - `sig` — verifier authorization signature over (pk, authorized_infor, timestamp, period)
/// - `pk` — attester secp256k1 public key
/// - `timestamp`, `period` — verifier response time window
/// - `authorized_infor` — `H(H(H(pk, ar), time), period)`, binding device measurement to time
/// - `timestamp_attester`, `period_attester` — attester-side freshness window
/// - `proof_timestamp_period_signature` — attester sig over (proof, timestamp_attester, period_attester)
///
/// Verification on RP: verify attester sig → verify verifier sig → Groth16::verify.
#[derive(Debug)]
pub struct EvidenceReply {
    /// Groth16 proof over BLS12-381 (proves device in whitelist without revealing index)
    pub proof: Proof<Bls12_381>,
    /// Groth16 verifying key (generated per-proof via circuit_specific_setup)
    pub vk: ArkVerifyingKey<Bls12_381>,
    /// Verifier authorization signature: sign(pk || authorized_infor || timestamp || period)
    pub sig: Signature,
    /// Attester secp256k1 public key
    pub pk: VerifyingKey<Secp256k1>,
    /// Verifier response timestamp (start of validity window)
    pub timestamp: Duration,
    /// Verifier response period (validity window length)
    pub period: Duration,
    /// H(H(H(pk, ar), time), period) — binds device measurement to time
    pub authorized_infor: BlsScalar,
    /// Attester-side timestamp when EvidenceReply was generated
    pub timestamp_attester: Duration,
    /// Attester-side freshness window (default 120s)
    pub period_attester: Duration,
    /// Attester signature over (proof, timestamp_attester, period_attester) — proves freshness
    pub proof_timestamp_period_signature: Signature,
}

impl EvidenceReply {
    pub fn new(
        proof: Proof<Bls12_381>,
        vk: ArkVerifyingKey<Bls12_381>,
        verifier_signature: Signature,
        attester_pk: VerifyingKey<Secp256k1>,
        timestamp: Duration,
        period: Duration,
        authorized_infor: BlsScalar,
        attester_signing_key: &SigningKey<Secp256k1>,
    ) -> EvidenceReply {
        let timestamp_attester = current_unix_duration().expect("system time is before UNIX_EPOCH");
        let period_attester = Duration::from_secs(EVIDENCE_REPLY_ATTESTER_PERIOD_SECS);
        let proof_timestamp_period_signature = sign_proof_timestamp_period(
            attester_signing_key,
            &proof,
            timestamp_attester,
            period_attester,
        )
        .expect("serialize EvidenceReply proof freshness fields failed");

        EvidenceReply {
            proof,
            vk,
            sig: verifier_signature,
            pk: attester_pk,
            timestamp,
            period,
            authorized_infor,
            timestamp_attester,
            period_attester,
            proof_timestamp_period_signature,
        }
    }
    /// Build public inputs in the exact order expected by the Groth16 circuit:
    /// `[pk, root[0..N], authorized_infor, timestamp, period]`
    pub fn gen_public_inputs(&self, root: &[BlsScalar]) -> Vec<BlsScalar> {
        let mut public_inputs = vec![];
        // [0] attester public key (Fr)
        public_inputs.push(BlsScalar::from(BigUint::from_bytes_be(
            self.pk.to_encoded_point(true).as_bytes(),
        )));
        // [1..1+N] shrubs accumulator root list (one Fr per root)
        public_inputs.extend_from_slice(root);
        // [1+N] authorized_infor = H(H(H(pk, ar), time), period)
        public_inputs.push(self.authorized_infor);
        // [2+N] verifier response timestamp (seconds)
        public_inputs.push(BlsScalar::from(self.timestamp.as_secs()));
        // [3+N] verifier response period (seconds)
        public_inputs.push(BlsScalar::from(self.period.as_secs()));

        public_inputs
    }

    pub fn to_signing_bytes_all_fields(&self) -> Result<Vec<u8>, SerializationError> {
        let mut out = Vec::new();

        let proof_bytes = serialize_ark(&self.proof)?;
        append_field(&mut out, &b"proof"[..], &proof_bytes);

        let vk_bytes = serialize_ark(&self.vk)?;
        append_field(&mut out, &b"vk"[..], &vk_bytes);

        let sig_der = self.sig.to_der();
        append_field(&mut out, &b"sig"[..], sig_der.as_bytes());

        let pk_encoded = self.pk.to_encoded_point(true);
        append_field(&mut out, &b"pk"[..], pk_encoded.as_bytes());

        let timestamp_bytes = serialize_duration(&self.timestamp);
        append_field(&mut out, &b"timestamp"[..], &timestamp_bytes);

        let period_bytes = serialize_duration(&self.period);
        append_field(&mut out, &b"period"[..], &period_bytes);

        let authorized_infor_bytes = serialize_ark(&self.authorized_infor)?;
        append_field(&mut out, &b"authorized_infor"[..], &authorized_infor_bytes);

        let timestamp_attester_bytes = serialize_duration(&self.timestamp_attester);
        append_field(
            &mut out,
            &b"timestamp_attester"[..],
            &timestamp_attester_bytes,
        );

        let period_attester_bytes = serialize_duration(&self.period_attester);
        append_field(&mut out, &b"period_attester"[..], &period_attester_bytes);

        let proof_sig_der = self.proof_timestamp_period_signature.to_der();
        append_field(
            &mut out,
            &b"proof_timestamp_period_signature"[..],
            proof_sig_der.as_bytes(),
        );

        Ok(out)
    }
}

fn proof_timestamp_period_signing_bytes(
    proof: &Proof<Bls12_381>,
    timestamp_attester: Duration,
    period_attester: Duration,
) -> Result<Vec<u8>, SerializationError> {
    let mut out = Vec::new();

    let proof_bytes = serialize_ark(proof)?;
    append_field(&mut out, &b"proof"[..], &proof_bytes);

    let timestamp_attester_bytes = serialize_duration(&timestamp_attester);
    append_field(
        &mut out,
        &b"timestamp_attester"[..],
        &timestamp_attester_bytes,
    );

    let period_attester_bytes = serialize_duration(&period_attester);
    append_field(&mut out, &b"period_attester"[..], &period_attester_bytes);

    Ok(out)
}

fn sign_proof_timestamp_period(
    signing_key: &SigningKey<Secp256k1>,
    proof: &Proof<Bls12_381>,
    timestamp_attester: Duration,
    period_attester: Duration,
) -> Result<Signature, SerializationError> {
    let msg = proof_timestamp_period_signing_bytes(proof, timestamp_attester, period_attester)?;
    Ok(signing_key.sign(&msg[..]))
}

fn append_field(out: &mut Vec<u8>, field_name: &[u8], field_data: &[u8]) {
    out.extend_from_slice(&(field_name.len() as u64).to_be_bytes());
    out.extend_from_slice(field_name);

    out.extend_from_slice(&(field_data.len() as u64).to_be_bytes());
    out.extend_from_slice(field_data);
}

fn serialize_ark<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::new();
    value.serialize_uncompressed(&mut bytes)?;
    Ok(bytes)
}

fn serialize_duration(duration: &Duration) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&duration.as_secs().to_be_bytes());

    bytes.extend_from_slice(&duration.subsec_nanos().to_be_bytes());

    bytes
}

/// Current wall-clock time as a `Duration` since UNIX_EPOCH.
/// Errors only if the system clock is set before 1970.
pub fn current_unix_duration() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")
}

/// Reject a DeviceClientInfor whose timestamp+period has already expired.
/// Called by the verifier before queuing an attester into the batch pipeline.
pub fn verify_device_client_infor_freshness(value: &DeviceClientInfor) -> Result<()> {
    let expires_at = value
        .timestamp
        .checked_add(value.period)
        .context("DeviceClientInfor timestamp + period overflow")?;
    let now = current_unix_duration()?;
    if expires_at > now {
        Ok(())
    } else {
        bail!(
            "DeviceClientInfor expired: timestamp={} period={} now={}",
            value.timestamp.as_secs(),
            value.period.as_secs(),
            now.as_secs()
        )
    }
}

/// Device identity submitted by attester to the verifier TCP daemon.
#[derive(Debug, Clone)]
pub struct DeviceClientInfor {
    /// Attester secp256k1 public key (used for ECDH encryption of verifier response)
    pub verifying_key: VerifyingKey<Secp256k1>,
    /// Local measurement string (read from example.txt at startup)
    pub measured_value: String,
    /// H(H(ar, sk), pk) — leaf inserted into the shrubs accumulator
    pub merkle_leaf: BlsScalar,
    /// Submission timestamp (for freshness check)
    pub timestamp: Duration,
    /// Validity window; expired submissions are rejected
    pub period: Duration,
}
impl DeviceClientInfor {
    pub fn new(vk: VerifyingKey<Secp256k1>, leaf: BlsScalar) -> DeviceClientInfor {
        let measure = read_measurement_file();
        let timestamp = current_unix_duration().expect("system time is before UNIX_EPOCH");
        let period = Duration::from_secs(8640000);
        DeviceClientInfor {
            verifying_key: vk,
            merkle_leaf: leaf,
            measured_value: measure,
            timestamp,
            period,
        }
    }
}

/// Wire-format DeviceClientInfor: fields that are native types in memory
/// (VerifyingKey, BlsScalar) are serialized to `Vec<u8>` for TCP transport.
pub struct DeviceClientInforWire {
    pub verifying_key: Vec<u8>,
    pub measured_value: String,
    pub merkle_leaf: Vec<u8>,
    pub timestamp: Duration,
    pub period: Duration,
}

/// Signed wrapper for `DeviceClientInforWire`. The attester signs the serialized
/// device info to prove it generated this submission.
pub struct SignedDeviceClientInforWire {
    pub device: DeviceClientInforWire,
    pub signature: Vec<u8>,
}

/// ECIES-like encrypted message: ephemeral pubkey + AES-256-GCM nonce + ciphertext.
/// Key derivation: ECDH(ephemeral_sk, recipient_pk) → HKDF → AES key.
pub struct EncryptedMessage {
    pub ephemeral_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn find_device_shrubs_path_tag(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    leaf: &BlsScalar,
    hasher: &Poseidon<BlsScalar>,
) -> (Option<Vec<BlsScalar>>, Option<Vec<bool>>) {
    match find_interval_index(leaves, leaf) {
        Some((vect, index)) => {
            let inx = 0;

            match find_shrubs_path(root, &vect, inx, index, hasher) {
                Some((path, tag)) => (Some(path), Some(tag)),
                None => (None, None),
            }
        }

        None => (None, None),
    }
}

/// secp256k1 key pair used by attester and verifier for signing/verification.
pub struct KeyInfor {
    pub signing_key: SigningKey<Secp256k1>,
    pub verifying_key: VerifyingKey<Secp256k1>,
}

impl KeyInfor {
    pub fn new() -> Self {
        let signing_key: SigningKey<Secp256k1> = SigningKey::<Secp256k1>::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key,
        }
    }
}

impl Default for KeyInfor {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the shrubs Merkle leaf: `leaf = H(H(ar, sk), pk)`.
/// `ar` is read from the measurement file; `sk`/`pk` from the device key.
pub fn generate_device_merkle_leaf(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let measure = read_measurement_file();
    let sk = BlsScalar::from(BigUint::from_bytes_be(
        &device_key.signing_key.to_bytes()[..],
    ));
    let pk = BlsScalar::from(BigUint::from_bytes_be(
        device_key.verifying_key.to_encoded_point(true).as_bytes(),
    ));
    let ar = BlsScalar::from(BigUint::from_bytes_be(measure.as_bytes()));

    let c = hasher.hash(&[ar, sk][..]).unwrap();
    hasher.hash(&[c, pk][..]).unwrap()
}
/// Verifier response carrying authorization signature, shrubs path/tag, and time window.
/// Sent encrypted (AES-GCM + ECDH) to attester; fields are fed into DeviceConfigInfor.
#[derive(Clone)]
pub struct ResponseDeviceInfor {
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub attester_addr: String,
    pub timestamp: Duration,
    pub period: Duration,
    pub sig: Option<Signature>,
    pub shrubs_path: Option<Vec<BlsScalar>>,
    pub shrubs_tag: Option<Vec<bool>>,
}

impl ResponseDeviceInfor {
    pub fn new(pk: VerifyingKey<Secp256k1>) -> ResponseDeviceInfor {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time failed");
        let period = Duration::from_secs(8640000);
        ResponseDeviceInfor {
            attester_addr: String::new(),
            timestamp,
            period,
            verifying_key: pk,
            sig: None,
            shrubs_path: None,
            shrubs_tag: None,
        }
    }
    pub fn set_signature(&mut self, sig: &Signature) {
        self.sig = Some(*sig);
    }
}

pub struct ResponseDeviceInforWire {
    pub verifying_key: Vec<u8>,
    pub attester_addr: String,
    pub timestamp: Duration,
    pub period: Duration,
    pub sig: Option<Vec<u8>>,
    pub shrubs_path: Option<Vec<Vec<u8>>>,
    pub shrubs_tag: Option<Vec<bool>>,
}

pub fn generate_device_authoried_infor(
    devices_infor: &DeviceClientInfor,
    devices_time: &ResponseDeviceInfor,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let pk = BlsScalar::from(BigUint::from_bytes_be(
        devices_infor
            .verifying_key
            .to_encoded_point(true)
            .as_bytes(),
    ));
    let ar = BlsScalar::from(BigUint::from_bytes_be(
        devices_infor.measured_value.as_bytes(),
    ));
    let time = BlsScalar::from(devices_time.timestamp.as_secs());
    let peri = BlsScalar::from(devices_time.period.as_secs());

    let temp_1 = hasher.hash(&[pk, ar][..]).unwrap();
    let temp_2 = hasher.hash(&[temp_1, time][..]).unwrap();
    hasher.hash(&[temp_2, peri][..]).unwrap()
}

pub fn generate_verifier_authoried_infor(
    ar: BlsScalar,
    pk: BlsScalar,
    time: BlsScalar,
    peri: BlsScalar,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let temp_1 = hasher.hash(&[pk, ar][..]).unwrap();
    let temp_2 = hasher.hash(&[temp_1, time][..]).unwrap();
    hasher.hash(&[temp_2, peri][..]).unwrap()
}

pub fn insert_batch_devices(
    root: &mut Vec<BlsScalar>,
    old_leaves: &[BlsScalar],
    new_leaves: &mut Vec<BlsScalar>,
    hasher: &Poseidon<BlsScalar>,
) {
    let k: isize = -1;
    let ll: usize = 0;

    let exps = exponents_of_two(old_leaves.len());

    if exps[0] == 0 {
        let mut n_leaf = Vec::with_capacity(new_leaves.len() + 1);
        n_leaf.push(root[0]);
        n_leaf.append(new_leaves);

        insert_shrubs_tree(root, &n_leaf, k, &exps, ll + 1, hasher);
    } else {
        insert_shrubs_tree(root, new_leaves, k, &exps, ll, hasher);
    }
}
/// Build a DeviceClientInfor from a key pair: computes the merkle leaf
/// `H(H(ar, sk), pk)`, reads the measurement file, stamps the current time.
/// This is the first step in the attester's hydra submission flow.
pub fn generate_device_client_infor(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
) -> DeviceClientInfor {
    let device_leaf = generate_device_merkle_leaf(device_key, hasher);
    DeviceClientInfor::new(device_key.verifying_key, device_leaf)
}

/// Global public state broadcast by verifier on every batch completion.
#[derive(Debug, Clone)]
pub struct PublicContext {
    /// Current shrubs accumulator root list (one Fr per root)
    pub root: Vec<BlsScalar>,
    /// Verifier secp256k1 public key — RP uses this to verify authorization signatures
    pub verifier_pk: VerifyingKey<Secp256k1>,
}

// ---- Wire codec helpers -------------------------------------------------------
// The following encode_*/decode_* pairs convert between native Rust types and
// length-prefixed binary blobs for TCP transport and on-disk persistence.
// All scalar types (BlsScalar, Signature, VerifyingKey) are serialized via
// ark-serialize (uncompressed) or k256 DER encoding. Durations are 12-byte
// (u64 seconds + u32 nanoseconds). Vectors are u64-length-prefixed.
// Every encode_* has a matching decode_* that inverts it exactly.

fn append_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_exact<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    std::io::Read::read_exact(cursor, &mut buf).context("read fixed bytes failed")?;
    Ok(buf)
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    Ok(u64::from_be_bytes(read_exact::<8>(cursor)?))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    Ok(u32::from_be_bytes(read_exact::<4>(cursor)?))
}

fn read_len_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = read_u64(cursor)? as usize;
    let mut bytes = vec![0u8; len];
    std::io::Read::read_exact(cursor, &mut bytes).context("read length-prefixed bytes failed")?;
    Ok(bytes)
}

fn append_string(out: &mut Vec<u8>, value: &str) {
    append_len_bytes(out, value.as_bytes());
}

fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    String::from_utf8(read_len_bytes(cursor)?).context("parse UTF-8 string failed")
}

fn append_duration(out: &mut Vec<u8>, value: Duration) {
    out.extend_from_slice(&value.as_secs().to_be_bytes());
    out.extend_from_slice(&value.subsec_nanos().to_be_bytes());
}

fn read_duration(cursor: &mut Cursor<&[u8]>) -> Result<Duration> {
    let secs = read_u64(cursor)?;
    let nanos = read_u32(cursor)?;
    Ok(Duration::new(secs, nanos))
}

fn encode_scalar(value: &BlsScalar) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("serialize BlsScalar failed")?;
    Ok(bytes)
}

fn decode_scalar(bytes: &[u8]) -> Result<BlsScalar> {
    let mut cursor = Cursor::new(bytes);
    BlsScalar::deserialize_uncompressed(&mut cursor).context("deserialize BlsScalar failed")
}

fn append_scalar(out: &mut Vec<u8>, value: &BlsScalar) -> Result<()> {
    append_len_bytes(out, &encode_scalar(value)?);
    Ok(())
}

fn read_scalar(cursor: &mut Cursor<&[u8]>) -> Result<BlsScalar> {
    decode_scalar(&read_len_bytes(cursor)?)
}

fn append_scalar_vec(out: &mut Vec<u8>, values: &[BlsScalar]) -> Result<()> {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        append_scalar(out, value)?;
    }
    Ok(())
}

fn read_scalar_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<BlsScalar>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(read_scalar(cursor)?);
    }
    Ok(values)
}

fn append_bool_vec(out: &mut Vec<u8>, values: &[bool]) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        out.push(u8::from(*value));
    }
}

fn read_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<bool>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let b = read_exact::<1>(cursor)?[0];
        match b {
            0 => values.push(false),
            1 => values.push(true),
            _ => bail!("invalid bool field: {}", b),
        }
    }
    Ok(values)
}

fn append_option_bool_vec(out: &mut Vec<u8>, values: &Option<Vec<bool>>) {
    match values {
        Some(values) => {
            out.push(1);
            append_bool_vec(out, values);
        }
        None => out.push(0),
    }
}

fn read_option_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Option<Vec<bool>>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_bool_vec(cursor)?)),
        other => bail!("Option<Vec<bool>> 闁哄秴娲╅鍥閻愬銆? {}", other),
    }
}

fn encode_signature(value: &Signature) -> Vec<u8> {
    value.to_der().as_bytes().to_vec()
}

fn decode_signature(bytes: &[u8]) -> Result<Signature> {
    Signature::from_der(bytes).context("deserialize secp256k1 signature failed")
}

fn append_signature(out: &mut Vec<u8>, value: &Signature) {
    append_len_bytes(out, &encode_signature(value));
}

fn read_signature(cursor: &mut Cursor<&[u8]>) -> Result<Signature> {
    decode_signature(&read_len_bytes(cursor)?)
}

fn append_verifying_key(out: &mut Vec<u8>, value: &VerifyingKey<Secp256k1>) {
    append_len_bytes(out, value.to_encoded_point(true).as_bytes());
}

fn read_verifying_key(cursor: &mut Cursor<&[u8]>) -> Result<VerifyingKey<Secp256k1>> {
    VerifyingKey::<Secp256k1>::from_sec1_bytes(&read_len_bytes(cursor)?)
        .context("deserialize secp256k1 public key failed")
}

pub fn device_client_infor_to_wire(value: &DeviceClientInfor) -> Result<DeviceClientInforWire> {
    Ok(DeviceClientInforWire {
        verifying_key: value
            .verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        measured_value: value.measured_value.clone(),
        merkle_leaf: encode_scalar(&value.merkle_leaf)?,
        timestamp: value.timestamp,
        period: value.period,
    })
}

pub fn device_client_infor_from_wire(wire: &DeviceClientInforWire) -> Result<DeviceClientInfor> {
    Ok(DeviceClientInfor {
        verifying_key: VerifyingKey::<Secp256k1>::from_sec1_bytes(&wire.verifying_key)
            .context("decode DeviceClientInforWire verifying_key failed")?,
        measured_value: wire.measured_value.clone(),
        merkle_leaf: decode_scalar(&wire.merkle_leaf)?,
        timestamp: wire.timestamp,
        period: wire.period,
    })
}

pub fn sign_device_client_infor(value: &DeviceClientInfor, key: &KeyInfor) -> Result<Signature> {
    let message = encode_device_client_infor(value)?;
    Ok(key.signing_key.sign(message.as_slice()))
}

pub fn sign_device_client_infor_to_wire(
    value: &DeviceClientInfor,
    key: &KeyInfor,
) -> Result<SignedDeviceClientInforWire> {
    let signature = sign_device_client_infor(value, key)?;
    Ok(SignedDeviceClientInforWire {
        device: device_client_infor_to_wire(value)?,
        signature: encode_signature(&signature),
    })
}

pub fn verify_signed_device_client_infor_wire(
    signed: &SignedDeviceClientInforWire,
) -> Result<DeviceClientInfor> {
    let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&signed.device.verifying_key)
        .context("decode signed DeviceClientInfor verifying_key failed")?;
    let signature = decode_signature(&signed.signature)?;
    let message = encode_device_client_infor_wire(&signed.device)?;
    verifying_key
        .verify(message.as_slice(), &signature)
        .context("attester DeviceClientInfor signature verification failed")?;
    device_client_infor_from_wire(&signed.device)
}

fn derive_aes_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"hydra verifier response encryption", &mut key)
        .map_err(|_| anyhow::anyhow!("derive AES-GCM key failed"))?;
    Ok(key)
}

pub fn encrypt_for_device_pubkey(
    plaintext: &[u8],
    device_pubkey: &VerifyingKey<Secp256k1>,
) -> Result<EncryptedMessage> {
    // ECDH key agreement: generate ephemeral keypair, compute shared secret with
    // the attester's static public key, then derive an AES-256 key via HKDF.
    let recipient_public_key =
        PublicKey::from_sec1_bytes(device_pubkey.to_encoded_point(true).as_bytes())
            .context("decode device public key for encryption failed")?;
    let ephemeral_secret = k256::ecdh::EphemeralSecret::random(&mut OsRng);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
    // HKDF the raw ECDH bytes into a fixed-length AES-256 key
    let key = derive_aes_key(shared_secret.raw_secret_bytes().as_slice())?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("create AES-GCM cipher failed"))?;

    // Fresh random nonce per encryption — reuse would break AES-GCM security
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("encrypt verifier response failed"))?;

    Ok(EncryptedMessage {
        ephemeral_public_key: ephemeral_public_key.to_sec1_bytes().to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Reverse of `encrypt_for_device_pubkey`: reconstruct the ECDH shared secret from
/// the attester's private key and the verifier's ephemeral public key, derive the
/// same AES key, and decrypt.
pub fn decrypt_for_device_key(
    encrypted: &EncryptedMessage,
    device_key: &KeyInfor,
) -> Result<Vec<u8>> {
    let ephemeral_public_key = PublicKey::from_sec1_bytes(&encrypted.ephemeral_public_key)
        .context("decode verifier ephemeral public key failed")?;
    let secret_key = k256::SecretKey::from_slice(&device_key.signing_key.to_bytes())
        .context("load device secret key for decryption failed")?;
    let shared_secret = k256::ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        ephemeral_public_key.as_affine(),
    );
    let key = derive_aes_key(shared_secret.raw_secret_bytes().as_slice())?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("create AES-GCM cipher failed"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.ciphertext.as_ref(),
        )
        .map_err(|_| anyhow::anyhow!("decrypt verifier response failed"))
}

pub fn response_device_infor_to_wire(
    value: &ResponseDeviceInfor,
) -> Result<ResponseDeviceInforWire> {
    let shrubs_path = match &value.shrubs_path {
        Some(path) => Some(path.iter().map(encode_scalar).collect::<Result<Vec<_>>>()?),
        None => None,
    };

    Ok(ResponseDeviceInforWire {
        verifying_key: value
            .verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        attester_addr: value.attester_addr.clone(),
        timestamp: value.timestamp,
        period: value.period,
        sig: value.sig.as_ref().map(encode_signature),
        shrubs_path,
        shrubs_tag: value.shrubs_tag.clone(),
    })
}

pub fn response_device_infor_from_wire(
    wire: &ResponseDeviceInforWire,
) -> Result<ResponseDeviceInfor> {
    let shrubs_path = match &wire.shrubs_path {
        Some(path) => Some(
            path.iter()
                .map(|item| decode_scalar(item))
                .collect::<Result<Vec<_>>>()?,
        ),
        None => None,
    };

    Ok(ResponseDeviceInfor {
        verifying_key: VerifyingKey::<Secp256k1>::from_sec1_bytes(&wire.verifying_key)
            .context("decode ResponseDeviceInforWire verifying_key failed")?,
        attester_addr: wire.attester_addr.clone(),
        timestamp: wire.timestamp,
        period: wire.period,
        sig: wire.sig.as_deref().map(decode_signature).transpose()?,
        shrubs_path,
        shrubs_tag: wire.shrubs_tag.clone(),
    })
}

fn encode_proof(value: &Proof<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("serialize Groth16 proof failed")?;
    Ok(bytes)
}

fn decode_proof(bytes: &[u8]) -> Result<Proof<Bls12_381>> {
    let mut cursor = Cursor::new(bytes);
    Proof::<Bls12_381>::deserialize_uncompressed(&mut cursor)
        .context("deserialize Groth16 proof failed")
}

fn append_proof(out: &mut Vec<u8>, value: &Proof<Bls12_381>) -> Result<()> {
    append_len_bytes(out, &encode_proof(value)?);
    Ok(())
}

fn read_proof(cursor: &mut Cursor<&[u8]>) -> Result<Proof<Bls12_381>> {
    decode_proof(&read_len_bytes(cursor)?)
}

fn encode_ark_vk(value: &ArkVerifyingKey<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("serialize Groth16 verifying key failed")?;
    Ok(bytes)
}

fn decode_ark_vk(bytes: &[u8]) -> Result<ArkVerifyingKey<Bls12_381>> {
    let mut cursor = Cursor::new(bytes);
    ArkVerifyingKey::<Bls12_381>::deserialize_uncompressed(&mut cursor)
        .context("deserialize Groth16 verifying key failed")
}

fn append_ark_vk(out: &mut Vec<u8>, value: &ArkVerifyingKey<Bls12_381>) -> Result<()> {
    append_len_bytes(out, &encode_ark_vk(value)?);
    Ok(())
}

fn read_ark_vk(cursor: &mut Cursor<&[u8]>) -> Result<ArkVerifyingKey<Bls12_381>> {
    decode_ark_vk(&read_len_bytes(cursor)?)
}

pub fn encode_device_client_infor(value: &DeviceClientInfor) -> Result<Vec<u8>> {
    encode_device_client_infor_wire(&device_client_infor_to_wire(value)?)
}

pub fn encode_device_client_infor_wire(value: &DeviceClientInforWire) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &value.verifying_key);
    append_string(&mut out, &value.measured_value);
    append_len_bytes(&mut out, &value.merkle_leaf);
    append_duration(&mut out, value.timestamp);
    append_duration(&mut out, value.period);
    Ok(out)
}

pub fn decode_device_client_infor_wire(bytes: &[u8]) -> Result<DeviceClientInforWire> {
    let mut cursor = Cursor::new(bytes);
    Ok(DeviceClientInforWire {
        verifying_key: read_len_bytes(&mut cursor)?,
        measured_value: read_string(&mut cursor)?,
        merkle_leaf: read_len_bytes(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
    })
}

pub fn encode_signed_device_client_infor_wire(
    value: &SignedDeviceClientInforWire,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &encode_device_client_infor_wire(&value.device)?);
    append_len_bytes(&mut out, &value.signature);
    Ok(out)
}

pub fn decode_signed_device_client_infor_wire(bytes: &[u8]) -> Result<SignedDeviceClientInforWire> {
    let mut cursor = Cursor::new(bytes);
    let device = decode_device_client_infor_wire(&read_len_bytes(&mut cursor)?)?;
    let signature = read_len_bytes(&mut cursor)?;
    Ok(SignedDeviceClientInforWire { device, signature })
}

pub fn encode_encrypted_message(value: &EncryptedMessage) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &value.ephemeral_public_key);
    append_len_bytes(&mut out, &value.nonce);
    append_len_bytes(&mut out, &value.ciphertext);
    Ok(out)
}

pub fn decode_encrypted_message(bytes: &[u8]) -> Result<EncryptedMessage> {
    let mut cursor = Cursor::new(bytes);
    Ok(EncryptedMessage {
        ephemeral_public_key: read_len_bytes(&mut cursor)?,
        nonce: read_len_bytes(&mut cursor)?,
        ciphertext: read_len_bytes(&mut cursor)?,
    })
}

pub fn encode_response_device_infor(value: &ResponseDeviceInfor) -> Result<Vec<u8>> {
    encode_response_device_infor_wire(&response_device_infor_to_wire(value)?)
}

pub fn encode_response_device_infor_wire(value: &ResponseDeviceInforWire) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &value.verifying_key);
    append_string(&mut out, &value.attester_addr);
    append_duration(&mut out, value.timestamp);
    append_duration(&mut out, value.period);
    match &value.sig {
        Some(sig) => {
            out.push(1);
            append_len_bytes(&mut out, sig);
        }
        None => out.push(0),
    }
    match &value.shrubs_path {
        Some(path) => {
            out.push(1);
            out.extend_from_slice(&(path.len() as u64).to_be_bytes());
            for item in path {
                append_len_bytes(&mut out, item);
            }
        }
        None => out.push(0),
    }
    append_option_bool_vec(&mut out, &value.shrubs_tag);
    Ok(out)
}

pub fn decode_response_device_infor(bytes: &[u8]) -> Result<ResponseDeviceInfor> {
    let wire = decode_response_device_infor_wire(bytes)?;
    response_device_infor_from_wire(&wire)
}

pub fn decode_response_device_infor_wire(bytes: &[u8]) -> Result<ResponseDeviceInforWire> {
    let mut cursor = Cursor::new(bytes);
    let verifying_key = read_len_bytes(&mut cursor)?;
    let attester_addr = read_string(&mut cursor)?;
    let timestamp = read_duration(&mut cursor)?;
    let period = read_duration(&mut cursor)?;
    let sig = match read_exact::<1>(&mut cursor)?[0] {
        0 => None,
        1 => Some(read_len_bytes(&mut cursor)?),
        other => bail!("Option<Signature bytes> tag invalid: {}", other),
    };
    let shrubs_path = match read_exact::<1>(&mut cursor)?[0] {
        0 => None,
        1 => {
            let len = read_u64(&mut cursor)? as usize;
            let mut path = Vec::with_capacity(len);
            for _ in 0..len {
                path.push(read_len_bytes(&mut cursor)?);
            }
            Some(path)
        }
        other => bail!("Option<Vec<Vec<u8>>> tag invalid: {}", other),
    };
    let shrubs_tag = read_option_bool_vec(&mut cursor)?;

    Ok(ResponseDeviceInforWire {
        verifying_key,
        attester_addr,
        timestamp,
        period,
        sig,
        shrubs_path,
        shrubs_tag,
    })
}

pub fn encode_public_context(value: &PublicContext) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_scalar_vec(&mut out, &value.root)?;
    append_verifying_key(&mut out, &value.verifier_pk);
    Ok(out)
}

pub fn decode_public_context(bytes: &[u8]) -> Result<PublicContext> {
    let mut cursor = Cursor::new(bytes);
    Ok(PublicContext {
        root: read_scalar_vec(&mut cursor)?,
        verifier_pk: read_verifying_key(&mut cursor)?,
    })
}

pub fn encode_evidence_bundle(
    evidence_reply: &EvidenceReply,
    device_signature: &Signature,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_proof(&mut out, &evidence_reply.proof)?;
    append_ark_vk(&mut out, &evidence_reply.vk)?;
    append_signature(&mut out, &evidence_reply.sig);
    append_verifying_key(&mut out, &evidence_reply.pk);
    append_duration(&mut out, evidence_reply.timestamp);
    append_duration(&mut out, evidence_reply.period);
    append_scalar(&mut out, &evidence_reply.authorized_infor)?;
    append_duration(&mut out, evidence_reply.timestamp_attester);
    append_duration(&mut out, evidence_reply.period_attester);
    append_signature(&mut out, &evidence_reply.proof_timestamp_period_signature);
    append_signature(&mut out, device_signature);
    Ok(out)
}

pub fn decode_evidence_bundle(bytes: &[u8]) -> Result<(EvidenceReply, Signature)> {
    let mut cursor = Cursor::new(bytes);
    let evidence_reply = EvidenceReply {
        proof: read_proof(&mut cursor)?,
        vk: read_ark_vk(&mut cursor)?,
        sig: read_signature(&mut cursor)?,
        pk: read_verifying_key(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        authorized_infor: read_scalar(&mut cursor)?,
        timestamp_attester: read_duration(&mut cursor)?,
        period_attester: read_duration(&mut cursor)?,
        proof_timestamp_period_signature: read_signature(&mut cursor)?,
    };
    let device_signature = read_signature(&mut cursor)?;
    Ok((evidence_reply, device_signature))
}

pub fn encode_verifier_response(
    dev_res: &ResponseDeviceInfor,
    public_context: &PublicContext,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &encode_response_device_infor(dev_res)?);
    append_len_bytes(&mut out, &encode_public_context(public_context)?);
    Ok(out)
}

pub fn decode_verifier_response(bytes: &[u8]) -> Result<(ResponseDeviceInfor, PublicContext)> {
    let mut cursor = Cursor::new(bytes);
    let dev_res_bytes = read_len_bytes(&mut cursor)?;
    let public_context_bytes = read_len_bytes(&mut cursor)?;
    Ok((
        decode_response_device_infor(&dev_res_bytes)?,
        decode_public_context(&public_context_bytes)?,
    ))
}

/// Serialize ResponseDeviceInfor + PublicContext, then encrypt with attester's pubkey
/// via ECDH + HKDF → AES-256-GCM. Only the attester holding the corresponding private key
/// can decrypt.
pub fn encode_encrypted_verifier_response(
    dev_res: &ResponseDeviceInfor,
    public_context: &PublicContext,
    device_pubkey: &VerifyingKey<Secp256k1>,
) -> Result<Vec<u8>> {
    let plaintext = encode_verifier_response(dev_res, public_context)?;
    let encrypted = encrypt_for_device_pubkey(&plaintext, device_pubkey)?;
    encode_encrypted_message(&encrypted)
}

/// Decrypt and decode the verifier's encrypted response. Returns the pair
/// (ResponseDeviceInfor, PublicContext) that the attester uses to build DeviceConfigInfor.
pub fn decode_encrypted_verifier_response(
    bytes: &[u8],
    device_key: &KeyInfor,
) -> Result<(ResponseDeviceInfor, PublicContext)> {
    let encrypted = decode_encrypted_message(bytes)?;
    let plaintext = decrypt_for_device_key(&encrypted, device_key)?;
    decode_verifier_response(&plaintext)
}

fn encode_typed_message(kind: &[u8; 4], payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(kind);
    out.extend_from_slice(&payload);
    out
}

pub fn encode_signed_device_client_infor_message(
    value: &SignedDeviceClientInforWire,
) -> Result<Vec<u8>> {
    Ok(encode_typed_message(
        MSG_DEVICE_INFOR,
        encode_signed_device_client_infor_wire(value)?,
    ))
}

pub fn decode_signed_device_client_infor_message(
    bytes: &[u8],
) -> Result<SignedDeviceClientInforWire> {
    if !bytes.starts_with(MSG_DEVICE_INFOR) {
        bail!("not a DeviceClientInfor message");
    }
    decode_signed_device_client_infor_wire(&bytes[MSG_DEVICE_INFOR.len()..])
}

pub fn encode_public_context_message(public_context: &PublicContext) -> Result<Vec<u8>> {
    Ok(encode_typed_message(
        MSG_PUBLIC_CONTEXT,
        encode_public_context(public_context)?,
    ))
}

pub fn decode_public_context_message(bytes: &[u8]) -> Result<PublicContext> {
    if !bytes.starts_with(MSG_PUBLIC_CONTEXT) {
        bail!("not a PublicContext message");
    }
    decode_public_context(&bytes[MSG_PUBLIC_CONTEXT.len()..])
}

pub fn encode_evidence_message(
    evidence_reply: &EvidenceReply,
    device_signature: &Signature,
) -> Result<Vec<u8>> {
    Ok(encode_typed_message(
        MSG_EVIDENCE,
        encode_evidence_bundle(evidence_reply, device_signature)?,
    ))
}

pub fn decode_evidence_message(bytes: &[u8]) -> Result<(EvidenceReply, Signature)> {
    if !bytes.starts_with(MSG_EVIDENCE) {
        bail!("not an Evidence message");
    }
    decode_evidence_bundle(&bytes[MSG_EVIDENCE.len()..])
}

/// Write a `[u64 len][payload]` framed message to a TCP stream.
pub async fn tcp_send_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u64;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("send TCP frame length failed")?;
    stream
        .write_all(payload)
        .await
        .context("send TCP frame body failed")?;
    stream.flush().await.context("TCP flush failed")?;
    Ok(())
}

pub async fn tcp_read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 8];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read TCP frame length failed")?;
    let len = u64::from_be_bytes(len_buf);
    if len > MAX_TCP_FRAME_LEN {
        bail!("TCP frame too large: {} bytes", len);
    }

    let mut payload = vec![0u8; len as usize];
    stream
        .read_exact(&mut payload)
        .await
        .context("read TCP frame payload failed")?;
    Ok(payload)
}

pub fn save_key_infor(path: impl AsRef<Path>, key: &KeyInfor) -> Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let mut out = Vec::new();
    append_len_bytes(&mut out, &key.signing_key.to_bytes()[..]);
    fs::write(path, out).context("save KeyInfor failed")
}

pub fn load_key_infor(path: impl AsRef<Path>) -> Result<KeyInfor> {
    let bytes = fs::read(path).context("read KeyInfor failed")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let signing_key_bytes = read_len_bytes(&mut cursor)?;
    let signing_key = SigningKey::<Secp256k1>::from_slice(&signing_key_bytes)
        .context("deserialize secp256k1 signing key failed")?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok(KeyInfor {
        signing_key,
        verifying_key,
    })
}

pub fn save_device_client_infor(path: impl AsRef<Path>, value: &DeviceClientInfor) -> Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let out = encode_device_client_infor(value)?;
    fs::write(path, out).context("save DeviceClientInfor failed")
}

pub fn save_response_device_infor(
    path: impl AsRef<Path>,
    value: &ResponseDeviceInfor,
) -> Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let out = encode_response_device_infor(value)?;
    fs::write(path, out).context("save ResponseDeviceInfor failed")
}

pub fn save_public_context(path: impl AsRef<Path>, value: &PublicContext) -> Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let mut out = Vec::new();
    append_scalar_vec(&mut out, &value.root)?;
    append_verifying_key(&mut out, &value.verifier_pk);
    fs::write(path, out).context("save PublicContext failed")
}

pub fn load_public_context(path: impl AsRef<Path>) -> Result<PublicContext> {
    let bytes = fs::read(path).context("read PublicContext failed")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    Ok(PublicContext {
        root: read_scalar_vec(&mut cursor)?,
        verifier_pk: read_verifying_key(&mut cursor)?,
    })
}

pub fn save_evidence_bundle(
    path: impl AsRef<Path>,
    evidence_reply: &EvidenceReply,
    device_signature: &Signature,
) -> Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let mut out = Vec::new();
    append_proof(&mut out, &evidence_reply.proof)?;
    append_ark_vk(&mut out, &evidence_reply.vk)?;
    append_signature(&mut out, &evidence_reply.sig);
    append_verifying_key(&mut out, &evidence_reply.pk);
    append_duration(&mut out, evidence_reply.timestamp);
    append_duration(&mut out, evidence_reply.period);
    append_scalar(&mut out, &evidence_reply.authorized_infor)?;
    append_duration(&mut out, evidence_reply.timestamp_attester);
    append_duration(&mut out, evidence_reply.period_attester);
    append_signature(&mut out, &evidence_reply.proof_timestamp_period_signature);
    append_signature(&mut out, device_signature);
    fs::write(path, out).context("save EvidenceReply and attester signature failed")
}
