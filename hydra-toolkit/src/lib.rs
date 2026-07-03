pub mod device_vc;
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
use ark_std::UniformRand;
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
use rayon::prelude::*;
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
pub const MSG_RELYING_PARTY_DEVICE_INFOR: &[u8; 4] = b"RDIN";
pub const MSG_PUBLIC_CONTEXT: &[u8; 4] = b"PUBC";
pub const MSG_EVIDENCE: &[u8; 4] = b"EVID";
pub const EVIDENCE_REPLY_ATTESTER_PERIOD_SECS: u64 = 2 * 60;

pub fn project_root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn workspace_data_dir() -> PathBuf {
    project_root_dir().join(DATA_DIR_NAME)
}

pub fn workspace_data_file(name: &str) -> PathBuf {
    workspace_data_dir().join(name)
}

pub fn ensure_workspace_data_dir() -> Result<()> {
    fs::create_dir_all(workspace_data_dir()).context("create workspace-data directory failed")
}

fn ensure_parent_dir(path: impl AsRef<Path>) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directory failed")?;
    }
    Ok(())
}

pub fn read_measurement_file() -> String {
    fs::read_to_string(project_root_dir().join("example.txt"))
        .expect("read measurement file failed")
}

fn generate_evidence_cmw_json() -> Vec<u8> {
    Vec::new()
}

pub fn default_hasher() -> Poseidon<BlsScalar> {
    crate::poseidon::poseidon_setup(arkworks_utils::Curve::Bls381, 5, 3)
}

#[derive(Debug)]
pub struct EvidenceReply {
    pub proof: Proof<Bls12_381>,
    pub vk: ArkVerifyingKey<Bls12_381>,
    pub sig: Signature,
    pub pk: VerifyingKey<Secp256k1>,
    pub timestamp: Duration,
    pub period: Duration,
    pub authorized_infor: BlsScalar,
    pub timestamp_attester: Duration,
    pub period_attester: Duration,
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
    pub fn gen_public_inputs(&self, root: &[BlsScalar]) -> Vec<BlsScalar> {
        let mut public_inputs = vec![];
        public_inputs.push(BlsScalar::from(BigUint::from_bytes_be(
            self.pk.to_encoded_point(true).as_bytes(),
        )));
        public_inputs.extend_from_slice(&root);
        public_inputs.push(self.authorized_infor);
        public_inputs.push(BlsScalar::from(self.timestamp.as_secs()));
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

pub fn current_unix_duration() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Model {
    Passport,
    BackgroundCheck,
}

impl Model {
    pub fn from_arg(value: &str) -> Result<Self> {
        match value {
            "passport" => Ok(Self::Passport),
            "background_check" | "background-check" => Ok(Self::BackgroundCheck),
            other => bail!("unknown mode: {other}; expected passport or background_check"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceClientInfor {
    pub mode: Model,
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub measured_value: String,
    pub merkle_leaf: Option<BlsScalar>,
    pub timestamp: Duration,
    pub period: Duration,
    pub evidence_cmw_json: Vec<u8>,
}
impl DeviceClientInfor {
    pub fn new(vk: VerifyingKey<Secp256k1>, leaf: BlsScalar) -> DeviceClientInfor {
        Self::new_with_mode(Model::Passport, vk, Some(leaf))
    }

    pub fn new_with_mode(
        mode: Model,
        vk: VerifyingKey<Secp256k1>,
        leaf: Option<BlsScalar>,
    ) -> DeviceClientInfor {
        let measure = read_measurement_file();
        let merkle_leaf = match mode {
            Model::Passport => leaf,
            Model::BackgroundCheck => None,
        };
        let timestamp = current_unix_duration().expect("system time is before UNIX_EPOCH");
        let period = Duration::from_secs(8640000 as u64);
        DeviceClientInfor {
            mode,
            verifying_key: vk,
            merkle_leaf,
            measured_value: measure,
            timestamp,
            period,
            evidence_cmw_json: generate_evidence_cmw_json(),
        }
    }
}

pub struct DeviceClientInforWire {
    pub mode: Model,
    pub verifying_key: Vec<u8>,
    pub measured_value: String,
    pub merkle_leaf: Option<Vec<u8>>,
    pub timestamp: Duration,
    pub period: Duration,
    pub evidence_cmw_json: Vec<u8>,
}

pub struct SignedDeviceClientInforWire {
    pub device: DeviceClientInforWire,
    pub signature: Vec<u8>,
}

pub struct RelyingPartySignedDeviceClientInforWire {
    pub signed_device: SignedDeviceClientInforWire,
    pub relying_party_verifying_key: Vec<u8>,
    pub relying_party_signature: Vec<u8>,
}

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
    match find_interval_index(&leaves, &leaf) {
        Some((vect, index)) => {
            let inx = 0;

            match find_shrubs_path(&root, &vect, inx, index, hasher) {
                Some((path, tag)) => {
                    // for i in path.iter() {
                    //     println!("path: {}", i);
                    // }

                    (Some(path), Some(tag))
                }

                None => (None, None),
            }
        }

        None => {
            println!("110");
            (None, None)
        }
    }
}

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

pub fn generate_device_merkle_leaf(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let measure = read_measurement_file();
    let sk = BlsScalar::from(BigUint::from_bytes_be(
        &device_key.signing_key.to_bytes()[..],
    ));
    let pk = BlsScalar::from(BigUint::from_bytes_be(
        &device_key.verifying_key.to_encoded_point(true).as_bytes(),
    ));
    let ar = BlsScalar::from(BigUint::from_bytes_be(measure.as_bytes()));

    let c = hasher.hash(&[ar, sk][..]).unwrap();
    let leaf = hasher.hash(&[c, pk][..]).unwrap();

    leaf
}
#[derive(Clone)]
pub struct ResponseDeviceInfor {
    pub mode: Model,
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
        Self::new_with_mode(Model::Passport, pk)
    }

    pub fn new_with_mode(mode: Model, pk: VerifyingKey<Secp256k1>) -> ResponseDeviceInfor {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time failed");
        let period = Duration::from_secs(8640000 as u64);
        ResponseDeviceInfor {
            mode,
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

    pub fn set_shrubs_path_and_tag(&mut self, path: Vec<BlsScalar>, tag: Vec<bool>) {
        self.shrubs_path = Some(path);
        self.shrubs_tag = Some(tag);
    }
}

pub struct ResponseDeviceInforWire {
    pub mode: Model,
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
    let output = hasher.hash(&[temp_2, peri][..]).unwrap();

    output
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
    let output = hasher.hash(&[temp_2, peri][..]).unwrap();

    output
}

pub fn insert_batch_devices(
    mut root: &mut Vec<BlsScalar>,
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

        insert_shrubs_tree(&mut root, &n_leaf, k, &exps, ll + 1, &hasher);
    } else {
        insert_shrubs_tree(&mut root, &new_leaves, k, &exps, ll, &hasher);
    }
}
pub fn generate_device_client_infor(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
) -> DeviceClientInfor {
    generate_device_client_infor_with_mode(device_key, hasher, Model::Passport)
}

pub fn generate_device_client_infor_with_mode(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
    mode: Model,
) -> DeviceClientInfor {
    let device_leaf = match mode {
        Model::Passport => Some(generate_device_merkle_leaf(device_key, hasher)),
        Model::BackgroundCheck => None,
    };
    DeviceClientInfor::new_with_mode(mode, device_key.verifying_key, device_leaf)
}

pub fn gen_leaves() -> Vec<BlsScalar> {
    let n = 1usize << 11;
    (0..n - 1)
        .into_par_iter()
        .map_init(|| OsRng, |rng, _| BlsScalar::rand(rng))
        .collect()
}

pub fn gen_new_leaves() -> Vec<BlsScalar> {
    let n = 1usize << 12;
    (0..n - 1)
        .into_par_iter()
        .map_init(|| OsRng, |rng, _| BlsScalar::rand(rng))
        .collect()
}

#[derive(Debug, Clone)]
pub struct PublicContext {
    pub root: Vec<BlsScalar>,
    pub verifier_pk: VerifyingKey<Secp256k1>,
}

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
    // cursor.read_exact(&mut bytes).context("read length-prefixed bytes failed")?;
    std::io::Read::read_exact(cursor, &mut bytes).context("read length-prefixed bytes failed")?;
    Ok(bytes)
}

fn append_string(out: &mut Vec<u8>, value: &str) {
    append_len_bytes(out, value.as_bytes());
}

fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    String::from_utf8(read_len_bytes(cursor)?).context("parse UTF-8 string failed")
}

fn append_model(out: &mut Vec<u8>, value: Model) {
    out.push(match value {
        Model::Passport => 0,
        Model::BackgroundCheck => 1,
    });
}

fn read_model(cursor: &mut Cursor<&[u8]>) -> Result<Model> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(Model::Passport),
        1 => Ok(Model::BackgroundCheck),
        other => bail!("Model tag is invalid: {}", other),
    }
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
    let merkle_leaf = match value.mode {
        Model::Passport => Some(encode_scalar(
            value
                .merkle_leaf
                .as_ref()
                .context("passport mode requires merkle_leaf")?,
        )?),
        Model::BackgroundCheck => None,
    };

    Ok(DeviceClientInforWire {
        mode: value.mode,
        verifying_key: value
            .verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        measured_value: value.measured_value.clone(),
        merkle_leaf,
        timestamp: value.timestamp,
        period: value.period,
        evidence_cmw_json: value.evidence_cmw_json.clone(),
    })
}

pub fn device_client_infor_from_wire(wire: &DeviceClientInforWire) -> Result<DeviceClientInfor> {
    let merkle_leaf = match wire.mode {
        Model::Passport => Some(decode_scalar(
            wire.merkle_leaf
                .as_deref()
                .context("passport mode requires merkle_leaf")?,
        )?),
        Model::BackgroundCheck => None,
    };

    Ok(DeviceClientInfor {
        mode: wire.mode,
        verifying_key: VerifyingKey::<Secp256k1>::from_sec1_bytes(&wire.verifying_key)
            .context("decode DeviceClientInforWire verifying_key failed")?,
        measured_value: wire.measured_value.clone(),
        merkle_leaf,
        timestamp: wire.timestamp,
        period: wire.period,
        evidence_cmw_json: wire.evidence_cmw_json.clone(),
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

pub fn sign_relying_party_device_client_infor_to_wire(
    signed_device: SignedDeviceClientInforWire,
    relying_party_key: &KeyInfor,
) -> Result<RelyingPartySignedDeviceClientInforWire> {
    let message = encode_signed_device_client_infor_wire(&signed_device)?;
    let signature: Signature = relying_party_key.signing_key.sign(message.as_slice());
    Ok(RelyingPartySignedDeviceClientInforWire {
        signed_device,
        relying_party_verifying_key: relying_party_key
            .verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        relying_party_signature: encode_signature(&signature),
    })
}

pub fn verify_relying_party_signed_device_client_infor_wire(
    signed: &RelyingPartySignedDeviceClientInforWire,
) -> Result<()> {
    let verifying_key =
        VerifyingKey::<Secp256k1>::from_sec1_bytes(&signed.relying_party_verifying_key)
            .context("decode relying-party verifying_key failed")?;
    let signature = decode_signature(&signed.relying_party_signature)?;
    let message = encode_signed_device_client_infor_wire(&signed.signed_device)?;
    verifying_key
        .verify(message.as_slice(), &signature)
        .context("relying-party DeviceClientInfor signature verification failed")
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
    let recipient_public_key =
        PublicKey::from_sec1_bytes(device_pubkey.to_encoded_point(true).as_bytes())
            .context("decode device public key for encryption failed")?;
    let ephemeral_secret = k256::ecdh::EphemeralSecret::random(&mut OsRng);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
    let key = derive_aes_key(shared_secret.raw_secret_bytes().as_slice())?;
    let cipher = Aes256Gcm::new_from_slice(&key).context("create AES-GCM cipher failed")?;

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
    let cipher = Aes256Gcm::new_from_slice(&key).context("create AES-GCM cipher failed")?;
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
        mode: value.mode,
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
        mode: wire.mode,
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

pub fn encode_key_infor(key: &KeyInfor) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &key.signing_key.to_bytes()[..]);
    Ok(out)
}

pub fn decode_key_infor(bytes: &[u8]) -> Result<KeyInfor> {
    let mut cursor = Cursor::new(bytes);
    let sk_bytes = read_len_bytes(&mut cursor)?;
    if sk_bytes.len() != 32 {
        bail!(
            "secp256k1 secret key length must be 32 bytes, got {}",
            sk_bytes.len()
        );
    }
    let signing_key = SigningKey::<Secp256k1>::from_bytes(k256::FieldBytes::from_slice(&sk_bytes))
        .context("decode secp256k1 secret key failed")?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok(KeyInfor {
        signing_key,
        verifying_key,
    })
}

pub fn encode_device_client_infor(value: &DeviceClientInfor) -> Result<Vec<u8>> {
    encode_device_client_infor_wire(&device_client_infor_to_wire(value)?)
}

pub fn encode_device_client_infor_wire(value: &DeviceClientInforWire) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_model(&mut out, value.mode);
    append_len_bytes(&mut out, &value.verifying_key);
    append_string(&mut out, &value.measured_value);
    match &value.merkle_leaf {
        Some(merkle_leaf) => {
            out.push(1);
            append_len_bytes(&mut out, merkle_leaf);
        }
        None => out.push(0),
    }
    append_duration(&mut out, value.timestamp);
    append_duration(&mut out, value.period);
    append_len_bytes(&mut out, &value.evidence_cmw_json);
    Ok(out)
}

pub fn decode_device_client_infor(bytes: &[u8]) -> Result<DeviceClientInfor> {
    let wire = decode_device_client_infor_wire(bytes)?;
    device_client_infor_from_wire(&wire)
}

pub fn decode_device_client_infor_wire(bytes: &[u8]) -> Result<DeviceClientInforWire> {
    let mut cursor = Cursor::new(bytes);
    Ok(DeviceClientInforWire {
        mode: read_model(&mut cursor)?,
        verifying_key: read_len_bytes(&mut cursor)?,
        measured_value: read_string(&mut cursor)?,
        merkle_leaf: match read_exact::<1>(&mut cursor)?[0] {
            0 => None,
            1 => Some(read_len_bytes(&mut cursor)?),
            other => bail!("Option<merkle_leaf> tag invalid: {}", other),
        },
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        evidence_cmw_json: read_len_bytes(&mut cursor)?,
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

pub fn encode_relying_party_signed_device_client_infor_wire(
    value: &RelyingPartySignedDeviceClientInforWire,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(
        &mut out,
        &encode_signed_device_client_infor_wire(&value.signed_device)?,
    );
    append_len_bytes(&mut out, &value.relying_party_verifying_key);
    append_len_bytes(&mut out, &value.relying_party_signature);
    Ok(out)
}

pub fn decode_relying_party_signed_device_client_infor_wire(
    bytes: &[u8],
) -> Result<RelyingPartySignedDeviceClientInforWire> {
    let mut cursor = Cursor::new(bytes);
    let signed_device = decode_signed_device_client_infor_wire(&read_len_bytes(&mut cursor)?)?;
    let relying_party_verifying_key = read_len_bytes(&mut cursor)?;
    let relying_party_signature = read_len_bytes(&mut cursor)?;
    Ok(RelyingPartySignedDeviceClientInforWire {
        signed_device,
        relying_party_verifying_key,
        relying_party_signature,
    })
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
    append_model(&mut out, value.mode);
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
    let mode = read_model(&mut cursor)?;
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
        mode,
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

pub fn encode_encrypted_verifier_response(
    dev_res: &ResponseDeviceInfor,
    public_context: &PublicContext,
    device_pubkey: &VerifyingKey<Secp256k1>,
) -> Result<Vec<u8>> {
    let plaintext = encode_verifier_response(dev_res, public_context)?;
    let encrypted = encrypt_for_device_pubkey(&plaintext, device_pubkey)?;
    encode_encrypted_message(&encrypted)
}

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

pub fn encode_relying_party_signed_device_client_infor_message(
    value: &RelyingPartySignedDeviceClientInforWire,
) -> Result<Vec<u8>> {
    Ok(encode_typed_message(
        MSG_RELYING_PARTY_DEVICE_INFOR,
        encode_relying_party_signed_device_client_infor_wire(value)?,
    ))
}

pub fn decode_relying_party_signed_device_client_infor_message(
    bytes: &[u8],
) -> Result<RelyingPartySignedDeviceClientInforWire> {
    if !bytes.starts_with(MSG_RELYING_PARTY_DEVICE_INFOR) {
        bail!("not a RelyingPartySignedDeviceClientInfor message");
    }
    decode_relying_party_signed_device_client_infor_wire(
        &bytes[MSG_RELYING_PARTY_DEVICE_INFOR.len()..],
    )
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
    let sk_bytes = read_len_bytes(&mut cursor)?;
    if sk_bytes.len() != 32 {
        bail!(
            "secp256k1 secret key length must be 32 bytes, got {}",
            sk_bytes.len()
        );
    }
    let signing_key = SigningKey::<Secp256k1>::from_bytes(k256::FieldBytes::from_slice(&sk_bytes))
        .context("decode secp256k1 secret key failed")?;
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

pub fn load_device_client_infor(path: impl AsRef<Path>) -> Result<DeviceClientInfor> {
    let bytes = fs::read(path).context("read DeviceClientInfor failed")?;
    decode_device_client_infor(&bytes)
}

pub fn save_response_device_infor(
    path: impl AsRef<Path>,
    value: &ResponseDeviceInfor,
) -> Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let out = encode_response_device_infor(value)?;
    fs::write(path, out).context("save ResponseDeviceInfor failed")
}

pub fn load_response_device_infor(path: impl AsRef<Path>) -> Result<ResponseDeviceInfor> {
    let bytes = fs::read(path).context("read ResponseDeviceInfor failed")?;
    decode_response_device_infor(&bytes)
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

pub fn load_evidence_bundle(path: impl AsRef<Path>) -> Result<(EvidenceReply, Signature)> {
    let bytes = fs::read(path).context("read EvidenceReply and attester signature failed")?;
    let mut cursor = Cursor::new(bytes.as_slice());
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
