use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use identity_iota::core::{Object, Timestamp, ToJson, Url};
use identity_iota::credential::{Credential, CredentialBuilder, Subject};
use identity_iota::iota::{IotaDocument, NetworkName};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{DATA_DIR_NAME, DeviceClientInfor};

pub const TRUST_TTL_DAYS: i64 = 10;
pub const DEVICE_VC_CACHE_FILE: &str = "device_vc_cache.json";
pub const DEFAULT_IOTA_ENV: &str = "testnet";
pub const DEVICE_VC_MODULE: &str = "device_vc_chain";
pub const DEVICE_VC_STORE_FUNCTION: &str = "store_vc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Trusted,
    Untrusted,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVCInfor {
    pub device_did: String,
    pub device_pubkey: String,
    pub status: DeviceStatus,
    pub evidence_hash: String,
    pub last_evidence_time: Option<DateTime<Utc>>,
    pub period: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVCRecord {
    pub device_pubkey_hash: String,
    pub vc_info: DeviceVCInfor,
    pub did_document: Value,
    pub verifiable_credential: Value,
    pub chain_object_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeviceVCCache {
    pub devices: Vec<DeviceVCRecord>,
}

#[derive(Debug, Clone)]
pub struct IotaPublishConfig {
    pub package_id: String,
    pub env: String,
    pub config_path: Option<String>,
    pub gas_budget: Option<String>,
    pub owner_address: Option<String>,
}

impl IotaPublishConfig {
    pub fn from_env() -> Result<Self> {
        let package_id = std::env::var("IOTA_DEVICE_VC_PACKAGE_ID")
            .context("set IOTA_DEVICE_VC_PACKAGE_ID to the published device_vc_chain package id")?;
        let env = std::env::var("IOTA_CLIENT_ENV").unwrap_or_else(|_| DEFAULT_IOTA_ENV.to_string());
        let config_path = std::env::var("IOTA_CLIENT_CONFIG").ok();
        let gas_budget = std::env::var("IOTA_GAS_BUDGET").ok();
        let owner_address = std::env::var("IOTA_VC_OWNER_ADDRESS").ok();

        Ok(Self {
            package_id,
            env,
            config_path,
            gas_budget,
            owner_address,
        })
    }
}

impl DeviceVCCache {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
    }

    pub fn upsert(&mut self, record: DeviceVCRecord) {
        if let Some(existing) = self
            .devices
            .iter_mut()
            .find(|item| item.device_pubkey_hash == record.device_pubkey_hash)
        {
            *existing = record;
        } else {
            self.devices.push(record);
        }
    }

    pub fn expire_trusted(&mut self, now: DateTime<Utc>) -> Vec<DeviceVCRecord> {
        let mut expired = Vec::new();
        for record in &mut self.devices {
            if record.vc_info.status == DeviceStatus::Trusted && now > record.vc_info.period {
                record.vc_info.status = DeviceStatus::Expired;
                record.vc_info.period = now;
                expired.push(record.clone());
            }
        }
        expired
    }
}

pub fn default_device_vc_cache_path(verifier_manifest_dir: &Path) -> std::path::PathBuf {
    verifier_manifest_dir
        .join(DATA_DIR_NAME)
        .join(DEVICE_VC_CACHE_FILE)
}

pub fn build_background_check_record(
    dev_infor: &DeviceClientInfor,
    network: &str,
    now: DateTime<Utc>,
) -> Result<DeviceVCRecord> {
    let public_key_bytes = dev_infor
        .verifying_key
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let device_pubkey = hex::encode(&public_key_bytes);
    let device_pubkey_hash = public_key_hash_hex(&public_key_bytes);
    let has_evidence = !dev_infor.evidence_cmw_json.is_empty();
    let status = if has_evidence {
        DeviceStatus::Trusted
    } else {
        DeviceStatus::Untrusted
    };
    let period = if has_evidence {
        now + Duration::days(TRUST_TTL_DAYS)
    } else {
        now
    };

    let vc_info = DeviceVCInfor {
        device_did: format!("did:iota:{network}:0x{device_pubkey_hash}"),
        device_pubkey,
        status,
        evidence_hash: hex::encode(Sha256::digest(&dev_infor.evidence_cmw_json)),
        last_evidence_time: has_evidence.then_some(now),
        period,
    };

    let mut record = DeviceVCRecord {
        device_pubkey_hash,
        did_document: Value::Null,
        verifiable_credential: Value::Null,
        chain_object_id: None,
        vc_info,
    };
    record.did_document = build_device_did_document(network, &record)?;
    record.verifiable_credential = build_device_vc(&verifier_did(network), &record.vc_info)?;

    Ok(record)
}

pub fn refresh_record_documents(record: &mut DeviceVCRecord, network: &str) -> Result<()> {
    record.did_document = build_device_did_document(network, record)?;
    record.verifiable_credential = build_device_vc(&verifier_did(network), &record.vc_info)?;
    Ok(())
}

pub fn publish_device_vc_to_iota(
    record: &DeviceVCRecord,
    config: &IotaPublishConfig,
) -> Result<Option<String>> {
    let vc_json = serde_json::to_string(&record.verifiable_credential)?;
    let output = run_iota_client_call(&record.device_pubkey_hash, &vc_json, config)?;

    extract_created_object_id(&output).map(Some).or_else(|_| {
        eprintln!(
            "published VC transaction, but object id could not be extracted from iota output"
        );
        Ok(None)
    })
}

pub fn query_device_vc_from_iota(device_pubkey: &str, config: &IotaPublishConfig) -> Result<Value> {
    let device_pubkey_bytes =
        hex::decode(device_pubkey).context("device public key must be compressed SEC1 hex")?;
    let device_pubkey_hash = public_key_hash_hex(&device_pubkey_bytes);
    let object_ids = list_owned_object_ids(config)?;
    let mut candidates = Vec::new();

    for object_id in object_ids {
        let object = read_iota_object(&object_id, config)?;
        let object_text = serde_json::to_string(&object)?;
        if !object_text.contains("DeviceVCRecord") {
            continue;
        }
        if !object_text.contains(&device_pubkey_hash) {
            continue;
        }
        if let Some(vc_json) = find_string_field(&object, "vc_json") {
            let vc: Value =
                serde_json::from_str(vc_json).context("parse on-chain vc_json failed")?;
            let period = find_string_field(&vc, "period").unwrap_or("").to_string();
            candidates.push((period, vc));
        }
    }

    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.pop().map(|(_, vc)| vc).with_context(|| {
        format!("device VC not found on IOTA for public key hash {device_pubkey_hash}")
    })
}

fn list_owned_object_ids(config: &IotaPublishConfig) -> Result<Vec<String>> {
    let mut command = Command::new("iota");
    command.arg("client");
    if let Some(config_path) = &config.config_path {
        command.args(["--client.config", config_path]);
    }
    command.args(["--client.env", &config.env]);
    command.arg("objects");
    if let Some(owner_address) = &config.owner_address {
        command.arg(owner_address);
    }
    command.arg("--json");

    let output = command
        .output()
        .context("execute iota client objects failed")?;
    if !output.status.success() {
        bail!(
            "iota client objects failed; status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).context("parse iota objects JSON failed")?;
    let mut ids = Vec::new();
    collect_string_fields(&value, "objectId", &mut ids);
    collect_string_fields(&value, "object_id", &mut ids);
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn read_iota_object(object_id: &str, config: &IotaPublishConfig) -> Result<Value> {
    let mut command = Command::new("iota");
    command.arg("client");
    if let Some(config_path) = &config.config_path {
        command.args(["--client.config", config_path]);
    }
    command.args(["--client.env", &config.env]);
    command.arg("object");
    command.arg(object_id);
    command.arg("--json");

    let output = command
        .output()
        .context("execute iota client object failed")?;
    if !output.status.success() {
        bail!(
            "iota client object failed for {object_id}; status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("parse iota object JSON failed")
}

fn collect_string_fields(value: &Value, field: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(item) = map.get(field).and_then(Value::as_str) {
                out.push(item.to_string());
            }
            for item in map.values() {
                collect_string_fields(item, field, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_string_fields(item, field, out);
            }
        }
        _ => {}
    }
}

fn find_string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    match value {
        Value::Object(map) => {
            if let Some(item) = map.get(field).and_then(Value::as_str) {
                return Some(item);
            }
            map.values().find_map(|item| find_string_field(item, field))
        }
        Value::Array(items) => items.iter().find_map(|item| find_string_field(item, field)),
        _ => None,
    }
}

fn run_iota_client_call(
    device_pubkey_hash: &str,
    vc_json: &str,
    config: &IotaPublishConfig,
) -> Result<Value> {
    let mut command = Command::new("iota");
    command.arg("client");
    if let Some(config_path) = &config.config_path {
        command.args(["--client.config", config_path]);
    }
    command.args(["--client.env", &config.env]);
    command.arg("call");
    command.args(["--package", &config.package_id]);
    command.args(["--module", DEVICE_VC_MODULE]);
    command.args(["--function", DEVICE_VC_STORE_FUNCTION]);
    command.arg("--args");
    command.arg(move_string_arg(device_pubkey_hash));
    command.arg(move_string_arg(vc_json));
    if let Some(gas_budget) = &config.gas_budget {
        command.args(["--gas-budget", gas_budget]);
    }
    command.arg("--json");

    let output = command
        .output()
        .context("execute iota client call failed")?;
    if !output.status.success() {
        bail!(
            "iota client call failed; status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("parse iota client call JSON output failed")
}

fn move_string_arg(value: &str) -> String {
    format!(
        "{{\"bytes\":[{}]}}",
        value
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn extract_created_object_id(value: &Value) -> Result<String> {
    if let Some(object_changes) = value.get("objectChanges").and_then(Value::as_array) {
        for change in object_changes {
            let created = change
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "created");
            if created {
                if let Some(object_id) = change.get("objectId").and_then(Value::as_str) {
                    return Ok(object_id.to_string());
                }
            }
        }
    }

    bail!("created object id not found")
}

pub fn build_device_vc(issuer_did: &str, device_vc_info: &DeviceVCInfor) -> Result<Value> {
    let subject = Subject::with_id_and_properties(
        Url::parse(&device_vc_info.device_did)?,
        device_vc_info_properties(device_vc_info)?,
    );

    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse(format!(
            "urn:hydra-device-vc:{}",
            device_vc_info.evidence_hash
        ))?)
        .type_("DeviceVC")
        .issuer(Url::parse(issuer_did)?)
        .issuance_date(Timestamp::parse(
            &device_vc_info
                .last_evidence_time
                .unwrap_or(device_vc_info.period)
                .to_rfc3339(),
        )?)
        .subject(subject)
        .build()?;

    Ok(credential.to_json_value()?)
}

fn device_vc_info_properties(device_vc_info: &DeviceVCInfor) -> Result<Object> {
    let value = serde_json::to_value(device_vc_info)?;
    let object = value
        .as_object()
        .cloned()
        .context("DeviceVCInfor must serialize to a JSON object")?;

    Ok(object.into_iter().collect())
}

pub fn build_device_did_document(network: &str, record: &DeviceVCRecord) -> Result<Value> {
    let network_name: NetworkName = NetworkName::try_from(network.to_owned())?;
    let mut document_json = IotaDocument::new(&network_name).to_json_value()?;
    let did = record.vc_info.device_did.clone();
    let public_key_bytes = hex::decode(&record.vc_info.device_pubkey)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .context("decode device public key for DID document failed")?;
    let encoded_point = verifying_key.to_encoded_point(false);
    let public_key_jwk_x = URL_SAFE_NO_PAD.encode(
        encoded_point
            .x()
            .context("missing secp256k1 x coordinate")?,
    );
    let public_key_jwk_y = URL_SAFE_NO_PAD.encode(
        encoded_point
            .y()
            .context("missing secp256k1 y coordinate")?,
    );

    document_json["id"] = json!(did);
    document_json["verificationMethod"] = json!([
        {
            "id": format!("{did}#device-key"),
            "type": "JsonWebKey",
            "controller": did,
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "alg": "ES256K",
                "kid": "device-key",
                "x": public_key_jwk_x,
                "y": public_key_jwk_y
            }
        }
    ]);
    document_json["authentication"] = json!([format!("{did}#device-key")]);
    document_json["service"] = json!([
        {
            "id": format!("{did}#trust-state"),
            "type": "DeviceTrustState",
            "serviceEndpoint": format!("urn:hydra-device-state:{}", record.device_pubkey_hash),
            "deviceVCInfor": record.vc_info
        }
    ]);

    Ok(document_json)
}

pub fn public_key_hash_hex(public_key_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key_bytes))
}

pub fn verifier_did(network: &str) -> String {
    format!("did:iota:{network}:verifier")
}
