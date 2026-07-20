//! iTrustee verification component.
//!
//! Real signature verification for iTrustee requires the native libteeverifier.so
//! library. Re-signature verification is NOT performed inside wasm. This component
//! validates nonce binding, extracts TA measurement values from the report JSON,
//! and passes through verification results injected by the host.
//!
//! Evidence schema (after attester wraps it):
//! ```text
//! {
//!   "report": "<JSON string, from iTrustee SDK RemoteAttest return value>",
//!   "nonce": "<base64url nonce>",
//!   "ima_log": [<optional, IMA log byte array>]
//! }
//! ```
//!
//! After the host completes verification, the following fields are injected
//! into the root level of the evidence JSON:
//! - `itrustee_uuid`: TA UUID
//! - `itrustee_ta_img`: TA image measurement (hex)
//! - `itrustee_ta_mem`: TA memory measurement (hex)
//! - `itrustee_hash_alg`: hash algorithm
//! - `itrustee_version`: TA version number
//!
//! Claims:
//! - `tee_type`: always "itrustee"
//! - `verification`: passed / failed (based on nonce binding)
//! - `nonce_bound`: bool
//! - `uuid` / `ta_img` / `ta_mem` / `hash_alg` / `version` / `ima_log_size`: extracted from evidence

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct ItrusteeEvidence {
    report: String,
    nonce: String,
    #[serde(default)]
    ima_log: Option<Vec<u8>>,
    // Host-injected fields (optional).
    #[serde(default)]
    itrustee_uuid: Option<String>,
    #[serde(default)]
    itrustee_ta_img: Option<String>,
    #[serde(default)]
    itrustee_ta_mem: Option<String>,
    #[serde(default)]
    itrustee_hash_alg: Option<String>,
    #[serde(default)]
    itrustee_version: Option<String>,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    // Parse the evidence JSON into an ItrusteeEvidence struct.
    let parsed: ItrusteeEvidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => {
            return json!({"error": format!("invalid evidence json: {e}")}).to_string();
        }
    };

    // Compare the evidence nonce with the expected nonce (report_data base64url-encoded).
    let nonce_ok = match expected_report_data.as_deref() {
        Some(report_data) => {
            let expected_nonce =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(report_data);
            parsed.nonce == expected_nonce
        }
        None => false,
    };

    // Prefer host-injected values; fall back to extracting from the report JSON string.
    let (uuid, ta_img, ta_mem, hash_alg, version) = if parsed.itrustee_uuid.is_some() {
        (
            parsed.itrustee_uuid.unwrap_or_default(),
            parsed.itrustee_ta_img,
            parsed.itrustee_ta_mem,
            parsed.itrustee_hash_alg,
            parsed.itrustee_version,
        )
    } else {
        // Parse the report JSON string and walk into payload for each field.
        let report: serde_json::Value =
            serde_json::from_str(&parsed.report).unwrap_or(serde_json::Value::Null);
        let payload = report.get("payload");
        (
            payload
                .and_then(|p| p.get("uuid"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            payload
                .and_then(|p| p.get("ta_img"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payload
                .and_then(|p| p.get("ta_mem"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payload
                .and_then(|p| p.get("hash_alg"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payload
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        )
    };

    let ima_log_size = parsed.ima_log.as_ref().map(|v| v.len());

    // Build base claims with required fields.
    let mut claims = json!({
        "tee_type": "itrustee-hydra",
        "verification": if nonce_ok { "passed" } else { "failed" },
        "nonce_bound": nonce_ok,
        "uuid": uuid,
    });
    // Conditionally insert optional fields.
    if let Some(obj) = claims.as_object_mut() {
        if let Some(ref v) = ta_img {
            obj.insert("ta_img".into(), v.clone().into());
        }
        if let Some(ref v) = ta_mem {
            obj.insert("ta_mem".into(), v.clone().into());
        }
        if let Some(ref v) = hash_alg {
            obj.insert("hash_alg".into(), v.clone().into());
        }
        if let Some(ref v) = version {
            obj.insert("version".into(), v.clone().into());
        }
        if let Some(sz) = ima_log_size {
            obj.insert("ima_log_size".into(), sz.into());
        }
    }
    claims.to_string()
}

struct Component;

impl Guest for Component {
    type Verifier = Verifier;
}

struct Verifier;

impl GuestVerifier for Verifier {
    fn new() -> Self {
        Self
    }

    fn evaluate(
        &self,
        evidence: Vec<u8>,
        expected_report_data: OptionalData,
        _expected_init_data_hash: OptionalData,
    ) -> String {
        // Convert OptionalData enum to Option<Vec<u8>> for easier handling.
        let report_data = match expected_report_data {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        evaluate_impl(evidence, report_data)
    }
}

export!(Component);
