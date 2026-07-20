//! Hygon CSV verification component.
//!
//! Same pattern as cca-appraiser: real CSV signature verification is done by
//! the verifier host (using csv-rs + openssl, which cannot target wasm32).
//! This component only passes through fields and validates nonce binding.
//!
//! Evidence schema (JSON):
//! ```text
//! {
//!   "csv_evidence_b64": "<base64(Hygon CSV evidence JSON, containing attestation_report + cert_chain + serial_number)>",
//!   "nonce": "<base64url nonce>"
//! }
//! ```
//!
//! Claims:
//! - `tee_type`: always "csv"
//! - `verification`: passed / failed (based on nonce binding)
//! - `nonce_bound`: bool
//! - `evidence_size`: raw evidence byte count

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct CsvEvidence {
    csv_evidence_b64: String,
    nonce: String,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    // Parse the evidence JSON into a CsvEvidence struct.
    let parsed: CsvEvidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("invalid evidence json: {e}")}).to_string(),
    };

    // Decode the base64-encoded CSV evidence blob.
    let csv_evidence = match base64::engine::general_purpose::STANDARD.decode(&parsed.csv_evidence_b64) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("csv_evidence base64: {e}")}).to_string(),
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

    // Parse the full evidence JSON again to pass through host-injected fields.
    let full: serde_json::Value = serde_json::from_slice(&evidence).unwrap_or(serde_json::Value::Null);
    // Build base claims.
    let mut claims = json!({
        "tee_type": "csv",
        "verification": if nonce_ok { "passed" } else { "failed" },
        "nonce_bound": nonce_ok,
        "evidence_size": csv_evidence.len(),
    });
    // Pass through selected host-injected fields from the evidence JSON root.
    if let Some(obj) = claims.as_object_mut() {
        passthrough(&full, obj, "chip_id");
        passthrough(&full, obj, "measurement");
        passthrough(&full, obj, "vm_version");
        passthrough(&full, obj, "policy_nodbg");
        passthrough(&full, obj, "policy_noks");
    }
    claims.to_string()
}

/// Copy a key from the evidence JSON root into claims, if present.
fn passthrough(
    evidence: &serde_json::Value,
    claims: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    if let Some(v) = evidence.get(key) {
        claims.insert(key.to_string(), v.clone());
    }
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
