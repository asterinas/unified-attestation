//! CCA verification component.
//!
//! Parses CCA evidence submitted by the attester, validates nonce binding, and
//! returns claims for the verifier policy to compare against.
//!
//! Evidence schema (JSON):
//! ```text
//! {
//!   "cca_token_b64": "<base64(ARM CCA hardware-signed attestation token)>",
//!   "nonce": "<base64url nonce, same as the challenge>"
//! }
//! ```
//!
//! Claims produced by the component:
//! - `tee_type`: always "cca"
//! - `verification`: nonce validation result (passed / failed)
//! - `nonce_bound`: whether the nonce was successfully bound
//! - `token_size`: CCA token byte count (for diagnostics)

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct CcaEvidence {
    cca_token_b64: String,
    nonce: String,
}

fn evaluate_impl(evidence: Vec<u8>, expected_report_data: Option<Vec<u8>>) -> String {
    // Parse the evidence JSON into a CcaEvidence struct.
    let parsed: CcaEvidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => {
            return json!({"error": format!("invalid evidence json: {e}")}).to_string();
        }
    };

    // Decode the base64-encoded CCA token.
    let cca_token = match base64::engine::general_purpose::STANDARD.decode(&parsed.cca_token_b64) {
        Ok(v) => v,
        Err(e) => {
            return json!({"error": format!("cca_token base64: {e}")}).to_string();
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

    // Pass through CCA measurement values that the host already injected into
    // the evidence JSON root (read from top-level fields).
    let full: serde_json::Value = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(_) => serde_json::Value::Null,
    };

    // Build base claims.
    let mut claims = json!({
        "tee_type": "cca",
        "verification": if nonce_ok { "passed" } else { "failed" },
        "nonce_bound": nonce_ok,
        "token_size": cca_token.len(),
    });
    // Pass through host-injected CCA measurement fields.
    if let Some(obj) = claims.as_object_mut() {
        passthrough(&full, obj, "cca_realm_initial_measurement");
        passthrough(&full, obj, "cca_realm_personalization_value");
        passthrough(&full, obj, "cca_platform_instance_id");
        passthrough(&full, obj, "cca_platform_implementation_id");
        passthrough(&full, obj, "cca_platform_lifecycle");
        passthrough(&full, obj, "cca_platform_sw_components");
    }
    claims.to_string()
}

/// Read a key from the evidence JSON root and write it into claims if present.
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
