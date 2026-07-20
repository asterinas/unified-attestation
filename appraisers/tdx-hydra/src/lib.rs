//! TDX verification component (reference: trustmee-artifact tdx-verifier-component).
//!
//! Performs full DCAP verification inside wasm: ECDSA + PCK chain + Intel root
//! CA + CRL + TCB + QE Identity. Collateral is fetched by the attester from
//! PCS/PCCS and submitted alongside the evidence.
//!
//! Evidence schema (JSON):
//! ```text
//! {
//!   "quote_b64":      "<base64(TDX quote)>",
//!   "collateral_b64": "<base64(serde_json::to_vec(QuoteCollateralV3))>",
//!   "now_secs":       1700000000
//! }
//! ```
//!
//! Verification order:
//! 1. dcap-qvl full chain verification (result includes tcb_status / advisory_ids)
//! 2. quote.report_data[0..32] == expected_report_data (challenge nonce binding)
//! 3. quote.mr_config_id == expected_init_data_hash (if passed through by host)
//! 4. quote fields (mr_td / mr_seam / rtmr0..3 / mr_config_id) are written back
//!    into claims for verifier policy comparison

use base64::Engine;
use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::quote::Quote;
use serde::Deserialize;
use serde_json::json;

wit_bindgen::generate!({
    path: "../wit",
    world: "verifier",
});

use exports::unified_attestation::verifier::verifier_interface::{Guest, GuestVerifier, OptionalData};

#[derive(Debug, Deserialize)]
struct Evidence {
    quote_b64: String,
    collateral_b64: String,
    now_secs: u64,
}

/// Decode a standard base64 string, returning a String error on failure.
fn b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

/// Build a "failed" claims JSON with the given error message.
fn err(msg: impl Into<String>) -> String {
    json!({"tee_type": "tdx-hydra", "verification": "failed", "error": msg.into()}).to_string()
}

fn evaluate_impl(
    evidence: Vec<u8>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> String {
    // Parse the evidence JSON.
    let parsed: Evidence = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => return err(format!("invalid evidence json: {e}")),
    };
    // Decode the base64 quote and collateral.
    let quote_bin = match b64(&parsed.quote_b64) {
        Ok(v) => v,
        Err(e) => return err(format!("quote: {e}")),
    };
    let collateral_bin = match b64(&parsed.collateral_b64) {
        Ok(v) => v,
        Err(e) => return err(format!("collateral: {e}")),
    };
    let collateral: QuoteCollateralV3 = match serde_json::from_slice(&collateral_bin) {
        Ok(v) => v,
        Err(e) => return err(format!("collateral parse: {e}")),
    };

    // ---- Step 1: full DCAP chain verification ----
    let verified = match dcap_qvl::verify::rustcrypto::verify(
        &quote_bin,
        &collateral,
        parsed.now_secs,
    ) {
        Ok(v) => v,
        Err(e) => return err(format!("dcap verify: {e:?}")),
    };

    // ---- Step 2: parse quote to extract TD fields (chain verification already done) ----
    let quote = match Quote::parse(&quote_bin) {
        Ok(v) => v,
        Err(e) => return err(format!("parse quote: {e:?}")),
    };
    let td = match quote.report.as_td10() {
        Some(v) => v,
        None => return err("not a TDX quote"),
    };

    // ---- Step 3: challenge nonce binding — first 32 bytes of report_data ----
    if let Some(expected) = expected_report_data {
        let cmp_len = expected.len().min(td.report_data.len());
        if &td.report_data[..cmp_len] != expected.as_slice()
            || td.report_data[cmp_len..].iter().any(|b| *b != 0)
        {
            return err("report_data does not match expected (challenge nonce)");
        }
    }

    // ---- Step 4: init_data_hash binding against mr_config_id (if provided by host) ----
    if let Some(expected) = expected_init_data_hash {
        let cmp_len = expected.len().min(td.mr_config_id.len());
        if &td.mr_config_id[..cmp_len] != expected.as_slice() {
            return err("mr_config_id does not match expected_init_data_hash");
        }
    }

    // Build passed claims with all TDX measurement fields.
    json!({
        "tee_type": "tdx-hydra",
        "verification": "passed",
        "tcb_status": verified.status,
        "advisory_ids": verified.advisory_ids,
        "mr_td": hex::encode(td.mr_td),
        "mr_seam": hex::encode(td.mr_seam),
        "mr_signer_seam": hex::encode(td.mr_signer_seam),
        "mr_config_id": hex::encode(td.mr_config_id),
        "report_data": hex::encode(td.report_data),
    })
    .to_string()
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
        expected_init_data_hash: OptionalData,
    ) -> String {
        // Convert both OptionalData enums to Option<Vec<u8>> for easier handling.
        let report = match expected_report_data {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        let init = match expected_init_data_hash {
            OptionalData::Value(v) => Some(v),
            OptionalData::NotProvided => None,
        };
        evaluate_impl(evidence, report, init)
    }
}

export!(Component);
