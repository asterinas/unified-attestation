//! iTrustee host-side evidence field extraction.
//!
//! Full verification requires libteeverifier.so FFI, which is not available in the build
//! environment. This module parses the report JSON to extract TA measurements for wasm
//! appraiser passthrough. When libteeverifier.so is available in the deployment environment,
//! the FFI verification path can be wired in here (ref: hydra/evidence-verify).

use anyhow::{Context, Result};
use serde_json::Value;

/// TA measurements extracted from iTrustee evidence.
#[derive(Debug, Default)]
pub struct ItrusteeVerificationResult {
    pub uuid: Option<String>,
    pub ta_img: Option<String>,
    pub ta_mem: Option<String>,
    pub hash_alg: Option<String>,
    pub version: Option<String>,
}

/// Parse evidence JSON and extract payload fields from the embedded report.
///
/// Evidence format (after attester wrapping):
/// ```json
/// { "report": "<JSON string>", "nonce": "...", "ima_log": null }
/// ```
///
/// Report JSON format (iTrustee SDK return value):
/// ```json
/// { "payload": { "uuid": "...", "ta_img": "...", "ta_mem": "...", ... } }
/// ```
pub fn extract_claims(evidence: &[u8]) -> Result<ItrusteeVerificationResult> {
    let ev: Value =
        serde_json::from_slice(evidence).context("parse itrustee evidence JSON")?;
    let report_str = ev
        .get("report")
        .and_then(|v| v.as_str())
        .context("evidence.report missing or not a string")?;
    let report: Value =
        serde_json::from_str(report_str).context("parse itrustee report JSON")?;
    let payload = report.get("payload");

    Ok(ItrusteeVerificationResult {
        uuid: payload.and_then(|p| p.get("uuid")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        ta_img: payload.and_then(|p| p.get("ta_img")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        ta_mem: payload.and_then(|p| p.get("ta_mem")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        hash_alg: payload.and_then(|p| p.get("hash_alg")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        version: payload.and_then(|p| p.get("version")).and_then(|v| v.as_str()).map(|s| s.to_string()),
    })
}
