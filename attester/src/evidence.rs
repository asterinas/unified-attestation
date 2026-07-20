//! Evidence construction.
//!
//! All TEE paths collect evidence through the guest-components api-server-rest HTTP interface:
//! `GET /aa/evidence?runtime_data=<base64(nonce)>` → returns raw TEE evidence bytes.
//!
//! - mock: fixed payload + nonce passthrough (no TEE hardware required)
//! - cca / csv / tdx: AA returns raw evidence (CCA token / CSV report / TDX quote),
//!   attester base64-encodes and wraps it
//! - itrustee / virtcca: AA returns JSON (report + optional log), attester appends the nonce field
//! - *-hydra: identical to the non-hydra path for TEE evidence; the ZK layer is handled by
//!   the separate hydra TCP client task and is orthogonal to the wasm evidence.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use protos::TeeType;
use serde_json::json;
use std::io::Read;

pub async fn build_evidence(
    tee_type: TeeType,
    nonce_bytes: &[u8],
    aa_endpoint: &str,
) -> Result<Vec<u8>> {
    let nonce_b64 = B64URL.encode(nonce_bytes);
    let nonce_b64 = nonce_b64.as_str();
    // Each *-hydra variant produces the same TEE evidence as its non-hydra counterpart.
    // The hydra ZK layer is handled by the separate TCP client task, orthogonal to wasm.
    match tee_type {
        // Mock: fixed payload, no hardware
        TeeType::Mock => Ok(serde_json::to_vec(&json!({
            "payload": {
                "device_id": "mock-device-001",
                "challenge_b64": nonce_b64,
                "note": "stage-1 mock evidence",
            },
            "issued_at": now_secs(),
        }))?),
        // ARM CCA: AA returns raw CCA token → base64 + nonce
        TeeType::Cca | TeeType::CcaHydra => {
            Ok(serde_json::to_vec(&build_cca_part(nonce_b64, aa_endpoint)?)?)
        }
        // Hygon CSV: AA returns CSV attestation report → base64 + nonce
        TeeType::Csv | TeeType::CsvHydra => {
            Ok(serde_json::to_vec(&build_csv_part(nonce_b64, aa_endpoint)?)?)
        }
        // Intel TDX: AA returns raw TDX quote → base64 (collateral fetched by verifier)
        TeeType::Tdx | TeeType::TdxHydra => {
            Ok(serde_json::to_vec(&build_tdx_part(nonce_b64, aa_endpoint)?)?)
        }
        // iTrustee: AA returns JSON {report, ima_log} → append nonce
        TeeType::Itrustee | TeeType::ItrusteeHydra => {
            Ok(serde_json::to_vec(&build_itrustee_part(nonce_b64, aa_endpoint)?)?)
        }
        // VirtCCA: AA returns JSON {evidence, dev_cert, event_log} → append nonce
        TeeType::Virtcca | TeeType::VirtccaHydra => {
            Ok(serde_json::to_vec(&build_virtcca_part(nonce_b64, aa_endpoint)?)?)
        }
        TeeType::Unspecified => anyhow::bail!("tee_type unspecified"),
    }
}

/// Call guest-components api-server-rest: `GET /aa/evidence?runtime_data=<nonce>`.
/// The nonce is base64-url-encoded twice: first for the JSON nonce field, then standard
/// base64 for the query parameter. AA writes it into evidence's report_data/challenge field.
fn fetch_aa_evidence(nonce_b64: &str, aa_endpoint: &str) -> Result<Vec<u8>> {
    let nonce_raw = B64URL.decode(nonce_b64).context("decode challenge nonce")?;
    let runtime_data_b64 = B64.encode(&nonce_raw);
    let url = format!("{}/aa/evidence?runtime_data={}", aa_endpoint, runtime_data_b64);
    let response = ureq::get(&url).call().with_context(|| format!("GET {}", url))?;
    let mut buf = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut buf)
        .context("read AA evidence body")?;
    Ok(buf)
}

fn build_cca_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let cca_token = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "cca_token_b64": B64.encode(&cca_token),
        "nonce": nonce_b64,
    }))
}

fn build_csv_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let csv_evidence = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "csv_evidence_b64": B64.encode(&csv_evidence),
        "nonce": nonce_b64,
    }))
}

fn build_tdx_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let quote_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    Ok(json!({
        "quote_b64": B64.encode(&quote_bytes),
    }))
}

fn build_itrustee_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let evidence_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&evidence_bytes).context("parse itrustee AA evidence")?;
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("nonce".into(), nonce_b64.into());
    }
    Ok(evidence)
}

fn build_virtcca_part(nonce_b64: &str, aa_endpoint: &str) -> Result<serde_json::Value> {
    let evidence_bytes = fetch_aa_evidence(nonce_b64, aa_endpoint)?;
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&evidence_bytes).context("parse virtcca AA evidence")?;
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("nonce".into(), nonce_b64.into());
    }
    Ok(evidence)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
