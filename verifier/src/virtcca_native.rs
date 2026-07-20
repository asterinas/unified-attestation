//! VirtCCA host-side evidence verification (reserved).
//!
//! Full verification requires OpenSSL + cose + ciborium (CBOR/COSE decode + HW cert chain).
//! Reference implementation: hydra/evidence-verify/src/virtcca/mod.rs.
//! When libvccaattestation.so + OpenSSL are available in the deployment environment:
//!   1. CBOR Tag 399 decode → CvmToken + PlatformToken
//!   2. Device certificate chain verification (Huawei Root CA → Sub CA → dev_cert)
//!   3. CvmToken COSE-Sign1 verification + challenge binding
//!   4. Reference value comparison (RIM)
//!
//! Currently no cryptographic verification; the wasm appraiser handles nonce binding
//! and field passthrough.

use anyhow::Result;
use serde_json::Value;

/// Metadata extracted from VirtCCA evidence.
#[derive(Debug, Default)]
pub struct VirtccaVerificationResult {
    pub token_size: usize,
    pub cert_size: usize,
    pub ima_log_size: Option<usize>,
    pub event_log_size: Option<usize>,
}

/// Parse evidence JSON and extract binary field sizes.
///
/// Evidence fields:
/// - `evidence`: CBOR/COSE token as JSON byte array
/// - `dev_cert`: DER device certificate as JSON byte array
/// - `ima_log`: optional IMA log as JSON byte array
/// - `event_log`: optional event log (CCEL ACPI table) as JSON byte array
pub fn extract_claims(evidence: &[u8]) -> Result<VirtccaVerificationResult> {
    let ev: Value = serde_json::from_slice(evidence)?;
    Ok(VirtccaVerificationResult {
        token_size: ev.get("evidence").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        cert_size: ev.get("dev_cert").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        ima_log_size: ev.get("ima_log").and_then(|v| v.as_array()).map(|a| a.len()),
        event_log_size: ev.get("event_log").and_then(|v| v.as_array()).map(|a| a.len()),
    })
}
