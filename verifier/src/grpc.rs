//! tonic gRPC implementation: VerifierService.Verify.
//!
//! Verify request processing has 6 steps:
//! 1. Parse / register wasm component (sha256 whitelist validation)
//! 2. Host-side evidence processing (CCA/CSV chain verification, TDX collateral fetch,
//!    iTrustee/VirtCCA field extraction)
//! 3. wasm appraiser sandbox invocation (nonce binding + claims output)
//! 4. Policy matching (trusted roots / RIM / mr_td / tcb_status whitelists)
//! 5. EAR JWT issuance (ES256 signed, including dynamic trust_vector assignment)
//! 6. Hydra-stacking paths delegate the ZK layer verification to a separate TCP daemon;
//!    the wasm here only vouches for TEE evidence, not for the Groth16 proof or roots.

use crate::cca_native::CcaVerifier;
use crate::config::{CcaPolicy, TdxPolicy};
use crate::csv_native::CsvVerifier;
use crate::ear::{EarClaims, SigningContext, TrustVector, VerifierId};
use crate::wasm_host::WasmHost;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use protos::verifier_service_server::VerifierService;
use protos::verify_request::Wasm;
use protos::{TeeType, VerifyRequest, VerifyResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

/// Global state shared across all gRPC handler invocations via `Arc`.
/// The wasm host and signing context are immutable after construction;
/// the optional host-side verifiers are loaded once at startup based on config.
pub struct AppState {
    pub host: Arc<WasmHost>,
    pub signing: SigningContext,
    pub cca_policy: CcaPolicy,
    pub tdx_policy: TdxPolicy,
    pub cca_verifier: Option<CcaVerifier>,
    pub csv_verifier: Option<CsvVerifier>,
}

#[tonic::async_trait]
impl VerifierService for AppState {
    async fn verify(
        &self,
        req: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let req = req.into_inner();

        // Validate tee_type and nonce before any processing
        let tee = TeeType::try_from(req.tee_type)
            .map_err(|_| Status::invalid_argument("invalid tee_type"))?;
        if matches!(tee, TeeType::Unspecified) {
            return Err(Status::invalid_argument("tee_type unspecified"));
        }
        if req.nonce.is_empty() {
            return Err(Status::invalid_argument("nonce required"));
        }

        // —— Step 1: parse / load wasm component ——
        // First submission with wasm bytes → register (sha256 whitelist check).
        // Subsequent reuse with stable component_id → skip registration.
        let component_id = match req.wasm {
            Some(Wasm::WasmComponent(bytes)) => self
                .host
                .register(&bytes)
                .await
                .map_err(|e| Status::invalid_argument(format!("component rejected: {e}")))?,
            Some(Wasm::WasmComponentId(id)) => id,
            None => return Err(Status::invalid_argument("wasm required")),
        };

        // —— Step 2: host-side evidence processing + measurement injection ——
        // CCA / CSV: full chain verification + measurement injection into evidence JSON.
        //   No verifier configured (missing ta_store, csv disabled) → skip, wasm only.
        // iTrustee / VirtCCA: parse evidence and inject extracted fields.
        //   Full verification requires .so / OpenSSL — deploy when available.
        // TDX: host fetches collateral by fmspc and injects into evidence JSON.
        //
        // Mutex stores CCA lifecycle across the if-let scope for use in step 5 trust_vector.
        let cca_platform_lifecycle: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
        let evidence_for_wasm = if matches!(tee, TeeType::Cca | TeeType::CcaHydra) {
            // CCA: decode evidence JSON, run host verification if verifier configured
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            if let Some(verifier) = &self.cca_verifier {
                // Extract and decode the base64-encoded CCA token from evidence
                let cca_token = extract_b64_field(&req.evidence, "cca_token_b64")
                    .map_err(|e| Status::invalid_argument(format!("extract cca token: {e}")))?;
                // CCA challenge must be 64 bytes (zero-padded nonce)
                let mut padded = req.nonce.clone();
                padded.resize(64, 0);
                let result = verifier.verify(&cca_token, &padded).map_err(|e| {
                    warn!(error = %e, "cca host verify failed");
                    Status::invalid_argument(format!("cca verify failed: {e}"))
                })?;
                info!("cca host verify passed");
                let obj = ev.as_object_mut()
                    .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                // Inject extracted CCA measurements so wasm appraiser can passthrough
                inject_cca_claims(obj, &result);
                *cca_platform_lifecycle.lock().unwrap() = result.cca_platform_lifecycle.clone();
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Csv | TeeType::CsvHydra) {
            // CSV: decode evidence JSON, run host verification if csv_verifier configured
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            if let Some(verifier) = &self.csv_verifier {
                // Extract the base64-encoded CSV evidence blob
                let csv_evidence = extract_b64_field(&req.evidence, "csv_evidence_b64")
                    .map_err(|e| Status::invalid_argument(format!("extract csv evidence: {e}")))?;
                let result = verifier
                    .verify(&csv_evidence, &req.nonce)
                    .map_err(|e| Status::invalid_argument(format!("csv verify failed: {e}")))?;
                let obj = ev.as_object_mut()
                    .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                inject_csv_claims(obj, &result);
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Itrustee | TeeType::ItrusteeHydra) {
            // iTrustee / iTrustee-hydra: parse report JSON to extract TA measurements, inject for wasm passthrough
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            match crate::itrustee_native::extract_claims(&req.evidence) {
                Ok(result) => {
                    let obj = ev.as_object_mut()
                        .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                    inject_itrustee_claims(obj, &result);
                }
                // If report parsing fails, proceed with raw evidence (wasm still does nonce binding)
                Err(e) => warn!(error = %e, "itrustee claim extraction failed, proceeding with raw evidence"),
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Virtcca | TeeType::VirtccaHydra) {
            // VirtCCA / VirtCCA-hydra: extract binary field sizes, inject for wasm passthrough
            let mut ev: serde_json::Value = serde_json::from_slice(&req.evidence)
                .map_err(|e| Status::invalid_argument(format!("evidence json: {e}")))?;
            match crate::virtcca_native::extract_claims(&req.evidence) {
                Ok(result) => {
                    let obj = ev.as_object_mut()
                        .ok_or_else(|| Status::invalid_argument("evidence root must be object"))?;
                    inject_virtcca_claims(obj, &result);
                }
                Err(e) => warn!(error = %e, "virtcca claim extraction failed, proceeding with raw evidence"),
            }
            serde_json::to_vec(&ev)
                .map_err(|e| Status::internal(format!("serialize evidence: {e}")))?
        } else if matches!(tee, TeeType::Tdx | TeeType::TdxHydra) {
            // TDX: fetch collateral from PCCS by fmspc, inject into evidence for wasm dcap-qvl
            inject_tdx_collateral(&req.evidence, &self.tdx_policy.pccs_url)
                .await
                .map_err(|e| {
                    warn!(error = %e, "fetch tdx collateral failed");
                    Status::internal(format!("fetch collateral: {e}"))
                })?
        } else {
            // Mock: no host-side processing, pass evidence through as-is
            req.evidence.clone()
        };

        let cca_lifecycle = cca_platform_lifecycle.lock().unwrap().clone();

        // —— Step 3: wasm appraiser evaluation ——
        // For TDX, pass the first trusted_mr_config_id_hex entry as expected_init_data_hash.
        // The wasm appraiser does 1:1 strict equality on init_data_hash; multi-value candidates
        // are meaningless here. Remaining entries are OR-matched in enforce_tdx_policy below.
        let expected_init = matches!(tee, TeeType::Tdx | TeeType::TdxHydra)
            .then(|| self.tdx_policy.trusted_mr_config_id_hex.first())
            .flatten()
            .and_then(|s| hex::decode(s).ok());
        let outcome = self
            .host
            .evaluate(
                &component_id,
                &evidence_for_wasm,
                Some(&req.nonce),
                expected_init.as_deref(),
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "wasm evaluate failed");
                Status::invalid_argument(format!("evidence rejected: {e}"))
            })?;

        // —— Step 4: policy enforcement ——
        // Cross-check: wasm must report the same tee_type as the request
        let tee_kind_str = tee_type_str(tee);
        let claim_tee = outcome
            .claims
            .get("tee_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if claim_tee != tee_kind_str {
            return Err(Status::invalid_argument(format!(
                "tee_type mismatch: request={tee_kind_str}, claim={claim_tee}"
            )));
        }

        match tee {
            // Mock / CSV / iTrustee / VirtCCA / *-hydra: policy already handled in host step,
            // or wasm appraiser self-enforces. *-hydra host-side zk verification is done by the
            // separate hydra TCP daemon; the wasm here only vouches for TEE evidence.
            TeeType::Unspecified
            | TeeType::Mock
            | TeeType::Csv
            | TeeType::Itrustee
            | TeeType::Virtcca
            | TeeType::ItrusteeHydra
            | TeeType::VirtccaHydra
            | TeeType::CsvHydra => {}
            TeeType::Cca | TeeType::CcaHydra => {
                enforce_cca_policy(&self.cca_policy, &outcome.claims).map_err(|e| {
                    warn!(error = %e, "cca policy mismatch");
                    Status::invalid_argument(e)
                })?;
            }
            TeeType::Tdx | TeeType::TdxHydra => {
                enforce_tdx_policy(&self.tdx_policy, &outcome.claims)
                    .map_err(|e| Status::invalid_argument(format!("tdx: {e}")))?;
            }
        }

        // —— Step 5: sign EAR JWT ——
        // eat_nonce uses base64url no-pad encoding of the RP nonce, enabling text comparison at the RP.
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&req.nonce);
        let nonce_bound = outcome.claims.get("nonce_bound").and_then(|v| v.as_bool()).unwrap_or(false);
        let tcb_status = outcome.claims.get("tcb_status").and_then(|v| v.as_str());
        // Dynamic trust_vector: each TEE type has its own assignment rules
        let trust_vector = trust_vector_for(tee, nonce_bound, &cca_lifecycle, tcb_status);
        let claims = EarClaims {
            iss: "unified-attestation-verifier".to_string(),
            iat: now_secs(),
            exp: Some(now_secs() + 3600), // 1 hour expiry
            eat_nonce: nonce_b64,
            tee_type: tee_kind_str.to_string(),
            component_id: outcome.component_id.clone(),
            submods: outcome.claims.clone(),
            trust_vector,
            verifier_id: VerifierId {
                developer: "unified-attestation".to_string(),
                build: None,
            },
            eat_profile: Some("tag:github.com,2024:unified-attestation".to_string()),
        };
        let ear = self
            .signing
            .sign(claims)
            .map_err(|e| Status::internal(e.to_string()))?;

        // —— Step 6: hydra ZK verification is handled by the separate hydra TCP daemon ——

        Ok(Response::new(VerifyResponse {
            ear,
            wasm_component_id: outcome.component_id,
        }))
    }
}

/// Map TeeType proto enum to kebab-case string used in config and EAR claims.
fn tee_type_str(t: TeeType) -> &'static str {
    match t {
        TeeType::Unspecified => "unspecified",
        TeeType::Mock => "mock",
        TeeType::Cca => "cca",
        TeeType::CcaHydra => "cca-hydra",
        TeeType::Csv => "csv",
        TeeType::CsvHydra => "csv-hydra",
        TeeType::Tdx => "tdx",
        TeeType::TdxHydra => "tdx-hydra",
        TeeType::Itrustee => "itrustee",
        TeeType::ItrusteeHydra => "itrustee-hydra",
        TeeType::Virtcca => "virtcca",
        TeeType::VirtccaHydra => "virtcca-hydra",
    }
}

/// Current Unix timestamp in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Extract and base64-decode a named string field from a JSON evidence byte slice.
fn extract_b64_field(evidence: &[u8], key: &str) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(evidence).map_err(|e| format!("evidence json: {e}"))?;
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("evidence.{key} missing"))?;
    B64.decode(s).map_err(|e| format!("{key} base64: {e}"))
}

/// Fetch TDX collateral from PCS/PCCS by fmspc and write it back into evidence JSON.
///
/// The wasm appraiser is unaware of the fetch process; the evidence it receives has the
/// same shape as if the attester had fetched it. Injected fields: `collateral_b64`
/// (QuoteCollateralV3 serialized then base64-encoded), `now_secs` (Unix seconds for dcap-qvl).
async fn inject_tdx_collateral(evidence: &[u8], pccs_url: &str) -> Result<Vec<u8>, String> {
    let mut v: serde_json::Value =
        serde_json::from_slice(evidence).map_err(|e| format!("evidence json: {e}"))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "evidence root must be object".to_string())?;

    // Extract and decode quote bytes from evidence
    let quote_b64 = obj
        .get("quote_b64")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "evidence.quote_b64 missing".to_string())?;
    let quote_bytes = B64
        .decode(quote_b64)
        .map_err(|e| format!("quote_b64 base64: {e}"))?;

    // Fetch collateral from PCCS using dcap-qvl, then inject as base64
    let collateral = dcap_qvl::collateral::get_collateral(pccs_url, &quote_bytes)
        .await
        .map_err(|e| format!("get_collateral: {e}"))?;
    let collateral_bin =
        serde_json::to_vec(&collateral).map_err(|e| format!("serialize collateral: {e}"))?;

    obj.insert(
        "collateral_b64".to_string(),
        serde_json::Value::String(B64.encode(&collateral_bin)),
    );
    obj.insert(
        "now_secs".to_string(),
        serde_json::Value::Number(serde_json::Number::from(now_secs())),
    );
    serde_json::to_vec(&v).map_err(|e| format!("serialize evidence: {e}"))
}

/// Enforce CCA policy: RIM whitelist + subject whitelist.
fn enforce_cca_policy(policy: &CcaPolicy, claims: &serde_json::Value) -> Result<(), String> {
    // RIM (Realm Initial Measurement) comparison
    if !policy.trusted_rim_hex.is_empty() {
        let rim = claims
            .get("cca_realm_initial_measurement")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "claims.cca_realm_initial_measurement missing".to_string())?;
        // Case-insensitive hex comparison
        if !policy.trusted_rim_hex.iter().any(|s| s.eq_ignore_ascii_case(rim)) {
            return Err(format!("rim '{}' not in trusted list", rim));
        }
    }
    // Subject comparison (device instance whitelist for cca-hydra)
    if !policy.trusted_subjects.is_empty() {
        let subject = claims
            .get("subject")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "claims.subject missing".to_string())?;
        if !policy.trusted_subjects.iter().any(|s| s == subject) {
            return Err(format!("subject '{}' not in trusted list", subject));
        }
    }
    if policy.trusted_subjects.is_empty() && policy.trusted_rim_hex.is_empty() {
        warn!("cca policy.trusted_subjects and trusted_rim_hex both empty; skipping CCA binding");
    }
    Ok(())
}

/// Inject CCA verification results into evidence JSON for wasm appraiser passthrough.
fn inject_cca_claims(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    result: &crate::cca_native::CcaVerificationResult,
) {
    if let Some(ref v) = result.realm_initial_measurement {
        obj.insert("cca_realm_initial_measurement".into(), v.clone().into());
    }
    if let Some(ref v) = result.realm_personalization_value {
        obj.insert("cca_realm_personalization_value".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_instance_id {
        obj.insert("cca_platform_instance_id".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_implementation_id {
        obj.insert("cca_platform_implementation_id".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_lifecycle {
        obj.insert("cca_platform_lifecycle".into(), v.clone().into());
    }
    if let Some(ref v) = result.cca_platform_sw_components {
        obj.insert("cca_platform_sw_components".into(), serde_json::to_value(v).unwrap_or_default());
    }
}

/// Inject CSV verification results into evidence JSON for wasm appraiser passthrough.
fn inject_csv_claims(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    result: &crate::csv_native::CsvVerificationResult,
) {
    if let Some(ref v) = result.chip_id {
        obj.insert("chip_id".into(), v.clone().into());
    }
    if let Some(ref v) = result.measurement {
        obj.insert("measurement".into(), v.clone().into());
    }
    if let Some(ref v) = result.vm_version {
        obj.insert("vm_version".into(), v.clone().into());
    }
    if let Some(v) = result.policy_nodbg {
        obj.insert("policy_nodbg".into(), v.into());
    }
    if let Some(v) = result.policy_noks {
        obj.insert("policy_noks".into(), v.into());
    }
}

/// Generate a dynamic Trust Vector per verification result.
///
/// Assignment rules by TEE type:
/// - TDX: executables follows tcb_status (UpToDate=2, SWHardeningNeeded=1, OutOfDate/Revoked=0)
/// - CCA: instance_identity follows nonce_bound, configuration follows lifecycle
/// - CSV: instance_identity follows nonce_bound
/// - Others (mock, Itrustee, ItrusteeHydra, Virtcca, VirtccaHydra): all affirming (2,2,2)
fn trust_vector_for(
    tee: TeeType,
    nonce_bound: bool,
    cca_lifecycle: &Option<String>,
    tcb_status: Option<&str>,
) -> TrustVector {
    match tee {
        TeeType::Tdx | TeeType::TdxHydra => {
            let executables = match tcb_status {
                Some("UpToDate") => 2,
                Some("SWHardeningNeeded") | Some("ConfigurationAndSWHardeningNeeded") => 1,
                Some("OutOfDate") | Some("Revoked") => 0,
                _ => 1, // unknown status → warning
            };
            TrustVector::new(2, 2, executables)
        }
        TeeType::Cca | TeeType::CcaHydra => {
            let instance_identity = if nonce_bound { 2 } else { 0 };
            let configuration = match cca_lifecycle.as_deref() {
                Some("secured") | Some("secured_no_debug") => 2,
                Some("not_secured") | Some("recoverable") => 1,
                _ => 0, // unknown lifecycle → none
            };
            TrustVector::new(instance_identity, configuration, 2)
        }
        TeeType::Csv | TeeType::CsvHydra => {
            let instance_identity = if nonce_bound { 2 } else { 0 };
            TrustVector::new(instance_identity, 2, 2)
        }
        _ => TrustVector::affirming(),
    }
}

/// Inject iTrustee verification results into evidence JSON for wasm appraiser passthrough.
fn inject_itrustee_claims(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    result: &crate::itrustee_native::ItrusteeVerificationResult,
) {
    if let Some(ref v) = result.uuid {
        obj.insert("itrustee_uuid".into(), v.clone().into());
    }
    if let Some(ref v) = result.ta_img {
        obj.insert("itrustee_ta_img".into(), v.clone().into());
    }
    if let Some(ref v) = result.ta_mem {
        obj.insert("itrustee_ta_mem".into(), v.clone().into());
    }
    if let Some(ref v) = result.hash_alg {
        obj.insert("itrustee_hash_alg".into(), v.clone().into());
    }
    if let Some(ref v) = result.version {
        obj.insert("itrustee_version".into(), v.clone().into());
    }
}

/// Inject VirtCCA verification results into evidence JSON for wasm appraiser passthrough.
fn inject_virtcca_claims(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    result: &crate::virtcca_native::VirtccaVerificationResult,
) {
    obj.insert("virtcca_token_size".into(), result.token_size.into());
    obj.insert("virtcca_cert_size".into(), result.cert_size.into());
    if let Some(sz) = result.ima_log_size {
        obj.insert("virtcca_ima_log_size".into(), sz.into());
    }
    if let Some(sz) = result.event_log_size {
        obj.insert("virtcca_event_log_size".into(), sz.into());
    }
}

/// Enforce TDX measurement whitelist policies.
///
/// Each trusted_*_hex list is independently checked: empty list → skip that field.
/// `accept_tcb_status` controls acceptable TCB security levels.
fn enforce_tdx_policy(policy: &TdxPolicy, claims: &serde_json::Value) -> Result<(), String> {
    /// Single-field hex whitelist check: empty list → skip, otherwise must match.
    fn match_hex(claim: Option<&str>, list: &[String], field: &str) -> Result<(), String> {
        if list.is_empty() {
            return Ok(());
        }
        let v = claim.ok_or_else(|| format!("claims.{field} missing"))?;
        if !list.iter().any(|s| s.eq_ignore_ascii_case(v)) {
            return Err(format!("{field} '{v}' not in trusted list"));
        }
        Ok(())
    }

    match_hex(
        claims.get("mr_td").and_then(|v| v.as_str()),
        &policy.trusted_mr_td_hex,
        "mr_td",
    )?;
    match_hex(
        claims.get("mr_seam").and_then(|v| v.as_str()),
        &policy.trusted_mr_seam_hex,
        "mr_seam",
    )?;
    match_hex(
        claims.get("mr_config_id").and_then(|v| v.as_str()),
        &policy.trusted_mr_config_id_hex,
        "mr_config_id",
    )?;
    // TCB status check: must be in the accept list if list is non-empty
    if !policy.accept_tcb_status.is_empty() {
        let s = claims
            .get("tcb_status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "claims.tcb_status missing".to_string())?;
        if !policy.accept_tcb_status.iter().any(|x| x == s) {
            return Err(format!("tcb_status '{s}' not accepted"));
        }
    }
    Ok(())
}
