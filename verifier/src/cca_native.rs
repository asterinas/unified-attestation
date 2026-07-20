//! Host-side CCA token verification (ref: trustee deps/verifier/src/cca/local.rs).
//!
//! Consistent with trustmee-artifact: CCA verification stays on the host, the wasm appraiser
//! only does field parsing and nonce comparison. Uses the ccatoken crate for: CBOR decode +
//! COSE-Sign1 verification + IAK/RAK chain + RV appraisal.
//!
//! Flow:
//! 1. Evidence::from_reader → CBOR + COSE-Sign1 decode
//! 2. e.verify(&ta_store) → IAK/RAK certificate chain verification
//! 3. e.appraise(&rv_store) → platform/realm measurement comparison
//! 4. Extract realm claims (RIM, perso) + platform claims (instance_id, lifecycle, sw_components)
//!
//! When either ta_store or rv_store is missing: CcaVerifier::load returns None,
//! host verification is skipped (demo only).

use anyhow::{Context, Result, anyhow, bail};
use ccatoken::store::{MemoRefValueStore, MemoTrustAnchorStore};
use ccatoken::token::Evidence;
use ear::TrustTier;
use serde_json::Value;
use std::io::Cursor;
use tracing::warn;

use crate::config::CcaPolicy;

/// CCA verification result with measurements extracted from the token.
pub struct CcaVerificationResult {
    /// Realm Initial Measurement (hex)
    pub realm_initial_measurement: Option<String>,
    /// Realm Personalization Value (hex)
    pub realm_personalization_value: Option<String>,
    /// CCA Platform Instance ID (hex)
    pub cca_platform_instance_id: Option<String>,
    /// CCA Platform Implementation ID (hex)
    pub cca_platform_implementation_id: Option<String>,
    /// Platform lifecycle state ("secured" etc.)
    pub cca_platform_lifecycle: Option<String>,
    /// Platform software components
    pub cca_platform_sw_components: Option<Vec<Value>>,
}

pub struct CcaVerifier {
    tas: MemoTrustAnchorStore,
    rvs: MemoRefValueStore,
}

impl CcaVerifier {
    /// Load trust anchor and reference value stores from filesystem.
    /// Returns None if either path is not configured (demo mode).
    pub fn load(policy: &CcaPolicy) -> Result<Option<Self>> {
        let (Some(ta), Some(rv)) = (policy.ta_store.as_ref(), policy.rv_store.as_ref()) else {
            return Ok(None);
        };
        let jta = std::fs::read_to_string(ta)
            .with_context(|| format!("read CCA TA store {}", ta.display()))?;
        let jrv = std::fs::read_to_string(rv)
            .with_context(|| format!("read CCA RV store {}", rv.display()))?;

        let mut tas = MemoTrustAnchorStore::default();
        tas.load_json(&jta)
            .map_err(|e| anyhow!("load CCA TA store: {e}"))?;
        let mut rvs = MemoRefValueStore::default();
        rvs.load_json(&jrv)
            .map_err(|e| anyhow!("load CCA RV store: {e}"))?;
        Ok(Some(Self { tas, rvs }))
    }

    /// Verify a CCA token: signature chain + RAK attestation + RV comparison + nonce binding.
    /// Returns structured verification result with key measurements from realm and platform claims.
    pub fn verify(&self, token: &[u8], expected_report_data: &[u8]) -> Result<CcaVerificationResult> {
        // Decode CBOR + COSE-Sign1 envelope
        let cursor = Cursor::new(token.to_vec());
        let mut e = Evidence::decode(cursor).map_err(|err| anyhow!("decode CCA token: {err}"))?;

        // Step 1: Verify IAK → RAK certificate chain
        e.verify(&self.tas)
            .map_err(|err| anyhow!("verify CCA evidence: {err}"))?;
        // Step 2: Appraise platform and realm measurements against reference values
        e.appraise(&self.rvs)
            .map_err(|err| anyhow!("appraise CCA evidence: {err}"))?;

        // Step 3: Check realm trust tier — must be Affirming
        let (_platform_tvec, realm_tvec) = e.get_trust_vectors();
        let passed = realm_tvec.instance_identity.tier() == TrustTier::Affirming;
        if !passed {
            bail!("CCA RAK signature or RAK attestation could not be verified");
        }
        // Step 4: Nonce binding — realm challenge must match the RP's nonce (padded to 64 bytes)
        if expected_report_data != e.realm_claims.challenge {
            bail!("CCA realm token challenge does not match expected_report_data");
        }

        // Extract realm claims
        let rim_hex = (!e.realm_claims.rim.is_empty())
            .then(|| hex::encode(&e.realm_claims.rim));
        let pv_hex = (!e.realm_claims.perso.is_empty())
            .then(|| hex::encode(&e.realm_claims.perso));

        // Extract platform claims: instance ID, implementation ID, lifecycle, SW components
        let (plat_instance_id, plat_impl_id, plat_lifecycle, plat_sw_components) = {
            let pt = &e.platform_claims;
            // inst_id is [u8;33], impl_id is [u8;32] — hex-encode for JSON transport
            let iid = Some(hex::encode(&pt.inst_id[..]));
            let impid = Some(hex::encode(&pt.impl_id[..]));
            // Map u16 lifecycle code to human-readable string
            let lc = match pt.lifecycle {
                0x6000 | 0x6001 => Some("secured".to_string()),
                0x3000 | 0x3001 => Some("recoverable".to_string()),
                0x0000..=0x00ff => Some("not_secured".to_string()),
                _ => Some(format!("0x{:04x}", pt.lifecycle)),
            };
            let sw: Option<Vec<Value>> = if pt.sw_components.is_empty() {
                None
            } else {
                Some(
                    pt.sw_components
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                                "measurement": hex::encode(&c.mval),
                                "signer_id": hex::encode(&c.signer_id),
                                "measurement_type": c.mtyp,
                                "version": c.version,
                            })
                        })
                        .collect(),
                )
            };
            (iid, impid, lc, sw)
        };

        Ok(CcaVerificationResult {
            realm_initial_measurement: rim_hex,
            realm_personalization_value: pv_hex,
            cca_platform_instance_id: plat_instance_id,
            cca_platform_implementation_id: plat_impl_id,
            cca_platform_lifecycle: plat_lifecycle,
            cca_platform_sw_components: plat_sw_components,
        })
    }
}

/// Fallback when trust anchor stores are not configured: skip verification, log a warning.
/// Acceptable for demo / development only; production MUST configure ta-store / rv-store.
pub fn warn_no_store(policy: &CcaPolicy) {
    if policy.ta_store.is_none() || policy.rv_store.is_none() {
        warn!(
            "CCA policy.ta_store / policy.rv_store not configured; \
             host-side CCA token verification skipped. DO NOT USE IN PRODUCTION."
        );
    }
}
