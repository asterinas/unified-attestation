//! EAR (Entity Attestation Result) output.
//!
//! Produces a JWT-formatted EAR: custom claims + ES256 signature.

use crate::config::EarConfig;
use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// ES256 signing context loaded from a PEM-encoded EC private key.
pub struct SigningContext {
    encoding_key: EncodingKey,
}

impl SigningContext {
    pub fn new(cfg: &EarConfig) -> Result<Self> {
        let pem = std::fs::read(&cfg.signing_key_path)
            .with_context(|| format!("read signing key {}", cfg.signing_key_path.display()))?;
        let encoding_key =
            EncodingKey::from_ec_pem(&pem).context("parse signing key as EC PEM (ES256)")?;
        Ok(Self { encoding_key })
    }

    /// Sign an EarClaims struct into a JWT string.
    pub fn sign(&self, claims: EarClaims) -> Result<String> {
        let header = Header::new(Algorithm::ES256);
        encode(&header, &claims, &self.encoding_key).context("encode JWT")
    }
}

/// EAR top-level claims (JWT payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarClaims {
    /// Issuer identifier
    pub iss: String,
    /// Issued at (Unix seconds)
    pub iat: i64,
    /// Optional expiration time (Unix seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Nonce from the RP (base64url no-pad), used for replay protection
    pub eat_nonce: String,
    /// TEE type string (kebab-case)
    pub tee_type: String,
    /// Stable wasm component identifier
    pub component_id: String,
    /// Claims map returned by the wasm component (error field already stripped)
    pub submods: Value,
    /// Trust vector: instance_identity / configuration / executables
    pub trust_vector: TrustVector,
    /// Issuer metadata
    pub verifier_id: VerifierId,
    /// EAT profile identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eat_profile: Option<String>,
}

/// Verifier identity metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierId {
    pub developer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
}

/// AR4SI Trust Vector with three dimensions.
///
/// Values: 2 = Affirming (trusted), 1 = Warning, 0 = None (untrusted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVector {
    pub instance_identity: i32,
    pub configuration: i32,
    pub executables: i32,
}

impl TrustVector {
    pub fn new(instance_identity: i32, configuration: i32, executables: i32) -> Self {
        Self { instance_identity, configuration, executables }
    }

    /// Set all dimensions to affirming (=2).
    /// Used when no TEE-specific risk signal is available (mock, itrustee, itrustee-hydra, virtcca, virtcca-hydra).
    pub fn affirming() -> Self {
        Self { instance_identity: 2, configuration: 2, executables: 2 }
    }
}
