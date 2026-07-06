pub mod ima;

#[cfg(all(feature = "csv-user-attester", feature = "csv-kernel-attester"))]
compile_error!(
    "csv-user-attester and csv-kernel-attester are separate run modes; enable only one of them"
);

#[cfg(feature = "itrustee-attester")]
pub mod itrustee;

#[cfg(feature = "virtcca-attester")]
pub mod virtcca;

#[cfg(feature = "csv-user-attester")]
pub mod csv_user;

#[cfg(feature = "csv-kernel-attester")]
pub mod csv_kernel;

use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub uuid: Option<String>,
    pub challenge: Vec<u8>,
    pub ima: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TeeType {
    Itrustee = 1,
    Virtcca,
    HygonCsvUser,
    HygonCsvKernel,
    Invalid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub tee: TeeType,
    pub request: EvidenceRequest,
    pub evidence: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ItrusteeEvidence {
    pub report: String,
    pub ima_log: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtccaEvidence {
    pub evidence: Vec<u8>,
    pub dev_cert: Vec<u8>,
    pub ima_log: Option<Vec<u8>>,
    pub event_log: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HygonCsvEvidence {
    pub mode: String,
    pub report: String,
    pub nonce: String,
    pub ima_log: Option<Vec<u8>>,
}

#[derive(Default)]
pub struct Attester;

impl Attester {
    pub fn tee_get_evidence(&self, request: EvidenceRequest) -> Result<Vec<u8>> {
        let _ = &request;
        #[allow(unused_mut)]
        let mut errors: Vec<String> = Vec::new();

        #[cfg(feature = "csv-kernel-attester")]
        {
            match csv_kernel::HygonCsvKernelAttester::default().tee_get_evidence(request.clone()) {
                Ok(evidence) => {
                    return serde_json::to_vec(&Evidence {
                        tee: TeeType::HygonCsvKernel,
                        request: request.clone(),
                        evidence,
                    })
                    .map_err(Into::into);
                }
                Err(err) => errors.push(format!("hygon csv kernel failed: {err:#}")),
            }
        }

        #[cfg(feature = "csv-user-attester")]
        {
            match csv_user::HygonCsvUserAttester::default().tee_get_evidence(request.clone()) {
                Ok(evidence) => {
                    return serde_json::to_vec(&Evidence {
                        tee: TeeType::HygonCsvUser,
                        request: request.clone(),
                        evidence,
                    })
                    .map_err(Into::into);
                }
                Err(err) => errors.push(format!("hygon csv user failed: {err:#}")),
            }
        }

        #[cfg(feature = "itrustee-attester")]
        if itrustee::detect_platform() {
            match itrustee::ItrusteeAttester::default().tee_get_evidence(request.clone()) {
                Ok(evidence) => {
                    return serde_json::to_vec(&Evidence {
                        tee: TeeType::Itrustee,
                        request: request.clone(),
                        evidence,
                    })
                    .map_err(Into::into);
                }
                Err(err) => errors.push(format!("itrustee failed: {err:#}")),
            }
        }

        #[cfg(feature = "virtcca-attester")]
        if virtcca::detect_platform() {
            match virtcca::VirtccaAttester::default().tee_get_evidence(request.clone()) {
                Ok(evidence) => {
                    return serde_json::to_vec(&Evidence {
                        tee: TeeType::Virtcca,
                        request,
                        evidence,
                    })
                    .map_err(Into::into);
                }
                Err(err) => errors.push(format!("virtcca failed: {err:#}")),
            }
        }

        if !errors.is_empty() {
            bail!("TEE platform was detected but evidence generation failed: {errors:?}");
        }

        #[cfg(not(any(
            feature = "itrustee-attester",
            feature = "virtcca-attester",
            feature = "csv-user-attester",
            feature = "csv-kernel-attester"
        )))]
        bail!(
            "no attester backend was enabled; run with --features itrustee-attester, virtcca-attester, csv-user-attester, or csv-kernel-attester"
        );

        #[cfg(any(
            feature = "itrustee-attester",
            feature = "virtcca-attester",
            feature = "csv-user-attester",
            feature = "csv-kernel-attester"
        ))]
        bail!("unknown tee platform: no enabled attester backend detected this machine")
    }
}

pub const DEFAULT_UUID: &str = "f68fd704-6eb1-4d14-b218-722850eb3ef0";
pub const DEFAULT_CHALLENGE_LEN: usize = 64;
pub const CSV_CHALLENGE_LEN: usize = 16;

pub fn default_evidence_request() -> EvidenceRequest {
    #[cfg(any(feature = "csv-user-attester", feature = "csv-kernel-attester"))]
    {
        return EvidenceRequest {
            uuid: None,
            challenge: random_base64url_challenge_with_len(CSV_CHALLENGE_LEN).into_bytes(),
            ima: None,
        };
    }

    #[cfg(all(
        not(any(feature = "csv-user-attester", feature = "csv-kernel-attester")),
        feature = "itrustee-attester"
    ))]
    {
        return EvidenceRequest {
            uuid: Some(DEFAULT_UUID.to_string()),
            challenge: random_base64url_challenge_with_len(DEFAULT_CHALLENGE_LEN).into_bytes(),
            ima: None,
        };
    }

    #[cfg(all(
        not(any(
            feature = "csv-user-attester",
            feature = "csv-kernel-attester",
            feature = "itrustee-attester"
        )),
        feature = "virtcca-attester"
    ))]
    {
        return EvidenceRequest {
            uuid: None,
            challenge: random_base64url_challenge_with_len(DEFAULT_CHALLENGE_LEN).into_bytes(),
            ima: None,
        };
    }

    #[cfg(not(any(
        feature = "csv-user-attester",
        feature = "csv-kernel-attester",
        feature = "itrustee-attester",
        feature = "virtcca-attester"
    )))]
    {
        EvidenceRequest {
            uuid: None,
            challenge: random_base64url_challenge_with_len(DEFAULT_CHALLENGE_LEN).into_bytes(),
            ima: None,
        }
    }
}

pub fn itrustee_evidence_request() -> EvidenceRequest {
    EvidenceRequest {
        uuid: Some(DEFAULT_UUID.to_string()),
        challenge: random_base64url_challenge_with_len(DEFAULT_CHALLENGE_LEN).into_bytes(),
        ima: None,
    }
}

pub fn virtcca_evidence_request() -> EvidenceRequest {
    EvidenceRequest {
        uuid: None,
        challenge: random_base64url_challenge_with_len(DEFAULT_CHALLENGE_LEN).into_bytes(),
        ima: None,
    }
}

pub fn csv_evidence_request() -> EvidenceRequest {
    EvidenceRequest {
        uuid: None,
        challenge: random_base64url_challenge_with_len(CSV_CHALLENGE_LEN).into_bytes(),
        ima: None,
    }
}

pub fn random_base64url_challenge() -> String {
    random_base64url_challenge_with_len(DEFAULT_CHALLENGE_LEN)
}

pub fn random_base64url_challenge_with_len(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[allow(dead_code)]
pub(crate) fn ensure_challenge_len(challenge: &[u8], max_len: usize) -> Result<()> {
    if challenge.is_empty() || challenge.len() > max_len {
        bail!(
            "challenge length is wrong, expecting 0 < len <= {}, got {}",
            max_len,
            challenge.len()
        );
    }
    Ok(())
}
