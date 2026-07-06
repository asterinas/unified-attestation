#[cfg(feature = "csv-verifier")]
pub mod csv;
#[cfg(feature = "itrustee-verifier")]
pub mod itrustee;
#[cfg(feature = "virtcca-verifier")]
pub mod virtcca;

#[cfg(feature = "virtcca-verifier")]
pub mod eventlog_rs;
#[cfg(feature = "ima-verifier")]
pub mod ima;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type TeeClaim = Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub uuid: Option<String>,
    pub challenge: Vec<u8>,
    pub ima: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TeeType {
    Itrustee,
    Virtcca,
    HygonCsvUser,
    HygonCsvKernel,
    Invalid,
}

impl<'de> Deserialize<'de> for TeeType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TeeTypeVisitor;

        impl<'de> serde::de::Visitor<'de> for TeeTypeVisitor {
            type Value = TeeType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a TEE type string or integer")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value.to_ascii_lowercase().as_str() {
                    "itrustee" => Ok(TeeType::Itrustee),
                    "virtcca" | "vcca" => Ok(TeeType::Virtcca),
                    "hygoncsvuser" | "hygon_csv_user" | "hygon-csv-user" => {
                        Ok(TeeType::HygonCsvUser)
                    }
                    "hygoncsvkernel" | "hygon_csv_kernel" | "hygon-csv-kernel" => {
                        Ok(TeeType::HygonCsvKernel)
                    }
                    "invalid" => Ok(TeeType::Invalid),
                    _ => Err(E::custom(format!("unsupported tee type: {value}"))),
                }
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    1 => Ok(TeeType::Itrustee),
                    2 => Ok(TeeType::Virtcca),
                    3 => Ok(TeeType::HygonCsvUser),
                    4 => Ok(TeeType::HygonCsvKernel),
                    _ => Ok(TeeType::Invalid),
                }
            }
        }

        deserializer.deserialize_any(TeeTypeVisitor)
    }
}

impl Serialize for TeeType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = match self {
            TeeType::Itrustee => "Itrustee",
            TeeType::Virtcca => "Virtcca",
            TeeType::HygonCsvUser => "HygonCsvUser",
            TeeType::HygonCsvKernel => "HygonCsvKernel",
            TeeType::Invalid => "Invalid",
        };
        serializer.serialize_str(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeeEvidenceFile {
    pub tee: TeeType,
    pub request: EvidenceRequest,
    pub evidence: Value,
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

pub fn verify_evidence_json(input: &[u8]) -> Result<TeeClaim> {
    let evidence_file: TeeEvidenceFile =
        serde_json::from_slice(input).context("failed to parse evidence.json")?;
    verify_evidence(evidence_file)
}

pub fn verify_evidence(evidence_file: TeeEvidenceFile) -> Result<TeeClaim> {
    let evidence = evidence_to_bytes(&evidence_file.evidence)?;
    let challenge = evidence_file.request.challenge;
    #[cfg(not(any(
        feature = "csv-verifier",
        feature = "itrustee-verifier",
        feature = "virtcca-verifier"
    )))]
    let _ = (&evidence, &challenge);

    match evidence_file.tee {
        #[cfg(feature = "csv-user-verifier")]
        TeeType::HygonCsvUser => {
            csv::HygonCsvVerifier::default().evaluate_user(&challenge, &evidence)
        }
        #[cfg(feature = "csv-kernel-verifier")]
        TeeType::HygonCsvKernel => {
            csv::HygonCsvVerifier::default().evaluate_kernel(&challenge, &evidence)
        }
        #[cfg(feature = "itrustee-verifier")]
        TeeType::Itrustee => itrustee::ItrusteeVerifier::default().evaluate(&challenge, &evidence),
        #[cfg(feature = "virtcca-verifier")]
        TeeType::Virtcca => virtcca::VirtCCAVerifier::default().evaluate(&challenge, &evidence),
        tee => bail!("unsupported or disabled tee type: {:?}", tee),
    }
}

fn evidence_to_bytes(evidence: &Value) -> Result<Vec<u8>> {
    match evidence {
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        _ => serde_json::to_vec(evidence).map_err(Into::into),
    }
}
