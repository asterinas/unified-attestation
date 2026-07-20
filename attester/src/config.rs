//! Attester configuration (TOML).

use anyhow::{Context, Result};
use protos::TeeType;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// attester gRPC listen address, e.g. `127.0.0.1:9000`
    pub listen: String,
    /// TEE type of this attester instance (custom deserializer: kebab string → proto enum)
    #[serde(deserialize_with = "deser_tee_type")]
    pub tee_type: TeeType,
    /// Path to the local wasm component binary
    pub wasm_component_path: PathBuf,
    /// guest-components api-server-rest address for evidence collection.
    #[serde(default = "default_aa_endpoint")]
    pub aa_endpoint: String,
    /// Verifier gRPC endpoint. Required for passport mode.
    #[serde(default)]
    pub verifier_endpoint: Option<String>,
    /// Hydra TCP client config. Absent → no hydra client task spawned.
    #[serde(default)]
    pub hydra: Option<HydraClientConfig>,
}

/// Hydra TCP client config: connect to the verifier's hydra daemon, receive PublicContext,
/// optionally ship an EvidenceReply to relying-party endpoints.
/// Hydra TCP client config loaded from `[hydra]` section of attester.toml.
/// Absent → no hydra client task is spawned (non-hydra paths).
#[derive(Debug, Clone, Deserialize)]
pub struct HydraClientConfig {
    /// Verifier hydra TCP address, e.g. `127.0.0.1:7001`.
    pub verifier_addr: String,
    /// Relying-party TCP endpoints to ship the EvidenceReply to on session bootstrap.
    #[serde(default)]
    pub relying_party_addrs: Vec<String>,
    /// Attester data directory (attester_key.bin + session dirs land here).
    #[serde(default = "default_hydra_data_dir")]
    pub data_dir: PathBuf,
}

fn default_hydra_data_dir() -> PathBuf {
    PathBuf::from("workspace-data/attester")
}

/// Parse a kebab-case tee_type string to the proto enum.
pub fn parse_tee_type(s: &str) -> Result<TeeType> {
    match s {
        "mock" => Ok(TeeType::Mock),
        "cca" => Ok(TeeType::Cca),
        "cca-hydra" => Ok(TeeType::CcaHydra),
        "csv" => Ok(TeeType::Csv),
        "csv-hydra" => Ok(TeeType::CsvHydra),
        "tdx" => Ok(TeeType::Tdx),
        "tdx-hydra" => Ok(TeeType::TdxHydra),
        "itrustee" => Ok(TeeType::Itrustee),
        "itrustee-hydra" => Ok(TeeType::ItrusteeHydra),
        "virtcca" => Ok(TeeType::Virtcca),
        "virtcca-hydra" => Ok(TeeType::VirtccaHydra),
        other => anyhow::bail!("unknown tee_type '{other}'"),
    }
}

fn deser_tee_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<TeeType, D::Error> {
    let s = String::deserialize(d)?;
    parse_tee_type(&s).map_err(serde::de::Error::custom)
}

fn default_aa_endpoint() -> String {
    "http://127.0.0.1:8006".to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parse toml {}", path.display()))
    }
}
