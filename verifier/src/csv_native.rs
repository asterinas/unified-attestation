//! Host-side Hygon CSV evidence verification (ref: anolis-trustee deps/verifier/src/csv/mod.rs).
//!
//! csv-rs uses OpenSSL for P-384 ECDSA + chain verification, cannot cross-compile to
//! wasm32-wasip1. Same position as ccatoken: host-side verification, wasm appraiser only
//! does field passthrough and nonce comparison.
//!
//! Certificate chain: HRK(self-signed) → HSK → CEK → PEK → TEE attestation report.
//! HRK is embedded (`verifier/assets/hygon_hrk.cert`). HSK/CEK are either bundled with
//! the evidence or fetched online by chip_id.

use crate::config::CsvPolicy;
use anyhow::{Context, Result, anyhow, bail};
use codicon::Decoder;
use csv_rs::api::guest::{AttestationReport, AttestationReportWrapper};
use csv_rs::certs::{Verifiable, ca, csv};
use serde::Deserialize;
use std::io::Cursor;
use tracing::info;

/// Embedded Hygon Root Key certificate (self-signed, distributed with the verifier binary).
const HRK: &[u8] = include_bytes!("../assets/hygon_hrk.cert");

#[derive(Deserialize)]
struct HskCek {
    hsk: ca::Certificate,
    cek: csv::Certificate,
}

#[derive(Deserialize)]
struct CertificateChain {
    #[serde(default)]
    hsk_cek: Option<HskCek>,
    pek: csv::Certificate,
}

#[derive(Deserialize)]
struct CsvEvidenceJson {
    attestation_report: AttestationReportWrapper,
    cert_chain: CertificateChain,
    serial_number: Vec<u8>,
}

/// CSV verification result with measurements extracted from the attestation report.
pub struct CsvVerificationResult {
    /// Chip ID (serial_number with trailing null bytes trimmed)
    pub chip_id: Option<String>,
    /// Measurement value (hex)
    pub measurement: Option<String>,
    /// VM firmware version (hex)
    pub vm_version: Option<String>,
    /// Policy: debug disabled (0=false, 1=true)
    pub policy_nodbg: Option<u32>,
    /// Policy: key sharing disabled (0=false, 1=true)
    pub policy_noks: Option<u32>,
}

pub struct CsvVerifier {
    policy: CsvPolicy,
}

impl CsvVerifier {
    /// Load the CSV verifier. Returns None if policy.csv.enabled is false.
    pub fn load(policy: &CsvPolicy) -> Option<Self> {
        if !policy.enabled {
            return None;
        }
        Some(Self {
            policy: CsvPolicy {
                enabled: policy.enabled,
                cert_dir: policy.cert_dir.clone(),
                allow_kds_fetch: policy.allow_kds_fetch,
                trusted_chip_ids: policy.trusted_chip_ids.clone(),
            },
        })
    }

    /// Full verification: certificate chain (HRK→HSK→CEK→PEK→report) + report_data nonce binding.
    /// Returns structured result with chip ID and measurements.
    pub fn verify(&self, evidence: &[u8], expected_report_data: &[u8]) -> Result<CsvVerificationResult> {
        // Parse the evidence JSON envelope
        let parsed: CsvEvidenceJson =
            serde_json::from_slice(evidence).context("decode CSV evidence JSON")?;

        let report = AttestationReport::try_from(&parsed.attestation_report)
            .map_err(|e| anyhow!("parse CSV attestation report: {e}"))?;
        let chip_id = std::str::from_utf8(&parsed.serial_number)
            .context("decode serial_number")?
            .trim_end_matches('\0')
            .to_string();

        // Resolve HSK/CEK: use evidence-bundled certs if available, otherwise load from cache/KDS
        let (hsk, cek, pek) = match parsed.cert_chain.hsk_cek {
            Some(h) => (h.hsk, h.cek, parsed.cert_chain.pek),
            None => {
                let cert_data = self
                    .load_hsk_cek(&chip_id)
                    .with_context(|| format!("load HSK/CEK for chip {chip_id}"))?;
                let mut reader = Cursor::new(cert_data);
                let hsk = ca::Certificate::decode(&mut reader, ())
                    .map_err(|e| anyhow!("decode HSK: {e}"))?;
                let cek = csv::Certificate::decode(&mut reader, ())
                    .map_err(|e| anyhow!("decode CEK: {e}"))?;
                (hsk, cek, parsed.cert_chain.pek)
            }
        };

        // Verify HRK→HSK→CEK→PEK→report chain
        verify_chain(&report, hsk, cek, pek)?;

        // Nonce binding: CSV report_data is fixed 64 bytes. Nonce (≤32 bytes) is zero-padded.
        let mut expected = expected_report_data.to_vec();
        expected.resize(64, 0);
        if expected.as_slice() != report.tee_info().report_data() {
            bail!("CSV report_data does not match expected nonce");
        }

        // Chip ID whitelist check
        if !self.policy.trusted_chip_ids.is_empty()
            && !self.policy.trusted_chip_ids.iter().any(|x| x == &chip_id)
        {
            bail!("CSV chip_id '{chip_id}' not in trusted list");
        }

        // Extract measurements from the attestation report
        let tee = report.tee_info();
        let measure_bytes = tee.measure();
        let measurement = (!measure_bytes.is_empty()).then(|| hex::encode(&measure_bytes));
        let vm_version = Some(hex::encode(&tee.vm_version()));
        let policy = tee.policy();
        let policy_nodbg = Some(policy.nodbg());
        let policy_noks = Some(policy.noks());

        info!(%chip_id, "CSV host verify passed");
        Ok(CsvVerificationResult {
            chip_id: Some(chip_id),
            measurement,
            vm_version,
            policy_nodbg,
            policy_noks,
        })
    }

    /// Resolve HSK/CEK certificates: offline cache first, then online KDS if allowed.
    ///
    /// ponytail: synchronous ureq to avoid introducing reqwest + tokio runtime reuse issues.
    fn load_hsk_cek(&self, chip_id: &str) -> Result<Vec<u8>> {
        let local = self
            .policy
            .cert_dir
            .join("hsk_cek")
            .join(chip_id)
            .join("hsk_cek.cert");
        if let Ok(b) = std::fs::read(&local) {
            return Ok(b);
        }
        if !self.policy.allow_kds_fetch {
            bail!(
                "HSK/CEK not found at {} and policy.csv.allow_kds_fetch=false",
                local.display()
            );
        }
        // Fetch from Hygon KDS online service
        let url = format!("https://cert.hygon.cn/hsk_cek?snumber={chip_id}");
        let resp = ureq::get(&url)
            .call()
            .with_context(|| format!("GET {url}"))?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut buf)
            .context("read HSK/CEK body")?;
        Ok(buf)
    }
}

/// Verify the full CSV certificate chain: HRK(self-sign) → HSK → CEK → PEK → report.
fn verify_chain(
    report: &AttestationReport,
    hsk: ca::Certificate,
    cek: csv::Certificate,
    pek: csv::Certificate,
) -> Result<()> {
    let hrk = ca::Certificate::decode(&mut &HRK[..], ()).map_err(|e| anyhow!("decode HRK: {e}"))?;
    // Chain verification: each link must be signed by the previous
    (&hrk, &hrk).verify().map_err(|e| anyhow!("HRK self-sign: {e}"))?;
    (&hrk, &hsk).verify().map_err(|e| anyhow!("HSK signed by HRK: {e}"))?;
    (&hsk, &cek).verify().map_err(|e| anyhow!("CEK signed by HSK: {e}"))?;
    (&cek, &pek).verify().map_err(|e| anyhow!("PEK signed by CEK: {e}"))?;
    (&pek, &report.tee_info())
        .verify()
        .map_err(|e| anyhow!("report signed by PEK: {e}"))?;
    Ok(())
}
