use anyhow::{anyhow, bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{HygonCsvEvidence, TeeClaim};

mod report;
mod sm2;

const CSV_NONCE_LEN: usize = 16;
const KEY_USAGE_TYPE_HSK: u32 = 0x13;
const KEY_USAGE_TYPE_INVALID: u32 = 0x1000;
const KEY_USAGE_TYPE_PEK: u32 = 0x1002;
const KEY_USAGE_TYPE_CEK: u32 = 0x1004;
const SIG_ALGO_INVALID: u32 = 0x0;
const SIG_ALGO_RSA_SHA256: u32 = 0x1;
const SIG_ALGO_ECDSA_SHA256: u32 = 0x2;
const SIG_ALGO_ECDH_SHA256: u32 = 0x3;
const SIG_ALGO_SM2_SA: u32 = 0x4;
const SIG_ALGO_SM2_DH: u32 = 0x5;
const SIG_ALGO_RSA_SHA384: u32 = 0x101;
const SIG_ALGO_ECDSA_SHA384: u32 = 0x102;
const SIG_ALGO_ECDH_SHA384: u32 = 0x103;
const HSK_CEK_CERT_FILE: &str = "hsk_cek.cert";
const HSK_CEK_DEFAULT_DIR: &str = "/opt/hygon/demo/csv/hsk_cek";
const HYGON_KDS_SERVER_SITE: &str = "https://cert.hygon.cn/hsk_cek?snumber=";

#[derive(Debug, Default)]
pub struct HygonCsvVerifier;

impl HygonCsvVerifier {
    pub fn evaluate_user(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        self.evaluate("user", user_data, evidence)
    }

    pub fn evaluate_kernel(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        self.evaluate("kernel", user_data, evidence)
    }

    fn evaluate(&self, expected_mode: &str, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        let evidence: HygonCsvEvidence =
            serde_json::from_slice(evidence).context("parse Hygon CSV evidence failed")?;
        if evidence.mode != expected_mode {
            bail!(
                "Hygon CSV evidence mode mismatch: expected {expected_mode}, got {}",
                evidence.mode
            );
        }

        if evidence.ima_log.is_some() {
            bail!(
                "Hygon CSV evidence contains ima_log, but CSV IMA verification is not implemented"
            );
        }

        let expected_nonce = challenge_to_nonce(user_data)?;
        let evidence_nonce = URL_SAFE_NO_PAD
            .decode(evidence.nonce.as_bytes())
            .map_err(|err| anyhow!("decode Hygon CSV evidence nonce failed: {err:?}"))?;
        if evidence_nonce.as_slice() != expected_nonce.as_slice() {
            bail!("Hygon CSV evidence nonce does not match request.challenge");
        }

        let report_bytes = STANDARD
            .decode(evidence.report.as_bytes())
            .context("decode Hygon CSV report failed")?;
        let parsed = report::CsvReport::parse(&report_bytes)?;

        if parsed.mnonce.as_slice() != expected_nonce.as_slice() {
            bail!("Hygon CSV report mnonce does not match request.challenge");
        }

        let session_mac_verified = verify_session_mac_if_available(&parsed)?;
        sm2::verify_report_signature(&parsed)?;
        let chain_verified = verify_cert_chain_if_available(&parsed)?;

        Ok(json!({
            "tee": match expected_mode {
                "user" => "hygon_csv_user",
                "kernel" => "hygon_csv_kernel",
                _ => "hygon_csv",
            },
            "payload": {
                "csv.mode": evidence.mode,
                "csv.nonce": hex::encode(parsed.mnonce),
                "csv.user_data": hex::encode(parsed.user_data),
                "csv.measure": hex::encode(parsed.measure),
                "csv.policy": parsed.policy,
                "csv.policy.meaning": csv_policy_meaning(parsed.policy),
                "csv.sig_usage": parsed.sig_usage,
                "csv.sig_usage.meaning": csv_usage_meaning(parsed.sig_usage),
                "csv.sig_algo": parsed.sig_algo,
                "csv.sig_algo.meaning": csv_sig_algo_meaning(parsed.sig_algo),
                "csv.anonce": parsed.anonce,
                "csv.sn": hex::encode(parsed.chip_id),
                "csv.session_mac": session_mac_verified,
                "csv.cert_chain": chain_verified,
            },
            "ima": {},
        }))
    }
}

fn csv_policy_meaning(policy: u32) -> String {
    format!("CSV report policy bitfield ({policy:#x})")
}

fn csv_usage_meaning(usage: u32) -> String {
    match usage {
        0x0 => "HRK: Hygon root key".to_string(),
        KEY_USAGE_TYPE_HSK => "HSK: Hygon signing key".to_string(),
        KEY_USAGE_TYPE_INVALID => "INVALID: no key usage".to_string(),
        0x1001 => "OCA: owner certificate authority key".to_string(),
        KEY_USAGE_TYPE_PEK => "PEK: platform endorsement key".to_string(),
        0x1003 => "PDH: platform Diffie-Hellman key".to_string(),
        KEY_USAGE_TYPE_CEK => "CEK: chip endorsement key".to_string(),
        _ => format!("unknown key usage ({usage:#x})"),
    }
}

fn csv_sig_algo_meaning(algo: u32) -> String {
    match algo {
        SIG_ALGO_INVALID => "INVALID: no signature algorithm".to_string(),
        SIG_ALGO_RSA_SHA256 => "RSA with SHA-256".to_string(),
        SIG_ALGO_ECDSA_SHA256 => "ECDSA with SHA-256".to_string(),
        SIG_ALGO_ECDH_SHA256 => "ECDH with SHA-256".to_string(),
        SIG_ALGO_SM2_SA => "SM2 signature algorithm with SM3 digest".to_string(),
        SIG_ALGO_SM2_DH => "SM2 key exchange algorithm".to_string(),
        SIG_ALGO_RSA_SHA384 => "RSA with SHA-384".to_string(),
        SIG_ALGO_ECDSA_SHA384 => "ECDSA with SHA-384".to_string(),
        SIG_ALGO_ECDH_SHA384 => "ECDH with SHA-384".to_string(),
        _ => format!("unknown signature algorithm ({algo:#x})"),
    }
}

fn challenge_to_nonce(challenge: &[u8]) -> Result<[u8; CSV_NONCE_LEN]> {
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge)
        .map_err(|err| anyhow!("decode base64url challenge failed: {err:?}"))?;
    if challenge.is_empty() {
        bail!("challenge cannot be empty");
    }

    let digest = Sha256::digest(&challenge);
    let mut nonce = [0u8; CSV_NONCE_LEN];
    nonce.copy_from_slice(&digest[..CSV_NONCE_LEN]);
    Ok(nonce)
}

fn verify_session_mac_if_available(report: &report::CsvReport) -> Result<bool> {
    if report.reserved2.iter().all(|byte| *byte == 0) {
        return Ok(false);
    }

    let key = PKey::hmac(&report.mnonce)?;
    let mut signer = Signer::new(MessageDigest::sm3(), &key)?;
    signer.update(report.mac_input())?;
    let hmac = signer.sign_to_vec()?;

    if hmac.as_slice() != report.mac {
        bail!("Hygon CSV report session MAC verification failed");
    }

    Ok(true)
}

fn verify_cert_chain_if_available(report: &report::CsvReport) -> Result<bool> {
    let chip_id = chip_id_to_string(&report.chip_id)?;
    let Some(hsk_cek) = load_hsk_cek_cert(&chip_id)? else {
        return Ok(false);
    };
    let expected_hsk_cek_len = report::ROOT_CERT_SIZE + report::CSV_CERT_SIZE;

    let hsk = &hsk_cek[..report::ROOT_CERT_SIZE];
    let cek = &hsk_cek[report::ROOT_CERT_SIZE..expected_hsk_cek_len];

    verify_hsk_cert(hsk).context("verify HSK cert signature failed")?;
    verify_csv_cert_with_root_issuer(cek, hsk).context("verify CEK cert signature failed")?;
    verify_csv_cert_with_csv_issuer(&report.pek_cert, cek)
        .context("verify PEK cert signature failed")?;

    Ok(true)
}

fn chip_id_to_string(chip_id: &[u8]) -> Result<String> {
    let end = chip_id
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(chip_id.len());
    let chip_id = std::str::from_utf8(&chip_id[..end]).context("Hygon CSV chip_id is not UTF-8")?;
    if chip_id.is_empty() {
        bail!("Hygon CSV chip_id is empty");
    }
    Ok(chip_id.to_string())
}

fn load_hsk_cek_cert(chip_id: &str) -> Result<Option<Vec<u8>>> {
    for path in hsk_cek_candidate_paths(chip_id) {
        if path.exists() {
            let hsk_cek = fs::read(&path)
                .with_context(|| format!("read Hygon HSK/CEK cert failed: {}", path.display()))?;
            return Ok(Some(normalize_hsk_cek_cert(
                hsk_cek,
                &path.display().to_string(),
            )?));
        }
    }

    download_hsk_cek_cert(chip_id)
}

fn hsk_cek_candidate_paths(chip_id: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) = env::var("HYGON_HSK_CEK_CERT") {
        paths.push(PathBuf::from(path));
    }
    paths.push(PathBuf::from(HSK_CEK_CERT_FILE));
    paths.push(
        Path::new(HSK_CEK_DEFAULT_DIR)
            .join(chip_id)
            .join(HSK_CEK_CERT_FILE),
    );
    paths
}

fn download_hsk_cek_cert(chip_id: &str) -> Result<Option<Vec<u8>>> {
    if matches!(env::var("HYGON_CSV_DOWNLOAD_CERTS").as_deref(), Ok("0")) {
        return Ok(None);
    }

    let url = format!("{HYGON_KDS_SERVER_SITE}{chip_id}");
    let output = Command::new("curl")
        .args(["-fsSL", "--connect-timeout", "5", "--max-time", "10", &url])
        .output();

    let output = match output {
        Ok(output) => output,
        Err(_) => return Ok(None),
    };
    if !output.status.success() {
        return Ok(None);
    }

    Ok(Some(normalize_hsk_cek_cert(output.stdout, &url)?))
}

fn normalize_hsk_cek_cert(mut hsk_cek: Vec<u8>, source: &str) -> Result<Vec<u8>> {
    let expected = report::ROOT_CERT_SIZE + report::CSV_CERT_SIZE;
    if hsk_cek.len() < expected {
        bail!(
            "Hygon HSK/CEK cert from {source} is too short, expecting at least {expected}, got {}",
            hsk_cek.len()
        );
    }
    hsk_cek.truncate(expected);
    Ok(hsk_cek)
}

fn verify_hsk_cert(cert: &[u8]) -> Result<()> {
    if report::u32_at_le(cert, report::ROOT_CERT_KEY_USAGE_OFFSET) != KEY_USAGE_TYPE_HSK {
        bail!("hsk key_usage is not HSK");
    }

    let hrk_pubkey = hrk_pubkey();
    let issuer_pubkey = report::EccPubKey::new(&hrk_pubkey);
    let signature = report::EccSignature::new(
        &cert[report::ROOT_CERT_SIGNATURE_OFFSET
            ..report::ROOT_CERT_SIGNATURE_OFFSET + report::ECC_SIGNATURE_SIZE],
    );
    sm2::verify_signature(
        &cert[..report::ROOT_CERT_SIGNED_SIZE],
        signature,
        issuer_pubkey,
    )
}

fn verify_csv_cert_with_root_issuer(cert: &[u8], issuer: &[u8]) -> Result<()> {
    if report::u32_at_le(cert, report::CSV_CERT_PUBKEY_USAGE_OFFSET) != KEY_USAGE_TYPE_CEK {
        bail!("cek pubkey_usage is not CEK");
    }
    if report::u32_at_le(cert, report::CSV_CERT_SIG1_USAGE_OFFSET) != KEY_USAGE_TYPE_HSK {
        bail!("cek sig1_usage is not HSK");
    }
    if report::u32_at_le(cert, report::CSV_CERT_SIG2_USAGE_OFFSET) != KEY_USAGE_TYPE_INVALID {
        bail!("cek sig2_usage is not INVALID");
    }

    let issuer_pubkey = report::EccPubKey::new(
        &issuer[report::ROOT_CERT_PUBKEY_OFFSET
            ..report::ROOT_CERT_PUBKEY_OFFSET + report::ECC_PUBKEY_SIZE],
    );
    let sig_offset =
        if report::u32_at_le(cert, report::CSV_CERT_SIG1_USAGE_OFFSET) == KEY_USAGE_TYPE_INVALID {
            report::CSV_CERT_SIG2_OFFSET
        } else {
            report::CSV_CERT_SIG1_OFFSET
        };
    let signature =
        report::EccSignature::new(&cert[sig_offset..sig_offset + report::ECC_SIGNATURE_SIZE]);
    sm2::verify_signature(
        &cert[..report::CSV_CERT_SIGNED_SIZE],
        signature,
        issuer_pubkey,
    )
}

fn verify_csv_cert_with_csv_issuer(cert: &[u8], issuer: &[u8]) -> Result<()> {
    if report::u32_at_le(cert, report::CSV_CERT_PUBKEY_USAGE_OFFSET) != KEY_USAGE_TYPE_PEK {
        bail!("pek pubkey_usage is not PEK");
    }
    if report::u32_at_le(cert, report::CSV_CERT_SIG1_USAGE_OFFSET) != KEY_USAGE_TYPE_CEK {
        bail!("pek sig1_usage is not CEK");
    }

    let issuer_pubkey = report::EccPubKey::new(
        &issuer[report::CSV_CERT_PUBKEY_OFFSET
            ..report::CSV_CERT_PUBKEY_OFFSET + report::ECC_PUBKEY_SIZE],
    );
    let issuer_usage = report::u32_at_le(issuer, report::CSV_CERT_PUBKEY_USAGE_OFFSET);
    let sig_offset = match issuer_usage {
        KEY_USAGE_TYPE_CEK => report::CSV_CERT_SIG1_OFFSET,
        usage => bail!("unsupported CSV cert issuer usage {usage:#x}"),
    };
    let signature =
        report::EccSignature::new(&cert[sig_offset..sig_offset + report::ECC_SIGNATURE_SIZE]);
    sm2::verify_signature(
        &cert[..report::CSV_CERT_SIGNED_SIZE],
        signature,
        issuer_pubkey,
    )
}

fn hrk_pubkey() -> Vec<u8> {
    let mut pubkey = vec![0u8; report::ECC_PUBKEY_SIZE];
    pubkey[..4].copy_from_slice(&3u32.to_le_bytes());
    pubkey[4..37].copy_from_slice(&[
        0x2d, 0xf6, 0xc2, 0x92, 0x1d, 0xf2, 0xf5, 0x2a, 0x50, 0x1f, 0xcd, 0x85, 0xe7, 0x35, 0x09,
        0xc8, 0x75, 0x3a, 0x56, 0x09, 0xdb, 0x02, 0xd7, 0xf3, 0x4c, 0xf1, 0xa4, 0x62, 0x4d, 0xe1,
        0x62, 0xbe, 0x00,
    ]);
    pubkey[4 + report::ECC_POINT_SIZE..4 + report::ECC_POINT_SIZE + 33].copy_from_slice(&[
        0x46, 0xb9, 0x1e, 0xb4, 0x68, 0x4d, 0x74, 0x38, 0x47, 0x88, 0xbe, 0xb9, 0x10, 0x0c, 0x64,
        0x4a, 0x38, 0x95, 0x4e, 0x16, 0x97, 0x8b, 0x4f, 0x58, 0x15, 0x70, 0xbb, 0x57, 0x3a, 0x12,
        0xab, 0x3b, 0x00,
    ]);
    let user_id = b"HYGON-SSD-HRK";
    let user_id_offset = 4 + report::ECC_POINT_SIZE * 2;
    pubkey[user_id_offset..user_id_offset + 2]
        .copy_from_slice(&(user_id.len() as u16).to_le_bytes());
    pubkey[user_id_offset + 2..user_id_offset + 2 + user_id.len()].copy_from_slice(user_id);
    pubkey
}
