#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::raw::{c_int, c_uchar, c_uint};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::ima;
use crate::EvidenceRequest;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::HygonCsvEvidence;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CSV_NONCE_LEN: usize = 16;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
extern "C" {
    fn csv_user_attestation_report_size() -> c_uint;
    fn csv_user_get_attestation_report(
        report_buf: *mut c_uchar,
        buf_len: c_uint,
        nonce: *const c_uchar,
        nonce_len: c_uint,
    ) -> c_int;
}

#[derive(Debug, Default)]
pub struct HygonCsvUserAttester;

impl HygonCsvUserAttester {
    pub fn tee_get_evidence(&self, request: EvidenceRequest) -> Result<String> {
        csv_user_get_evidence(request)
    }
}

pub fn detect_platform() -> bool {
    let is_hygon = fs::read_to_string("/proc/cpuinfo")
        .map(|content| content.contains("HygonGenuine") || content.contains("Hygon"))
        .unwrap_or(false);
    is_hygon && std::path::Path::new("/proc/self/pagemap").exists()
}

fn csv_user_get_evidence(request: EvidenceRequest) -> Result<String> {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = request;
        bail!("hygon csv user-mode attestation is only supported on Linux x86_64");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let nonce = challenge_to_nonce(&request.challenge)?;
        let report_len = unsafe { csv_user_attestation_report_size() as usize };
        let mut report = vec![0u8; report_len];

        let ret = unsafe {
            csv_user_get_attestation_report(
                report.as_mut_ptr(),
                report.len() as c_uint,
                nonce.as_ptr(),
                nonce.len() as c_uint,
            )
        };
        if ret != 0 {
            bail!(
                "hygon csv user-mode attestation failed, ret:{ret}: {}",
                explain_csv_user_error(ret)
            );
        }

        let ima_log = ima::read_ima_log_if_requested(request.ima.unwrap_or(false))?;
        serde_json::to_string(&HygonCsvEvidence {
            mode: "user".to_string(),
            report: STANDARD.encode(report),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ima_log,
        })
        .map_err(Into::into)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn explain_csv_user_error(ret: i32) -> &'static str {
    match ret {
        -2 => "invalid report buffer or CSV nonce length",
        -3 => "mmap request page failed",
        -4 => "SM3 digest failed; check OpenSSL/GmSSL EVP_sm3 support",
        -5 => "failed to translate virtual address through /proc/self/pagemap; run as root/CAP_SYS_ADMIN or use csv-kernel-attester",
        -6 => "vmmcall KVM_HC_VM_ATTESTATION failed; check that this is a Hygon CSV guest and user-mode attestation is supported",
        -7 => "report session MAC verification failed",
        _ => "unknown C attestation failure",
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn challenge_to_nonce(challenge: &[u8]) -> Result<[u8; CSV_NONCE_LEN]> {
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge)
        .context("decode base64url challenge failed")?;
    if challenge.is_empty() {
        bail!("challenge cannot be empty");
    }

    let digest = Sha256::digest(&challenge);
    let mut nonce = [0u8; CSV_NONCE_LEN];
    nonce.copy_from_slice(&digest[..CSV_NONCE_LEN]);
    Ok(nonce)
}
