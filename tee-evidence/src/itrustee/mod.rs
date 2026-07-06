use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;

use crate::ima;
use crate::{ensure_challenge_len, EvidenceRequest, ItrusteeEvidence};

mod itrustee;

const MAX_CHALLENGE_LEN: usize = 64;
const MAX_CHALLENGE_LEN_IMA: usize = 32;

#[derive(Debug, Default)]
pub struct ItrusteeAttester;

impl ItrusteeAttester {
    pub fn tee_get_evidence(&self, user_data: EvidenceRequest) -> Result<String> {
        itrustee_provision().context("itrustee attester provision failed")?;
        itrustee_get_evidence(user_data)
    }
}

pub fn detect_platform() -> bool {
    fs::read_to_string("/proc/modules")
        .map(|content| content.lines().any(|line| line.starts_with("tzdriver")))
        .unwrap_or(false)
}

#[derive(Serialize, Deserialize)]
struct ReportInputPayload {
    version: String,
    nonce: String,
    uuid: String,
    hash_alg: String,
    with_tcb: bool,
    request_key: bool,
}

#[derive(Serialize, Deserialize)]
struct ItrusteeInput {
    handler: String,
    payload: ReportInputPayload,
}

fn itrustee_get_evidence(user_data: EvidenceRequest) -> Result<String> {
    let challenge = URL_SAFE_NO_PAD
        .decode(&user_data.challenge)
        .context("decode base64url challenge failed")?;
    let with_ima = user_data.ima.unwrap_or(false);
    let max_challenge_len = if with_ima {
        MAX_CHALLENGE_LEN_IMA
    } else {
        MAX_CHALLENGE_LEN
    };
    ensure_challenge_len(&challenge, max_challenge_len)?;

    let ima_log = ima::read_ima_log_if_requested(with_ima)?;
    let nonce = if with_ima {
        let ima_log = ima_log
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ima log is empty"))?;
        let mut hasher = Sha256::new();
        hasher.update(ima_log);
        let ima_log_hash = hasher.finalize();
        let mut combined = challenge.clone();
        combined.extend_from_slice(&ima_log_hash);
        URL_SAFE_NO_PAD.encode(combined)
    } else {
        String::from_utf8(user_data.challenge).context("challenge is not valid UTF-8")?
    };
    let uuid = user_data
        .uuid
        .context("itrustee evidence request requires uuid")?;

    let payload = ReportInputPayload {
        nonce,
        uuid,
        with_tcb: false,
        request_key: true,
        version: String::from("TEE.RA.1.0"),
        hash_alg: String::from("HS256"),
    };

    let itrustee_input = ItrusteeInput {
        handler: String::from("report-input"),
        payload,
    };
    let mut buf = serde_json::to_string(&itrustee_input)?;
    let mut input = itrustee::ra_buffer_data {
        size: buf.len() as ::std::os::raw::c_uint,
        buf: buf.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    let mut report = vec![b'\0'; 0x3000];
    let mut output = itrustee::ra_buffer_data {
        size: report.len() as ::std::os::raw::c_uint,
        buf: report.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    unsafe {
        let ret = itrustee::RemoteAttest(&mut input, &mut output);
        if ret != 0 {
            bail!("itrustee get report failed, ret:{ret}");
        }
        let out_len: usize = output.size.try_into()?;
        report.set_len(out_len);
    }

    while report.last() == Some(&b'\0') {
        report.pop();
    }

    log::info!("itrustee raw report len after trim nul: {}", report.len());
    let report = String::from_utf8(report).context("itrustee report is not valid UTF-8")?;
    serde_json::to_string(&ItrusteeEvidence { report, ima_log }).map_err(Into::into)
}

fn itrustee_provision() -> Result<()> {
    let json = r#"{"handler":"provisioning-input","payload":{"version":"TEE.RA.1.0","scenario":"sce_no_as","hash_alg":"HS256"}}"#;

    let provision_input: serde_json::Value = serde_json::from_str(json)?;
    let mut provision_input = provision_input.to_string();

    let mut input = itrustee::ra_buffer_data {
        size: provision_input.len() as ::std::os::raw::c_uint,
        buf: provision_input.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    let mut report = vec![b'\0'; 0x3000];
    let mut output = itrustee::ra_buffer_data {
        size: report.len() as ::std::os::raw::c_uint,
        buf: report.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    unsafe {
        let ret = itrustee::RemoteAttest(&mut input, &mut output);
        if ret != 0 {
            bail!("itrustee provision failed, ret:{ret}");
        }
    }

    Ok(())
}
