use super::*;
#[cfg(feature = "ima-verifier")]
use crate::ima::ImaVerifier;
use crate::ItrusteeEvidence;
use anyhow::anyhow;
use log;
use serde_json::json;
use std::ops::Add;
use std::path::Path;

#[allow(clippy::module_inception)]
mod itrustee;

const ITRUSTEE_REF_VALUE_DIR: &str = "/etc/attestation/attestation-service/verifier/itrustee";
const MAX_CHALLENGE_LEN: usize = 64;

#[derive(Debug, Default)]
pub struct ItrusteeVerifier {}

impl ItrusteeVerifier {
    pub fn evaluate(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        evaluate_wrapper(user_data, evidence)
    }
}

fn evaluate_wrapper(user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
    let challenge = base64_url::decode(user_data)
        .map_err(|err| anyhow!("decode base64url challenge failed: {err:?}"))?;
    let evidence: ItrusteeEvidence = serde_json::from_slice(evidence)?;

    if let Ok(pretty) = serde_json::to_string_pretty(&evidence) {
        log::debug!("{pretty}");
    }

    let report = evidence.report;
    let js_evidence: serde_json::Value = serde_json::from_str(&report)?;
    let with_ima = evidence.ima_log.is_some();
    #[cfg(feature = "ima-verifier")]
    let ima_log = evidence.ima_log.unwrap_or_default();
    let len = challenge.len();
    if len == 0 || len > MAX_CHALLENGE_LEN {
        log::error!(
            "challenge len is error, expecting 0 < len <= {}, got {}",
            MAX_CHALLENGE_LEN,
            len
        );
        bail!(
            "challenge len is error, expecting 0 < len <= {}, got {}",
            MAX_CHALLENGE_LEN,
            len
        );
    }

    #[cfg(feature = "ima-verifier")]
    let mut ima = serde_json::Value::Null;
    #[cfg(not(feature = "ima-verifier"))]
    let ima = serde_json::Value::Null;
    let mut in_data = challenge.to_vec();
    if with_ima {
        #[cfg(not(feature = "ima-verifier"))]
        bail!("iTrustee evidence contains ima_log, but ima-verifier feature is disabled");

        #[cfg(feature = "ima-verifier")]
        {
            let report_nonce = js_evidence["payload"]["nonce"]
                .as_str()
                .ok_or_else(|| anyhow!("IMA verification: nonce not found in evidence"))?;
            let uuid = js_evidence["payload"]["uuid"]
                .as_str()
                .ok_or_else(|| anyhow!("IMA verification: uuid not found in evidence"))?;
            let nonce_all = base64_url::decode(&report_nonce)
                .map_err(|err| anyhow!("decode base64url report nonce failed: {err:?}"))?;
            if nonce_all.len() != MAX_CHALLENGE_LEN {
                log::error!(
                    "IMA verification: {} nonce length is not 64 bytes, got {}",
                    uuid,
                    nonce_all.len()
                );
                bail!(
                    "IMA verification: {} nonce length is not 64 bytes, got {}",
                    uuid,
                    nonce_all.len()
                );
            }
            let nonce_expected = &nonce_all[..32]; // 前32字节是challenge
            let ima_log_hash = &nonce_all[32..]; // 后32字节是ima_log_hash
            if nonce_expected != challenge {
                log::error!("IMA verification: {} nonce and challenge mismatch", uuid);
                bail!("IMA verification: {} nonce and challenge mismatch", uuid);
            }
            ima = crate::ima::itrustee::ItrusteeImaVerify::default().ima_verify(
                &ima_log,
                &[ima_log_hash.to_vec()],
                Some(uuid),
            )?;
            in_data = nonce_all.to_vec();
        }
    }

    // let mut in_data = challenge.to_vec();
    let mut in_evidence = report.as_bytes().to_vec();
    let mut data_buf: itrustee::buffer_data = itrustee::buffer_data {
        size: in_evidence.len() as ::std::os::raw::c_uint,
        buf: in_evidence.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };
    let mut nonce = itrustee::buffer_data {
        size: in_data.len() as ::std::os::raw::c_uint,
        buf: in_data.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    // 1: verify ta_img; 2: verfiy ta_mem; 3: verify ta_img and ta_mem hash;
    let policy: std::os::raw::c_int = 1;

    let uuid;
    if let Some(v) = js_evidence
        .get("payload")
        .and_then(|v| v.get("uuid"))
        .and_then(|v| v.as_str())
    {
        uuid = v;
    } else {
        log::error!("Parse TA uuid from evidence failed.");
        bail!("Parse TA uuid from evidence failed.");
    }
    let ref_file = ITRUSTEE_REF_VALUE_DIR.to_string() + "/itrustee_" + uuid;
    if !Path::new(&ref_file).exists() {
        log::error!("itrustee verify report {} not exists", ref_file);
        bail!("itrustee verify report {} not exists", ref_file);
    }

    let mut file = ref_file.add("\0");
    let basevalue = file.as_mut_ptr() as *mut ::std::os::raw::c_char;
    unsafe {
        let ret = itrustee::tee_verify_report(&mut data_buf, &mut nonce, policy, basevalue);
        if ret != 0 {
            log::error!("itrustee verify report failed ret:{}", ret);
            bail!("itrustee verify report failed ret:{}", ret);
        }
    }

    let payload = json!({
        "itrustee.nonce": js_evidence["payload"]["nonce"].clone(),
        "itrustee.hash_alg": js_evidence["payload"]["hash_alg"].clone(),
        "itrustee.key": js_evidence["payload"]["key"].clone(),
        "itrustee.ta_img": js_evidence["payload"]["ta_img"].clone(),
        "itrustee.ta_mem": js_evidence["payload"]["ta_mem"].clone(),
        "itrustee.uuid": js_evidence["payload"]["uuid"].clone(),
        "itrustee.version": js_evidence["payload"]["version"].clone(),
    });

    let claim = json!({
        "tee": "itrustee",
        "payload" : payload,
        "ima" : ima,
    });

    if let Ok(pretty) = serde_json::to_string_pretty(&claim) {
        log::debug!("claim: {pretty}");
    }

    Ok(claim as TeeClaim)
}
