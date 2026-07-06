use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::path::Path;

use crate::ima;
use crate::{ensure_challenge_len, EvidenceRequest, VirtccaEvidence};

mod virtcca;

const CCEL_DATA_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";
const MAX_CHALLENGE_LEN: usize = 64;

#[derive(Debug, Default)]
pub struct VirtccaAttester;

impl VirtccaAttester {
    pub fn tee_get_evidence(&self, user_data: EvidenceRequest) -> Result<String> {
        let evidence = virtcca_get_token(user_data)?;
        serde_json::to_string(&evidence).map_err(Into::into)
    }
}

pub fn detect_platform() -> bool {
    Path::new("/dev/tsi").exists()
}

fn virtcca_get_token(user_data: EvidenceRequest) -> Result<VirtccaEvidence> {
    let mut challenge = URL_SAFE_NO_PAD.decode(&user_data.challenge)?;
    ensure_challenge_len(&challenge, MAX_CHALLENGE_LEN)?;

    unsafe {
        let ctx = virtcca::tsi_new_ctx();
        if ctx.is_null() {
            bail!("virtcca tsi_new_ctx returned null");
        }

        let mut token = vec![b'\0'; 4096];
        let mut token_len = token.len();
        let ret = virtcca::get_attestation_token(
            ctx,
            challenge.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
            challenge.len(),
            token.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
            &mut token_len as *mut usize,
        );
        if ret != 0 {
            virtcca::tsi_free_ctx(ctx);
            bail!("virtcca get attestation token failed {ret}");
        }
        token.set_len(token_len);

        let mut dev_cert = vec![b'\0'; 4096];
        let mut dev_cert_len = dev_cert.len();
        let ret = virtcca::get_dev_cert(
            ctx,
            dev_cert.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
            &mut dev_cert_len as *mut usize,
        );
        if ret != 0 {
            virtcca::tsi_free_ctx(ctx);
            bail!("get dev cert failed {ret}");
        }
        dev_cert.set_len(dev_cert_len);

        virtcca::tsi_free_ctx(ctx);

        let with_ima = user_data.ima.unwrap_or(false);
        let ima_log = ima::read_ima_log_if_requested(with_ima)?;
        let event_log = std::fs::read(CCEL_DATA_PATH).ok();

        Ok(VirtccaEvidence {
            evidence: token,
            dev_cert,
            ima_log,
            event_log,
        })
    }
}
