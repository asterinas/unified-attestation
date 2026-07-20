//! Verifier crypto helpers. The authorization signature here is the verifier's
//! endorsement that "this device was in the whitelist at this time."

use hydra_toolkit::{BlsScalar, KeyInfor, ResponseDeviceInfor};
use k256::ecdsa::{Signature, signature::Signer};

pub mod hydra_daemon;

/// Verifier authorization signature over `(attester_pk, authorized_infor, timestamp, period)`.
/// The relying-party verifies this signature with the verifier's public key from PublicContext.
pub fn verifier_compute_sig(
    verifier_key: &KeyInfor,
    device_time: &ResponseDeviceInfor,
    device_author_infor: &BlsScalar,
) -> Signature {
    // Message = attester_pk (SEC1 compressed) || authorized_infor (decimal string) || timestamp (u64 BE) || period (u64 BE)
    let mut msg = Vec::new();
    msg.extend_from_slice(device_time.verifying_key.to_encoded_point(true).as_bytes());
    msg.extend_from_slice(device_author_infor.to_string().as_bytes());
    msg.extend_from_slice(&device_time.timestamp.as_secs().to_be_bytes());
    msg.extend_from_slice(&device_time.period.as_secs().to_be_bytes());
    verifier_key.signing_key.sign(msg.as_slice())
}
