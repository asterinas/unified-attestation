use hydra_toolkit::{
    BlsScalar, DeviceClientInfor, KeyInfor, ResponseDeviceInfor, generate_device_authoried_infor,
};
use k256::ecdsa::{Signature, signature::Signer};

pub fn verifier_compute_sig(
    verifier_key: &KeyInfor,
    device_time: &ResponseDeviceInfor,
    device_author_infor: &BlsScalar,
) -> Signature {
    let mut msg = Vec::new();
    msg.extend_from_slice(device_time.verifying_key.to_encoded_point(true).as_bytes());
    msg.extend_from_slice(device_author_infor.to_string().as_bytes());
    msg.extend_from_slice(&device_time.timestamp.as_secs().to_be_bytes());
    msg.extend_from_slice(&device_time.period.as_secs().to_be_bytes());
    verifier_key.signing_key.sign(msg.as_slice())
}

pub fn generate_verifier_resonse_infor_1(
    devices_infor: &DeviceClientInfor,
    verifier_key: &KeyInfor,
    leaves: &mut Vec<BlsScalar>,
    hasher: &hydra_toolkit::Poseidon<BlsScalar>,
) -> ResponseDeviceInfor {
    let mut device_resp =
        ResponseDeviceInfor::new_with_mode(devices_infor.mode, devices_infor.verifying_key);
    let device_author_infor = generate_device_authoried_infor(devices_infor, &device_resp, hasher);
    let sig = verifier_compute_sig(verifier_key, &device_resp, &device_author_infor);
    device_resp.set_signature(&sig);
    let merkle_leaf = devices_infor
        .merkle_leaf
        .expect("passport mode requires merkle_leaf");
    leaves.push(merkle_leaf);
    device_resp
}
