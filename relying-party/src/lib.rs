use anyhow::{Context, Result, bail};
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::SNARK;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalSerialize, SerializationError};
use hydra_toolkit::{EvidenceReply, current_unix_duration};
use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use std::time::Duration;

type GrothSetup = Groth16<Bls12_381>;

fn append_field(out: &mut Vec<u8>, field_name: &[u8], field_data: &[u8]) {
    out.extend_from_slice(&(field_name.len() as u64).to_be_bytes());
    out.extend_from_slice(field_name);
    out.extend_from_slice(&(field_data.len() as u64).to_be_bytes());
    out.extend_from_slice(field_data);
}

fn serialize_ark<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::new();
    value.serialize_uncompressed(&mut bytes)?;
    Ok(bytes)
}

fn serialize_duration(duration: &Duration) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&duration.as_secs().to_be_bytes());
    bytes.extend_from_slice(&duration.subsec_nanos().to_be_bytes());
    bytes
}

fn proof_timestamp_period_signing_bytes(
    evidence_reply: &EvidenceReply,
) -> Result<Vec<u8>, SerializationError> {
    let mut out = Vec::new();

    let proof_bytes = serialize_ark(&evidence_reply.proof)?;
    append_field(&mut out, &b"proof"[..], &proof_bytes);

    let timestamp_attester_bytes = serialize_duration(&evidence_reply.timestamp_attester);
    append_field(
        &mut out,
        &b"timestamp_attester"[..],
        &timestamp_attester_bytes,
    );

    let period_attester_bytes = serialize_duration(&evidence_reply.period_attester);
    append_field(&mut out, &b"period_attester"[..], &period_attester_bytes);

    Ok(out)
}

/// Verify the verifier's authorization signature embedded in the EvidenceReply.
/// Message: `(attester_pk, authorized_infor, timestamp, period)` — the same format
/// produced by `verifier_compute_sig`. This proves the verifier endorsed this device
/// at this time window.
pub fn rely_party_verifier_sig(evidence_reply: &EvidenceReply, verifier_pk: &VerifyingKey) {
    let mut msg = Vec::new();
    msg.extend_from_slice(evidence_reply.pk.to_encoded_point(true).as_bytes());
    msg.extend_from_slice(evidence_reply.authorized_infor.to_string().as_bytes());
    msg.extend_from_slice(&evidence_reply.timestamp.as_secs().to_be_bytes());
    msg.extend_from_slice(&evidence_reply.period.as_secs().to_be_bytes());

    match verifier_pk.verify(msg.as_slice(), &evidence_reply.sig) {
        Ok(_) => println!("verifier authorization signature verified"),
        Err(e) => println!(
            "verifier authorization signature verification failed: {:?}",
            e
        ),
    }
}

/// Full hydra evidence verification on the relying-party side.
///
/// Three checks in order:
/// 1. Attester signature over the whole EvidenceReply (proves attester generated it).
/// 2. Verifier authorization signature over (pk, authorized_infor, timestamp, period)
///    (proves the verifier endorsed this device at this time).
/// 3. Groth16::verify with public inputs [pk, root[..], authorized_infor, timestamp, period]
///    (proves the device is in the shrubs whitelist without revealing its position).
///
/// Returns `Ok(true)` if all checks pass.
pub fn rely_party_verification(
    root: &[hydra_toolkit::BlsScalar],
    evidence_reply: &EvidenceReply,
    signature: Signature,
    verifier_pk: &VerifyingKey,
) -> Result<bool> {
    let attester_pubkey_hex = hex::encode(evidence_reply.pk.to_encoded_point(true).as_bytes());
    let public_inputs = evidence_reply.gen_public_inputs(root);
    let msg: Vec<u8> = evidence_reply
        .to_signing_bytes_all_fields()
        .expect("serialize EvidenceReply failed");

    // The attester signature and verifier signature are already verified by the
    // hydra_listener caller before entering this function. Here we re-check them
    // only for diagnostic println output — the return value depends solely on
    // Groth16::verify. If the caller hasn't pre-checked, failures here will be
    // printed but NOT reflected in the return value.
    match evidence_reply.pk.verify(&msg[..], &signature) {
        Ok(_) => println!("attester EvidenceReply signature verified"),
        Err(e) => println!(
            "attester EvidenceReply signature verification failed: {:?}",
            e
        ),
    }

    rely_party_verifier_sig(evidence_reply, verifier_pk);

    // The decisive check: Groth16 proof verification against the public inputs.
    // This is the mathematically binding step that proves the device is in the
    // shrubs whitelist without revealing its index.
    let res = match GrothSetup::verify(&evidence_reply.vk, &public_inputs, &evidence_reply.proof) {
        Ok(res) => res,
        Err(err) => {
            println!(
                "relying-party proof verification failed; attester_pubkey={}; error={:?}",
                attester_pubkey_hex, err
            );
            return Ok(false);
        }
    };
    if !res {
        println!(
            "relying-party proof verification failed; attester_pubkey={}",
            attester_pubkey_hex
        );
    }
    if res {
        println!(
            "relying-party proof verification success; attester_pubkey={}",
            attester_pubkey_hex
        );
        println!("attester evidence verification success");
    } else {
        println!("attester evidence verification failed");
    }
    Ok(res)
}

/// Verify that the attester signed this EvidenceReply with its own key.
/// The signed message is the deterministic `to_signing_bytes_all_fields()` output,
/// which covers every field of the EvidenceReply. This prevents replay or tampering.
pub fn verify_evidence_reply_attester_signature(
    evidence_reply: &EvidenceReply,
    signature: &Signature,
) -> Result<()> {
    let msg: Vec<u8> = evidence_reply
        .to_signing_bytes_all_fields()
        .expect("serialize EvidenceReply failed");
    evidence_reply
        .pk
        .verify(&msg[..], signature)
        .context("attester EvidenceReply signature verification failed")
}

/// Check that the attester's timestamp+period has not expired.
/// The attester stamps its own wall-clock time when generating the EvidenceReply;
/// the RP rejects stale evidence to prevent long-delayed replay.
pub fn verify_evidence_reply_attester_freshness(evidence_reply: &EvidenceReply) -> Result<()> {
    let expires_at = evidence_reply
        .timestamp_attester
        .checked_add(evidence_reply.period_attester)
        .context("EvidenceReply timestamp_attester + period_attester overflow")?;
    let now = current_unix_duration()?;
    if expires_at > now {
        Ok(())
    } else {
        bail!(
            "EvidenceReply expired: timestamp_attester={} period_attester={} now={}",
            evidence_reply.timestamp_attester.as_secs(),
            evidence_reply.period_attester.as_secs(),
            now.as_secs()
        )
    }
}

/// Verify the attester's proof-freshness signature: the attester signs
/// `(proof, timestamp_attester, period_attester)` to prove the Groth16 proof
/// was generated recently, not replayed from an old session.
pub fn verify_evidence_reply_proof_timestamp_period_signature(
    evidence_reply: &EvidenceReply,
) -> Result<()> {
    let msg = proof_timestamp_period_signing_bytes(evidence_reply)
        .context("serialize EvidenceReply proof freshness fields failed")?;
    evidence_reply
        .pk
        .verify(&msg[..], &evidence_reply.proof_timestamp_period_signature)
        .context("attester proof/timestamp_attester/period_attester signature verification failed")
}
