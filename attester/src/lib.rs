use anyhow::{Context, Result, bail};
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::SNARK;
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};
use ecdsa::{SigningKey, VerifyingKey};
use hydra_toolkit::{
    BlsScalar, DeviceClientInfor, EvidenceReply, KeyInfor, Poseidon, ResponseDeviceInfor,
    generate_verifier_authoried_infor,
};
use k256::Secp256k1;
use k256::ecdsa::{Signature, signature::Signer};
use num_bigint::BigUint;
use rand_core::OsRng;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::time::Duration;

type GrothSetup = Groth16<Bls12_381>;

#[derive(Debug)]
pub struct DeviceConfigInfor {
    pub signing_key: SigningKey<Secp256k1>,
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub measured_value: BlsScalar,
    pub timestamp: Duration,
    pub period: Duration,
    pub merkle_leaf: BlsScalar,
    pub merkle_path: Option<Vec<BlsScalar>>,
    pub merkle_tag: Option<Vec<bool>>,
    pub authorized_infor: BlsScalar,
    pub signature: Option<Signature>,
}

impl DeviceConfigInfor {
    pub fn new(
        dev_key: &KeyInfor,
        dev_cli: &DeviceClientInfor,
        dec_res: &ResponseDeviceInfor,
        hasher: &Poseidon<BlsScalar>,
    ) -> DeviceConfigInfor {
        let pk = BlsScalar::from(BigUint::from_bytes_be(
            dev_key.verifying_key.to_encoded_point(true).as_bytes(),
        ));
        let ar = BlsScalar::from(BigUint::from_bytes_be(dev_cli.measured_value.as_bytes()));
        let time = BlsScalar::from(dec_res.timestamp.as_secs());
        let peri = BlsScalar::from(dec_res.period.as_secs());
        let leaf = dev_cli
            .merkle_leaf
            .expect("passport mode requires merkle_leaf");
        let output = generate_verifier_authoried_infor(ar, pk, time, peri, hasher);

        DeviceConfigInfor {
            signing_key: dev_key.signing_key.clone(),
            verifying_key: dev_key.verifying_key,
            measured_value: ar,
            timestamp: dec_res.timestamp,
            period: dec_res.period,
            merkle_leaf: leaf,
            authorized_infor: output,
            merkle_path: dec_res.shrubs_path.clone(),
            merkle_tag: dec_res.shrubs_tag.clone(),
            signature: dec_res.sig,
        }
    }
}

#[derive(Copy, Debug)]
struct AttestationCircuit<'a, HG: FieldHasherGadget<BlsScalar>> {
    pk: BlsScalar,
    sk: BlsScalar,
    ar: BlsScalar,
    time: BlsScalar,
    period: BlsScalar,
    output: BlsScalar,
    root: &'a [BlsScalar],
    path: Option<&'a [BlsScalar]>,
    tag: Option<&'a [bool]>,
    hasher: &'a HG::Native,
}

impl<'a, HG: FieldHasherGadget<BlsScalar>> AttestationCircuit<'a, HG> {
    fn new(
        device_config: &DeviceConfigInfor,
        root: &'a [BlsScalar],
        path: Option<&'a [BlsScalar]>,
        tag: Option<&'a [bool]>,
        hasher: &'a HG::Native,
    ) -> Self {
        Self {
            pk: BlsScalar::from(BigUint::from_bytes_be(
                device_config
                    .verifying_key
                    .to_encoded_point(true)
                    .as_bytes(),
            )),
            sk: BlsScalar::from(BigUint::from_bytes_be(
                &device_config.signing_key.to_bytes()[..],
            )),
            ar: device_config.measured_value,
            period: BlsScalar::from(device_config.period.as_secs()),
            output: device_config.authorized_infor,
            time: BlsScalar::from(device_config.timestamp.as_secs()),
            root,
            path,
            tag,
            hasher,
        }
    }
}

impl<'a, HG: FieldHasherGadget<BlsScalar>> Clone for AttestationCircuit<'a, HG> {
    fn clone(&self) -> Self {
        AttestationCircuit {
            pk: self.pk,
            sk: self.sk,
            ar: self.ar,
            period: self.period,
            output: self.output,
            root: self.root,
            time: self.time,
            tag: self.tag,
            path: self.path,
            hasher: self.hasher,
        }
    }
}

impl<'a, HG: FieldHasherGadget<BlsScalar>> ConstraintSynthesizer<BlsScalar>
    for AttestationCircuit<'a, HG>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BlsScalar>,
    ) -> Result<(), SynthesisError> {
        let sk = FpVar::new_witness(cs.clone(), || Ok(self.sk))?;
        let ar = FpVar::new_witness(cs.clone(), || Ok(self.ar))?;
        let pk = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.pk))?;
        let root: Vec<_> = self
            .root
            .iter()
            .map(|x| FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;
        let output = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.output))?;
        let time = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.time))?;
        let period = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.period))?;
        let hasher_gadget: HG =
            FieldHasherGadget::<BlsScalar>::from_native(&mut cs.clone(), self.hasher.clone())?;
        let m = hasher_gadget.hash(&[ar.clone(), sk.clone()])?;
        let mut leaf = hasher_gadget.hash(&[m, pk.clone()])?;

        match (self.path, self.tag) {
            (Some(path_values), Some(tag_values)) => {
                if path_values.len() != tag_values.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
                let path: Vec<_> = path_values
                    .iter()
                    .map(|x| FpVar::<BlsScalar>::new_witness(cs.clone(), || Ok(*x)))
                    .collect::<Result<Vec<_>, _>>()?;
                for i in 0..tag_values.len() {
                    if tag_values[i] {
                        leaf = hasher_gadget.hash(&[leaf.clone(), path[i].clone()])?;
                    } else {
                        leaf = hasher_gadget.hash(&[path[i].clone(), leaf.clone()])?;
                    }
                }
                let mut res = Boolean::<BlsScalar>::constant(false);
                for root_i in root.iter() {
                    let is_equal = leaf.is_eq(root_i)?;
                    res = res.or(&is_equal)?;
                }
                res.enforce_equal(&Boolean::TRUE)?;
            }
            (None, None) => leaf.enforce_equal(&root[0])?,
            _ => return Err(SynthesisError::Unsatisfiable),
        }

        let result_1 = hasher_gadget.hash(&[pk, ar])?;
        let result_2 = hasher_gadget.hash(&[result_1, time])?;
        let result = hasher_gadget.hash(&[result_2, period])?;
        output.enforce_equal(&result)?;
        Ok(())
    }
}

fn ensure_parent_dir(path: impl AsRef<Path>) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directory failed")?;
    }
    Ok(())
}

fn append_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_exact<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    std::io::Read::read_exact(cursor, &mut buf).context("read fixed bytes failed")?;
    Ok(buf)
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    Ok(u64::from_be_bytes(read_exact::<8>(cursor)?))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    Ok(u32::from_be_bytes(read_exact::<4>(cursor)?))
}

fn read_len_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = read_u64(cursor)? as usize;
    let mut bytes = vec![0u8; len];
    std::io::Read::read_exact(cursor, &mut bytes).context("read length-prefixed bytes failed")?;
    Ok(bytes)
}

fn append_duration(out: &mut Vec<u8>, value: Duration) {
    out.extend_from_slice(&value.as_secs().to_be_bytes());
    out.extend_from_slice(&value.subsec_nanos().to_be_bytes());
}

fn read_duration(cursor: &mut Cursor<&[u8]>) -> Result<Duration> {
    let secs = read_u64(cursor)?;
    let nanos = read_u32(cursor)?;
    Ok(Duration::new(secs, nanos))
}

fn encode_scalar(value: &BlsScalar) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("serialize BlsScalar failed")?;
    Ok(bytes)
}

fn decode_scalar(bytes: &[u8]) -> Result<BlsScalar> {
    let mut cursor = Cursor::new(bytes);
    BlsScalar::deserialize_uncompressed(&mut cursor).context("deserialize BlsScalar failed")
}

fn append_scalar(out: &mut Vec<u8>, value: &BlsScalar) -> Result<()> {
    append_len_bytes(out, &encode_scalar(value)?);
    Ok(())
}

fn read_scalar(cursor: &mut Cursor<&[u8]>) -> Result<BlsScalar> {
    decode_scalar(&read_len_bytes(cursor)?)
}

fn append_scalar_vec(out: &mut Vec<u8>, values: &[BlsScalar]) -> Result<()> {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        append_scalar(out, value)?;
    }
    Ok(())
}

fn read_scalar_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<BlsScalar>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(read_scalar(cursor)?);
    }
    Ok(values)
}

fn append_bool_vec(out: &mut Vec<u8>, values: &[bool]) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        out.push(u8::from(*value));
    }
}

fn read_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<bool>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        match read_exact::<1>(cursor)?[0] {
            0 => values.push(false),
            1 => values.push(true),
            other => bail!("invalid bool value: {}", other),
        }
    }
    Ok(values)
}

fn append_option_scalar_vec(out: &mut Vec<u8>, values: &Option<Vec<BlsScalar>>) -> Result<()> {
    match values {
        Some(values) => {
            out.push(1);
            append_scalar_vec(out, values)?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn read_option_scalar_vec(cursor: &mut Cursor<&[u8]>) -> Result<Option<Vec<BlsScalar>>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_scalar_vec(cursor)?)),
        other => bail!("invalid Option<Vec<BlsScalar>> tag: {}", other),
    }
}

fn append_option_bool_vec(out: &mut Vec<u8>, values: &Option<Vec<bool>>) {
    match values {
        Some(values) => {
            out.push(1);
            append_bool_vec(out, values);
        }
        None => out.push(0),
    }
}

fn read_option_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Option<Vec<bool>>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_bool_vec(cursor)?)),
        other => bail!("invalid Option<Vec<bool>> tag: {}", other),
    }
}

fn encode_signature(value: &Signature) -> Vec<u8> {
    value.to_der().as_bytes().to_vec()
}

fn decode_signature(bytes: &[u8]) -> Result<Signature> {
    Signature::from_der(bytes).context("deserialize secp256k1 signature failed")
}

fn append_signature(out: &mut Vec<u8>, value: &Signature) {
    append_len_bytes(out, &encode_signature(value));
}

fn read_signature(cursor: &mut Cursor<&[u8]>) -> Result<Signature> {
    decode_signature(&read_len_bytes(cursor)?)
}

fn append_option_signature(out: &mut Vec<u8>, value: &Option<Signature>) {
    match value {
        Some(sig) => {
            out.push(1);
            append_signature(out, sig);
        }
        None => out.push(0),
    }
}

fn read_option_signature(cursor: &mut Cursor<&[u8]>) -> Result<Option<Signature>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_signature(cursor)?)),
        other => bail!("invalid Option<Signature> tag: {}", other),
    }
}

fn append_verifying_key(out: &mut Vec<u8>, value: &VerifyingKey<Secp256k1>) {
    append_len_bytes(out, value.to_encoded_point(true).as_bytes());
}

fn read_verifying_key(cursor: &mut Cursor<&[u8]>) -> Result<VerifyingKey<Secp256k1>> {
    VerifyingKey::<Secp256k1>::from_sec1_bytes(&read_len_bytes(cursor)?)
        .context("deserialize secp256k1 public key failed")
}

pub fn save_device_config_infor(path: impl AsRef<Path>, value: &DeviceConfigInfor) -> Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let mut out = Vec::new();
    append_len_bytes(&mut out, &value.signing_key.to_bytes()[..]);
    append_verifying_key(&mut out, &value.verifying_key);
    append_scalar(&mut out, &value.measured_value)?;
    append_duration(&mut out, value.timestamp);
    append_duration(&mut out, value.period);
    append_scalar(&mut out, &value.merkle_leaf)?;
    append_option_scalar_vec(&mut out, &value.merkle_path)?;
    append_option_bool_vec(&mut out, &value.merkle_tag);
    append_scalar(&mut out, &value.authorized_infor)?;
    append_option_signature(&mut out, &value.signature);
    fs::write(path, out).context("save DeviceConfigInfor failed")
}

pub fn load_device_config_infor(path: impl AsRef<Path>) -> Result<DeviceConfigInfor> {
    let bytes = fs::read(path).context("read DeviceConfigInfor failed")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let sk_bytes = read_len_bytes(&mut cursor)?;
    if sk_bytes.len() != 32 {
        bail!(
            "secp256k1 secret key length must be 32 bytes, got {}",
            sk_bytes.len()
        );
    }
    let signing_key = SigningKey::<Secp256k1>::from_bytes(k256::FieldBytes::from_slice(&sk_bytes))
        .context("decode DeviceConfigInfor secret key failed")?;
    Ok(DeviceConfigInfor {
        signing_key,
        verifying_key: read_verifying_key(&mut cursor)?,
        measured_value: read_scalar(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        merkle_leaf: read_scalar(&mut cursor)?,
        merkle_path: read_option_scalar_vec(&mut cursor)?,
        merkle_tag: read_option_bool_vec(&mut cursor)?,
        authorized_infor: read_scalar(&mut cursor)?,
        signature: read_option_signature(&mut cursor)?,
    })
}

pub fn generate_device_evidence(
    root: &[BlsScalar],
    device_key: &KeyInfor,
    device_client_infor: &DeviceClientInfor,
    device_resp: &ResponseDeviceInfor,
    hasher: &Poseidon<BlsScalar>,
) -> (EvidenceReply, Signature) {
    let dev_config = DeviceConfigInfor::new(device_key, device_client_infor, device_resp, hasher);
    generate_device_evidence_from_config(root, &dev_config, hasher)
}

pub fn generate_device_evidence_from_config(
    root: &[BlsScalar],
    dev_config: &DeviceConfigInfor,
    hasher: &Poseidon<BlsScalar>,
) -> (EvidenceReply, Signature) {
    let merkel_path_ref = dev_config.merkle_path.as_deref();
    let merkel_tag_ref = dev_config.merkle_tag.as_deref();

    let circuit = AttestationCircuit::<PoseidonGadget<BlsScalar>>::new(
        dev_config,
        root,
        merkel_path_ref,
        merkel_tag_ref,
        hasher,
    );
    let (pkk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), &mut OsRng).unwrap();
    let proof = GrothSetup::prove(&pkk, circuit.clone(), &mut OsRng).unwrap();

    let evidence_reply = EvidenceReply::new(
        proof,
        vk,
        dev_config
            .signature
            .expect("DeviceConfigInfor requires verifier signature"),
        dev_config.verifying_key,
        dev_config.timestamp,
        dev_config.period,
        dev_config.authorized_infor,
        &dev_config.signing_key,
    );
    let msg: Vec<u8> = evidence_reply
        .to_signing_bytes_all_fields()
        .expect("serialize EvidenceReply failed");
    let signature = dev_config.signing_key.sign(&msg[..]);

    (evidence_reply, signature)
}
