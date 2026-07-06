use anyhow::{bail, Result};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcPoint};
use openssl::hash::{Hasher, MessageDigest};
use std::cmp::Ordering;

use super::report::{CsvReport, EccPubKey, EccSignature, ECC_LEN};

const SM2_P: [u8; ECC_LEN] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
const SM2_A: [u8; ECC_LEN] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
];
const SM2_B: [u8; ECC_LEN] = [
    0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
    0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
];
const SM2_GX: [u8; ECC_LEN] = [
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
    0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
];
const SM2_GY: [u8; ECC_LEN] = [
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
    0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0,
];
const SM2_N: [u8; ECC_LEN] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b, 0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23,
];

pub fn verify_report_signature(report: &CsvReport) -> Result<()> {
    verify_signature(
        report.signed_bytes(),
        report.report_signature(),
        report.pek_pubkey(),
    )
}

pub(super) fn verify_signature(
    msg: &[u8],
    signature: EccSignature<'_>,
    pubkey: EccPubKey<'_>,
) -> Result<()> {
    let group = sm2_group()?;
    let qx = BigNum::from_slice(&pubkey.qx())?;
    let qy = BigNum::from_slice(&pubkey.qy())?;
    let mut ctx = openssl::bn::BigNumContext::new()?;
    let mut point = EcPoint::new(&group)?;
    point.set_affine_coordinates(&group, &qx, &qy, &mut ctx)?;

    let digest = sm2_message_digest(msg, pubkey)?;
    if !verify_sm2_digest(&group, &point, &digest, signature)? {
        bail!("Hygon CSV report SM2 signature verification failed");
    }

    Ok(())
}

fn sm2_group() -> Result<EcGroup> {
    let mut ctx = openssl::bn::BigNumContext::new()?;
    let p = BigNum::from_slice(&SM2_P)?;
    let a = BigNum::from_slice(&SM2_A)?;
    let b = BigNum::from_slice(&SM2_B)?;
    let mut group = EcGroup::from_components(p, a, b, &mut ctx)?;

    let gx = BigNum::from_slice(&SM2_GX)?;
    let gy = BigNum::from_slice(&SM2_GY)?;
    let mut generator = EcPoint::new(&group)?;
    generator.set_affine_coordinates(&group, &gx, &gy, &mut ctx)?;

    let order = BigNum::from_slice(&SM2_N)?;
    let cofactor = BigNum::from_u32(1)?;
    group.set_generator(generator, order, cofactor)?;

    Ok(group)
}

fn verify_sm2_digest(
    group: &EcGroup,
    pubkey: &EcPoint,
    digest: &[u8; ECC_LEN],
    signature: EccSignature<'_>,
) -> Result<bool> {
    let mut ctx = openssl::bn::BigNumContext::new()?;
    let mut order = BigNum::new()?;
    group.order(&mut order, &mut ctx)?;

    let zero = BigNum::from_u32(0)?;
    let r = BigNum::from_slice(&signature.r())?;
    let s = BigNum::from_slice(&signature.s())?;
    if r.ucmp(&zero) != Ordering::Greater || r.ucmp(&order) != Ordering::Less {
        return Ok(false);
    }
    if s.ucmp(&zero) != Ordering::Greater || s.ucmp(&order) != Ordering::Less {
        return Ok(false);
    }

    let mut t = BigNum::new()?;
    t.mod_add(&r, &s, &order, &mut ctx)?;
    if t.ucmp(&zero) == Ordering::Equal {
        return Ok(false);
    }

    let mut calculated = EcPoint::new(group)?;
    calculated.mul_full(group, &s, pubkey, &t, &mut ctx)?;

    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    calculated.affine_coordinates(group, &mut x, &mut y, &mut ctx)?;

    let e = BigNum::from_slice(digest)?;
    let mut expected_r = BigNum::new()?;
    expected_r.mod_add(&e, &x, &order, &mut ctx)?;

    Ok(expected_r.ucmp(&r) == Ordering::Equal)
}

fn sm2_message_digest(msg: &[u8], pubkey: EccPubKey<'_>) -> Result<[u8; ECC_LEN]> {
    let user_id = pubkey.user_id();
    if user_id.len() > (u16::MAX as usize / 8) {
        bail!("SM2 user id is too long");
    }
    let entl = ((user_id.len() * 8) as u16).to_be_bytes();
    let qx = pubkey.qx();
    let qy = pubkey.qy();

    let mut za_hasher = Hasher::new(MessageDigest::sm3())?;
    za_hasher.update(&entl)?;
    za_hasher.update(user_id)?;
    za_hasher.update(&SM2_A)?;
    za_hasher.update(&SM2_B)?;
    za_hasher.update(&SM2_GX)?;
    za_hasher.update(&SM2_GY)?;
    za_hasher.update(&qx)?;
    za_hasher.update(&qy)?;
    let za = za_hasher.finish()?;

    let mut digest_hasher = Hasher::new(MessageDigest::sm3())?;
    digest_hasher.update(za.as_ref())?;
    digest_hasher.update(msg)?;
    let digest = digest_hasher.finish()?;

    let mut out = [0u8; ECC_LEN];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}
