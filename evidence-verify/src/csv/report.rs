use anyhow::{bail, Result};

pub const HASH_LEN: usize = 32;
pub const VM_ID_SIZE: usize = 16;
pub const VM_VERSION_SIZE: usize = 16;
pub const USER_DATA_SIZE: usize = 64;
pub const NONCE_SIZE: usize = 16;
pub const SN_LEN: usize = 64;
pub const RESERVED2_SIZE: usize = 32;
pub const ECC_LEN: usize = 32;
pub const ECC_POINT_SIZE: usize = 72;
pub const HYGON_USER_ID_SIZE: usize = 256;
pub const ECC_PUBKEY_SIZE: usize = 4 + ECC_POINT_SIZE + ECC_POINT_SIZE + HYGON_USER_ID_SIZE;
pub const ECC_SIGNATURE_SIZE: usize = ECC_POINT_SIZE + ECC_POINT_SIZE;
pub const ROOT_CERT_SIZE: usize = 832;
pub const ROOT_CERT_SIGNED_SIZE: usize = 576;
pub const ROOT_CERT_PUBKEY_OFFSET: usize = 64;
pub const ROOT_CERT_SIGNATURE_OFFSET: usize = 576;
pub const CSV_CERT_SIZE: usize = 2084;
pub const CSV_CERT_SIGNED_SIZE: usize = 1044;
pub const REPORT_SIGNED_SIZE: usize = 180;
pub const REPORT_SIZE: usize = 2548;

const USER_DATA_OFFSET: usize = HASH_LEN + VM_ID_SIZE + VM_VERSION_SIZE;
const MNONCE_OFFSET: usize = USER_DATA_OFFSET + USER_DATA_SIZE;
const MEASURE_OFFSET: usize = MNONCE_OFFSET + NONCE_SIZE;
const POLICY_OFFSET: usize = MEASURE_OFFSET + HASH_LEN;
const SIG_USAGE_OFFSET: usize = POLICY_OFFSET + 4;
const SIG_ALGO_OFFSET: usize = SIG_USAGE_OFFSET + 4;
const ANONCE_OFFSET: usize = SIG_ALGO_OFFSET + 4;
const REPORT_SIG_OFFSET: usize = ANONCE_OFFSET + 4;
const PEK_CERT_OFFSET: usize = REPORT_SIG_OFFSET + ECC_SIGNATURE_SIZE;
const SN_OFFSET: usize = PEK_CERT_OFFSET + CSV_CERT_SIZE;
const RESERVED2_OFFSET: usize = SN_OFFSET + SN_LEN;
const MAC_OFFSET: usize = RESERVED2_OFFSET + RESERVED2_SIZE;

pub const ROOT_CERT_KEY_USAGE_OFFSET: usize = 36;
pub const CSV_CERT_PUBKEY_USAGE_OFFSET: usize = 8;
pub const CSV_CERT_PUBKEY_OFFSET: usize = 16;
pub const CSV_CERT_SIG1_USAGE_OFFSET: usize = 1044;
pub const CSV_CERT_SIG1_OFFSET: usize = 1052;
pub const CSV_CERT_SIG2_USAGE_OFFSET: usize = 1564;
pub const CSV_CERT_SIG2_OFFSET: usize = 1572;

#[derive(Debug)]
pub struct CsvReport {
    raw: Vec<u8>,
    pub user_data: [u8; USER_DATA_SIZE],
    pub mnonce: [u8; NONCE_SIZE],
    pub measure: [u8; HASH_LEN],
    pub policy: u32,
    pub sig_usage: u32,
    pub sig_algo: u32,
    pub anonce: u32,
    pub pek_cert: Vec<u8>,
    pub chip_id: [u8; SN_LEN],
    pub reserved2: [u8; RESERVED2_SIZE],
    pub mac: [u8; HASH_LEN],
}

impl CsvReport {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < REPORT_SIZE {
            bail!(
                "Hygon CSV report length is wrong, expecting at least {}, got {}",
                REPORT_SIZE,
                raw.len()
            );
        }
        let raw = raw[..REPORT_SIZE].to_vec();
        let anonce = u32_at(&raw, ANONCE_OFFSET);
        let policy = u32_at(&raw, POLICY_OFFSET) ^ anonce;
        let sig_usage = u32_at(&raw, SIG_USAGE_OFFSET) ^ anonce;
        let sig_algo = u32_at(&raw, SIG_ALGO_OFFSET) ^ anonce;

        let mut user_data = [0u8; USER_DATA_SIZE];
        xor_u32_chunks(
            &raw[USER_DATA_OFFSET..USER_DATA_OFFSET + USER_DATA_SIZE],
            anonce,
            &mut user_data,
        );

        let mut mnonce = [0u8; NONCE_SIZE];
        xor_u32_chunks(
            &raw[MNONCE_OFFSET..MNONCE_OFFSET + NONCE_SIZE],
            anonce,
            &mut mnonce,
        );

        let mut measure = [0u8; HASH_LEN];
        xor_u32_chunks(
            &raw[MEASURE_OFFSET..MEASURE_OFFSET + HASH_LEN],
            anonce,
            &mut measure,
        );

        let mut pek_cert = vec![0u8; CSV_CERT_SIZE];
        xor_u32_chunks(
            &raw[PEK_CERT_OFFSET..PEK_CERT_OFFSET + CSV_CERT_SIZE],
            anonce,
            &mut pek_cert,
        );

        let mut chip_id = [0u8; SN_LEN];
        xor_u32_chunks(&raw[SN_OFFSET..SN_OFFSET + SN_LEN], anonce, &mut chip_id);

        let mut reserved2 = [0u8; RESERVED2_SIZE];
        reserved2.copy_from_slice(&raw[RESERVED2_OFFSET..RESERVED2_OFFSET + RESERVED2_SIZE]);

        let mut mac = [0u8; HASH_LEN];
        mac.copy_from_slice(&raw[MAC_OFFSET..MAC_OFFSET + HASH_LEN]);

        Ok(Self {
            raw,
            user_data,
            mnonce,
            measure,
            policy,
            sig_usage,
            sig_algo,
            anonce,
            pek_cert,
            chip_id,
            reserved2,
            mac,
        })
    }

    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw[..REPORT_SIGNED_SIZE]
    }

    pub fn report_signature(&self) -> EccSignature<'_> {
        EccSignature::new(&self.raw[REPORT_SIG_OFFSET..REPORT_SIG_OFFSET + ECC_SIGNATURE_SIZE])
    }

    pub fn mac_input(&self) -> &[u8] {
        &self.raw[PEK_CERT_OFFSET..MAC_OFFSET]
    }

    pub fn pek_pubkey(&self) -> EccPubKey<'_> {
        EccPubKey::new(
            &self.pek_cert[CSV_CERT_PUBKEY_OFFSET..CSV_CERT_PUBKEY_OFFSET + ECC_PUBKEY_SIZE],
        )
    }
}

#[derive(Clone, Copy)]
pub struct EccPubKey<'a> {
    data: &'a [u8],
}

impl<'a> EccPubKey<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn qx(&self) -> [u8; ECC_LEN] {
        first_ecc_len_reversed(&self.data[4..4 + ECC_POINT_SIZE])
    }

    pub fn qy(&self) -> [u8; ECC_LEN] {
        first_ecc_len_reversed(&self.data[4 + ECC_POINT_SIZE..4 + ECC_POINT_SIZE * 2])
    }

    pub fn user_id(&self) -> &[u8] {
        let raw = &self.data[4 + ECC_POINT_SIZE * 2..4 + ECC_POINT_SIZE * 2 + HYGON_USER_ID_SIZE];
        let len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
        let len = len.min(HYGON_USER_ID_SIZE - 2);
        &raw[2..2 + len]
    }
}

pub struct EccSignature<'a> {
    data: &'a [u8],
}

impl<'a> EccSignature<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn r(&self) -> [u8; ECC_LEN] {
        first_ecc_len_reversed(&self.data[..ECC_POINT_SIZE])
    }

    pub fn s(&self) -> [u8; ECC_LEN] {
        first_ecc_len_reversed(&self.data[ECC_POINT_SIZE..ECC_POINT_SIZE * 2])
    }
}

fn first_ecc_len_reversed(input: &[u8]) -> [u8; ECC_LEN] {
    let mut out = [0u8; ECC_LEN];
    out.copy_from_slice(&input[..ECC_LEN]);
    out.reverse();
    out
}

fn xor_u32_chunks(input: &[u8], key: u32, out: &mut [u8]) {
    for (src, dst) in input.chunks_exact(4).zip(out.chunks_exact_mut(4)) {
        let value = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) ^ key;
        dst.copy_from_slice(&value.to_le_bytes());
    }
}

fn u32_at(input: &[u8], offset: usize) -> u32 {
    u32_at_le(input, offset)
}

pub fn u32_at_le(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}
