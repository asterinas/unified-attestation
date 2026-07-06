#ifndef TEE_EVIDENCE_CSV_ATTESTATION_H
#define TEE_EVIDENCE_CSV_ATTESTATION_H

#include <stdint.h>

#define CSV_HASH_LEN 32
#define CSV_GUEST_ATTESTATION_NONCE_SIZE 16
#define CSV_GUEST_ATTESTATION_DATA_SIZE 64
#define CSV_VM_ID_SIZE 16
#define CSV_VM_VERSION_SIZE 16
#define CSV_SN_LEN 64
#define CSV_USER_DATA_SIZE 64
#define CSV_HASH_BLOCK_LEN 32
#define CSV_CERT_ECC_MAX_KEY_SIZE 72
#define CSV_HYGON_USER_ID_SIZE 256
#define CSV_SIZE_INT32 4
#define CSV_SIZE_24 24
#define CSV_SIZE_108 108
#define CSV_SIZE_112 112
#define CSV_ECC_POINT_SIZE 72
#define CSV_CHIP_KEY_ID_LEN 16
#define CSV_CERT_RSVD3_SIZE 624
#define CSV_CERT_RSVD4_SIZE 368
#define CSV_CERT_RSVD5_SIZE 368
#define CSV_KVM_HC_VM_ATTESTATION 100

typedef struct csv_hash_block_u {
    unsigned char block[CSV_HASH_LEN];
} csv_hash_block_u;

typedef struct csv_hash_block {
    uint8_t block[CSV_HASH_BLOCK_LEN];
} __attribute__((packed)) csv_hash_block_t;

typedef struct csv_chip_key_id {
    uint8_t id[CSV_CHIP_KEY_ID_LEN];
} __attribute__((packed)) csv_chip_key_id_t;

typedef struct csv_ecc_pubkey {
    uint32_t curve_id;
    uint32_t Qx[CSV_ECC_POINT_SIZE / CSV_SIZE_INT32];
    uint32_t Qy[CSV_ECC_POINT_SIZE / CSV_SIZE_INT32];
    uint32_t user_id[CSV_HYGON_USER_ID_SIZE / CSV_SIZE_INT32];
} __attribute__((packed)) csv_ecc_pubkey_t;

typedef struct csv_ecc_signature {
    uint32_t sig_r[CSV_ECC_POINT_SIZE / CSV_SIZE_INT32];
    uint32_t sig_s[CSV_ECC_POINT_SIZE / CSV_SIZE_INT32];
} __attribute__((packed)) csv_ecc_signature_t;

typedef struct csv_cert {
    uint32_t version;
    uint8_t api_major;
    uint8_t api_minor;
    uint8_t reserved1;
    uint8_t reserved2;
    uint32_t pubkey_usage;
    uint32_t pubkey_algo;
    union {
        uint32_t pubkey[(CSV_SIZE_INT32 + CSV_ECC_POINT_SIZE * 2 + CSV_HYGON_USER_ID_SIZE) / CSV_SIZE_INT32];
        csv_ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved3[CSV_CERT_RSVD3_SIZE / CSV_SIZE_INT32];
    uint32_t sig1_usage;
    uint32_t sig1_algo;
    union {
        uint32_t sig1[CSV_ECC_POINT_SIZE * 2 / CSV_SIZE_INT32];
        csv_ecc_signature_t ecc_sig1;
    };
    uint32_t reserved4[CSV_CERT_RSVD4_SIZE / CSV_SIZE_INT32];
    uint32_t sig2_usage;
    uint32_t sig2_algo;
    union {
        uint32_t sig2[CSV_ECC_POINT_SIZE * 2 / CSV_SIZE_INT32];
        csv_ecc_signature_t ecc_sig2;
    };
    uint32_t reserved5[CSV_CERT_RSVD5_SIZE / CSV_SIZE_INT32];
} __attribute__((packed)) csv_cert_t;

typedef struct csv_attestation_report {
    csv_hash_block_t user_pubkey_digest;
    uint8_t vm_id[CSV_VM_ID_SIZE];
    uint8_t vm_version[CSV_VM_VERSION_SIZE];
    uint8_t user_data[CSV_USER_DATA_SIZE];
    uint8_t mnonce[CSV_GUEST_ATTESTATION_NONCE_SIZE];
    csv_hash_block_t measure;
    uint32_t policy;
    uint32_t sig_usage;
    uint32_t sig_algo;
    uint32_t anonce;
    union {
        uint32_t sig1[CSV_ECC_POINT_SIZE * 2 / CSV_SIZE_INT32];
        csv_ecc_signature_t ecc_sig1;
    };
    csv_cert_t pek_cert;
    uint8_t sn[CSV_SN_LEN];
    uint8_t reserved2[32];
    csv_hash_block_u mac;
} __attribute__((packed)) csv_attestation_report_t;

typedef struct csv_attestation_user_data {
    uint8_t data[CSV_GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[CSV_GUEST_ATTESTATION_NONCE_SIZE];
    csv_hash_block_u hash;
} __attribute__((packed)) csv_attestation_user_data_t;

#endif
