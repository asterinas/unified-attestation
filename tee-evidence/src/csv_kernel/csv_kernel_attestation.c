#include "csv_attestation.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
 
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

typedef struct csv_guest_mem {
    unsigned long va;
    int size;
} csv_guest_mem_t;

#define CSV_GUEST_IOC_TYPE 'D'
#define GET_ATTESTATION_REPORT _IOWR(CSV_GUEST_IOC_TYPE, 1, csv_guest_mem_t)

unsigned int csv_kernel_attestation_report_size(void)
{
    return sizeof(csv_attestation_report_t);
}

static int csv_sm3(const unsigned char *data, size_t data_len, unsigned char *out)
{
    unsigned int out_len = CSV_HASH_LEN;

    if (EVP_Digest(data, data_len, out, &out_len, EVP_sm3(), NULL) != 1) {
        return -1;
    }

    return out_len == CSV_HASH_LEN ? 0 : -1;
}

static int csv_sm3_hmac(const unsigned char *data,
                        size_t data_len,
                        const unsigned char *key,
                        size_t key_len,
                        unsigned char *out)
{
    unsigned int out_len = CSV_HASH_LEN;

    if (!HMAC(EVP_sm3(), key, (int)key_len, data, data_len, out, &out_len)) {
        return -1;
    }

    return out_len == CSV_HASH_LEN ? 0 : -1;
}

static int csv_verify_session_mac(csv_attestation_report_t *report, const unsigned char *nonce)
{
    csv_hash_block_u hmac = {0};

    if (!report || !nonce) {
        return -1;
    }

    if (csv_sm3_hmac((const unsigned char *)(&report->pek_cert),
                     sizeof(report->pek_cert) + CSV_SN_LEN + sizeof(report->reserved2),
                     nonce,
                     CSV_GUEST_ATTESTATION_NONCE_SIZE,
                     (unsigned char *)(hmac.block)) != 0) {
        return -1;
    }

    return memcmp(hmac.block, report->mac.block, sizeof(report->mac.block)) == 0 ? 0 : -1;
}

int csv_kernel_get_attestation_report(unsigned char *report_buf,
                                      unsigned int buf_len,
                                      const unsigned char *nonce,
                                      unsigned int nonce_len)
{
    csv_attestation_user_data_t *user_data;
    csv_attestation_report_t report;
    csv_guest_mem_t mem = {0};
    int fd;
    long ret;

    if (!report_buf || !nonce || nonce_len != CSV_GUEST_ATTESTATION_NONCE_SIZE) {
        return -2;
    }

    if (buf_len < sizeof(csv_attestation_report_t)) {
        return -2;
    }

    user_data = malloc(PAGE_SIZE);
    if (!user_data) {
        return -3;
    }

    memset(user_data, 0, PAGE_SIZE);
    snprintf((char *)user_data->data, CSV_GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    memcpy(user_data->mnonce, nonce, CSV_GUEST_ATTESTATION_NONCE_SIZE);
    if (csv_sm3((const unsigned char *)user_data,
                CSV_GUEST_ATTESTATION_DATA_SIZE + CSV_GUEST_ATTESTATION_NONCE_SIZE,
                (unsigned char *)&user_data->hash) != 0) {
        free(user_data);
        return -4;
    }

    fd = open("/dev/csv-guest", O_RDWR);
    if (fd < 0) {
        free(user_data);
        return -5;
    }

    mem.va = (unsigned long)user_data;
    mem.size = PAGE_SIZE;
    ret = ioctl(fd, GET_ATTESTATION_REPORT, &mem);
    close(fd);

    if (ret < 0) {
        free(user_data);
        return -6;
    }

    memcpy(&report, user_data, sizeof(report));
    free(user_data);

    if (csv_verify_session_mac(&report, nonce) != 0) {
        return -7;
    }

    memset(report.reserved2, 0, sizeof(report.reserved2));
    memcpy(report_buf, &report, sizeof(report));
    return 0;
}
