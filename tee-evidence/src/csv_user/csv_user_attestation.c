#include "csv_attestation.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGEMAP_LEN 8
#define CSV_PA_INVALID UINT64_MAX

unsigned int csv_user_attestation_report_size(void)
{
    return sizeof(csv_attestation_report_t);
}

static uint64_t va_to_pa(uint64_t va)
{
    FILE *pagemap = fopen("/proc/self/pagemap", "rb");
    uint64_t offset;
    uint64_t pfn = 0;

    if (!pagemap) {
        return CSV_PA_INVALID;
    }

    offset = va / PAGE_SIZE * PAGEMAP_LEN;
    if (fseek(pagemap, offset, SEEK_SET) != 0) {
        fclose(pagemap);
        return CSV_PA_INVALID;
    }

    if (fread(&pfn, 1, PAGEMAP_LEN - 1, pagemap) != PAGEMAP_LEN - 1) {
        fclose(pagemap);
        return CSV_PA_INVALID;
    }

    fclose(pagemap);
    pfn &= 0x7FFFFFFFFFFFFF;
    return pfn << PAGE_SHIFT;
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

static long csv_hypercall(unsigned int nr, unsigned long p1, unsigned int len)
{
    long ret = 0;

    asm volatile("vmmcall"
        : "=a"(ret)
        : "a"(nr), "b"(p1), "c"(len)
        : "memory");
    return ret;
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

int csv_user_get_attestation_report(unsigned char *report_buf,
                                    unsigned int buf_len,
                                    const unsigned char *nonce,
                                    unsigned int nonce_len)
{
    csv_attestation_user_data_t *user_data;
    csv_attestation_report_t report;
    uint64_t user_data_pa;
    long ret;

    if (!report_buf || !nonce || nonce_len != CSV_GUEST_ATTESTATION_NONCE_SIZE) {
        return -2;
    }

    if (buf_len < sizeof(csv_attestation_report_t)) {
        return -2;
    }

    user_data = mmap(NULL,
                     PAGE_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                     -1,
                     0);
    if (user_data == MAP_FAILED) {
        return -3;
    }

    memset(user_data, 0, PAGE_SIZE);
    snprintf((char *)user_data->data, CSV_GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    memcpy(user_data->mnonce, nonce, CSV_GUEST_ATTESTATION_NONCE_SIZE);
    if (csv_sm3((const unsigned char *)user_data,
                CSV_GUEST_ATTESTATION_DATA_SIZE + CSV_GUEST_ATTESTATION_NONCE_SIZE,
                (unsigned char *)&user_data->hash) != 0) {
        munmap(user_data, PAGE_SIZE);
        return -4;
    }

    user_data_pa = va_to_pa((uint64_t)user_data);
    if (user_data_pa == CSV_PA_INVALID) {
        munmap(user_data, PAGE_SIZE);
        return -5;
    }

    ret = csv_hypercall(CSV_KVM_HC_VM_ATTESTATION, user_data_pa, PAGE_SIZE);
    if (ret) {
        munmap(user_data, PAGE_SIZE);
        return -6;
    }

    memcpy(&report, user_data, sizeof(report));
    munmap(user_data, PAGE_SIZE);

    if (csv_verify_session_mac(&report, nonce) != 0) {
        return -7;
    }

    memset(report.reserved2, 0, sizeof(report.reserved2));
    memcpy(report_buf, &report, sizeof(report));
    return 0;
}
