// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "qudo_fips_aes.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int qudo_aes_ct_set_encrypt_key(const uint8_t *userKey, int bits,
                                       qudo_aes_key_t *key);
extern void qudo_aes_ct_encrypt(const uint8_t *in, uint8_t *out,
                                const qudo_aes_key_t *key);

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) \
    || defined(_M_IX86)
#    define HAVE_NI 1
extern int qudo_aes_ni_set_encrypt_key(const uint8_t *userKey, int bits,
                                       qudo_aes_key_t *key);
extern void qudo_aes_ni_encrypt(const uint8_t *in, uint8_t *out,
                                const qudo_aes_key_t *key);
#else
#    define HAVE_NI 0
#endif

static const uint8_t k[32]
    = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
       0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
       0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
static const uint8_t pt[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                               0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
static const uint8_t expected[16]
    = {0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
       0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8};

int main(void)
{
    qudo_aes_key_t key;
    uint8_t out_ct[16];
    int fail = 0;

    if (qudo_aes_ct_set_encrypt_key(k, 256, &key) != 0) {
        printf("  CT key schedule failed\n");
        return 1;
    }
    qudo_aes_ct_encrypt(pt, out_ct, &key);
    if (memcmp(out_ct, expected, 16) != 0) {
        printf("  AES-256 constant-time backend KAT: FAIL\n");
        fail = 1;
    } else {
        printf("  AES-256 constant-time backend KAT: PASS\n");
    }

#if HAVE_NI
    {
        uint8_t out_ni[16];
        if (qudo_aes_ni_set_encrypt_key(k, 256, &key) != 0) {
            printf("  NI key schedule failed\n");
            return 1;
        }
        qudo_aes_ni_encrypt(pt, out_ni, &key);
        if (memcmp(out_ni, expected, 16) != 0) {
            printf("  AES-256 AES-NI backend KAT: FAIL\n");
            fail = 1;
        } else {
            printf("  AES-256 AES-NI backend KAT: PASS\n");
        }
        if (memcmp(out_ni, out_ct, 16) != 0) {
            printf("  AES-256 CT/NI equivalence: FAIL\n");
            fail = 1;
        } else {
            printf("  AES-256 CT/NI equivalence: PASS\n");
        }
    }
#else
    printf("  AES-NI not compiled on this target; CT backend only\n");
#endif

    printf("%s\n", fail ? "test_fips_aes_backends: FAIL"
                        : "test_fips_aes_backends: PASS");
    return fail;
}
