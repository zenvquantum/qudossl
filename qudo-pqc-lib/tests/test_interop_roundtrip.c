/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            failures++;                         \
        }                                       \
    } while (0)

static void test_mlkem_der_roundtrip(void)
{
    uint8_t pk[ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_KEM_768_SECRET_KEY_BYTES];
    uint8_t der[ML_KEM_768_PUBLIC_KEY_BYTES + 64];
    uint8_t pk_out[ML_KEM_768_PUBLIC_KEY_BYTES];
    size_t der_len = sizeof(der);
    size_t pk_out_len = sizeof(pk_out);

    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
    CHECK(kem != NULL, "mlkem QUDO_KEM_new");
    if (!kem)
        return;
    CHECK(QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS, "mlkem keypair");
    QUDO_KEM_free(kem);
    CHECK(QUDO_KEM_export_public_key_der(pk, sizeof(pk), der, &der_len)
              == QUDO_KEM_SUCCESS,
          "mlkem export DER");
    CHECK(der_len > 0 && der_len <= sizeof(der), "mlkem DER size");
    CHECK(QUDO_KEM_import_public_key_der(der, der_len, pk_out, &pk_out_len)
              == QUDO_KEM_SUCCESS,
          "mlkem import DER");
    CHECK(pk_out_len == sizeof(pk), "mlkem import pk size matches");
    CHECK(memcmp(pk, pk_out, sizeof(pk)) == 0, "mlkem roundtrip bytes match");

    CHECK(QUDO_KEM_export_public_key_der(NULL, sizeof(pk), der, &der_len)
              == QUDO_KEM_ERROR_NULL_PTR,
          "mlkem export NULL pk");
    CHECK(QUDO_KEM_import_public_key_der(NULL, der_len, pk_out, &pk_out_len)
              == QUDO_KEM_ERROR_NULL_PTR,
          "mlkem import NULL der");

    size_t small = 1;
    CHECK(QUDO_KEM_export_public_key_der(pk, sizeof(pk), der, &small)
              == QUDO_KEM_ERROR_BUFFER_TOO_SMALL,
          "mlkem export buffer-too-small");
}

static void test_mldsa_der_roundtrip(void)
{
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t der[ML_DSA_44_PUBLIC_KEY_BYTES + 64];
    uint8_t pk_out[ML_DSA_44_PUBLIC_KEY_BYTES];
    size_t der_len = sizeof(der);
    size_t pk_out_len = sizeof(pk_out);

    CHECK(QUDO_MLDSA_ML_DSA_44_keypair(pk, sk) == QUDO_MLDSA_SUCCESS,
          "mldsa keypair");
    CHECK(QUDO_MLDSA_export_public_key_der(pk, sizeof(pk), der, &der_len)
              == QUDO_MLDSA_SUCCESS,
          "mldsa export DER");
    CHECK(der_len > 0 && der_len <= sizeof(der), "mldsa DER size");
    CHECK(QUDO_MLDSA_import_public_key_der(der, der_len, pk_out, &pk_out_len)
              == QUDO_MLDSA_SUCCESS,
          "mldsa import DER");
    CHECK(pk_out_len == sizeof(pk), "mldsa import pk size matches");
    CHECK(memcmp(pk, pk_out, sizeof(pk)) == 0, "mldsa roundtrip bytes match");

    CHECK(QUDO_MLDSA_export_public_key_der(NULL, sizeof(pk), der, &der_len)
              == QUDO_MLDSA_ERROR_NULL_PTR,
          "mldsa export NULL pk");
    CHECK(QUDO_MLDSA_import_public_key_der(NULL, der_len, pk_out, &pk_out_len)
              == QUDO_MLDSA_ERROR_NULL_PTR,
          "mldsa import NULL der");

    size_t small = 1;
    der_len = sizeof(der);
    CHECK(QUDO_MLDSA_export_public_key_der(pk, sizeof(pk), der, &small)
              == QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL,
          "mldsa export buffer-too-small");
}

static void test_slhdsa_der_roundtrip(void)
{
    uint8_t pk[SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES];
    uint8_t sk[SLH_DSA_SHA2_128F_SECRET_KEY_BYTES];
    uint8_t der[SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES + 64];
    uint8_t pk_out[SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES];
    size_t der_len = sizeof(der);
    size_t pk_out_len = sizeof(pk_out);

    CHECK(QUDO_SLHDSA_SHA2_128f_keypair(pk, sk) == QUDO_SLHDSA_SUCCESS,
          "slhdsa keypair");
    CHECK(QUDO_SLHDSA_export_public_key_der(
              pk, sizeof(pk), QUDO_SLHDSA_SHA2_128f, der, &der_len)
              == QUDO_SLHDSA_SUCCESS,
          "slhdsa export DER");
    CHECK(der_len > 0 && der_len <= sizeof(der), "slhdsa DER size");
    CHECK(QUDO_SLHDSA_import_public_key_der(der, der_len, pk_out, &pk_out_len)
              == QUDO_SLHDSA_SUCCESS,
          "slhdsa import DER");
    CHECK(pk_out_len == sizeof(pk), "slhdsa import pk size matches");
    CHECK(memcmp(pk, pk_out, sizeof(pk)) == 0, "slhdsa roundtrip bytes match");

    CHECK(QUDO_SLHDSA_export_public_key_der(
              NULL, sizeof(pk), QUDO_SLHDSA_SHA2_128f, der, &der_len)
              == QUDO_SLHDSA_ERROR_NULL_PTR,
          "slhdsa export NULL pk");

    size_t small = 1;
    CHECK(QUDO_SLHDSA_export_public_key_der(pk, sizeof(pk),
                                            QUDO_SLHDSA_SHA2_128f, der, &small)
              == QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL,
          "slhdsa export buffer-too-small");
}

static void test_malformed_huge_length_der(void)
{
    /* Long-form length claiming ~4 GB inside an 8-byte buffer. */
    static const uint8_t huge[]
        = {0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xF0, 0x01, 0x02};
    uint8_t pk_out[64];
    size_t pk_out_len;

    pk_out_len = sizeof(pk_out);
    CHECK(
        QUDO_KEM_import_public_key_der(huge, sizeof(huge), pk_out, &pk_out_len)
            != QUDO_KEM_SUCCESS,
        "mlkem rejects huge-length DER");
    pk_out_len = sizeof(pk_out);
    CHECK(QUDO_MLDSA_import_public_key_der(huge, sizeof(huge), pk_out,
                                           &pk_out_len)
              != QUDO_MLDSA_SUCCESS,
          "mldsa rejects huge-length DER");
    pk_out_len = sizeof(pk_out);
    CHECK(QUDO_SLHDSA_import_public_key_der(huge, sizeof(huge), pk_out,
                                            &pk_out_len)
              != QUDO_SLHDSA_SUCCESS,
          "slhdsa rejects huge-length DER");
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    if (!test_fips_init()) {
        fprintf(stderr, "FAIL: test_fips_init\n");
        return 1;
    }

    test_mlkem_der_roundtrip();
    test_mldsa_der_roundtrip();
    test_slhdsa_der_roundtrip();
    test_malformed_huge_length_der();

    if (failures == 0) {
        printf("test_interop_roundtrip: ALL PASS\n");
        return 0;
    }
    printf("test_interop_roundtrip: %d FAIL\n", failures);
    return 1;
}
