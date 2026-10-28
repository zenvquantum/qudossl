/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "slhdsa_wrapper.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, label)                          \
    do {                                            \
        if (cond) {                                 \
            g_pass++;                               \
        } else {                                    \
            g_fail++;                               \
            fprintf(stderr, "  FAIL: %s\n", label); \
        }                                           \
    } while (0)

#define PEM_BUF_SZ 32768

static void verify_pubkey_pem(const char *expected_alg, const char *pem,
                              size_t pem_len)
{
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) {
        g_fail++;
        fprintf(stderr, "  FAIL: BIO_new_mem_buf\n");
        return;
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        g_fail++;
        fprintf(stderr, "  FAIL: PEM_read_bio_PUBKEY for %s\n", expected_alg);
        return;
    }

    const char *alg = EVP_PKEY_get0_type_name(pkey);
    if (alg && strcmp(alg, expected_alg) == 0) {
        g_pass++;
        fprintf(stderr, "  PASS: OpenSSL parsed our PEM as %s\n", alg);
    } else {
        g_fail++;
        fprintf(stderr, "  FAIL: expected %s, OpenSSL got %s\n", expected_alg,
                alg ? alg : "(null)");
    }
    EVP_PKEY_free(pkey);
}

static void verify_privkey_pem(const char *expected_alg, const char *pem,
                               size_t pem_len)
{
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) {
        g_fail++;
        fprintf(stderr, "  FAIL: BIO_new_mem_buf\n");
        return;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        g_fail++;
        fprintf(stderr, "  FAIL: PEM_read_bio_PrivateKey for %s\n",
                expected_alg);
        return;
    }

    const char *alg = EVP_PKEY_get0_type_name(pkey);
    if (alg && strcmp(alg, expected_alg) == 0) {
        g_pass++;
        fprintf(stderr, "  PASS: OpenSSL parsed our private PEM as %s\n", alg);
    } else {
        g_fail++;
        fprintf(stderr, "  FAIL: expected %s, OpenSSL got %s\n", expected_alg,
                alg ? alg : "(null)");
    }
    EVP_PKEY_free(pkey);
}

static void test_slhdsa(const char *alg, QUDO_SLHDSA_parameter_set_t ps)
{
    fprintf(stderr, "[%s]\n", alg);

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg);
    if (!sig) {
        g_fail++;
        fprintf(stderr, "  FAIL: SLHDSA_new\n");
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    char *pem = (char *)malloc(PEM_BUF_SZ);
    if (!pk || !sk || !pem) {
        g_fail++;
        goto cleanup;
    }

    if (QUDO_SLHDSA_keypair(sig, pk, sk) != QUDO_SLHDSA_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: keypair\n");
        goto cleanup;
    }

    size_t pem_len = PEM_BUF_SZ;
    if (QUDO_SLHDSA_export_public_key_pem(pk, sig->length_public_key, ps, pem,
                                          &pem_len)
        != QUDO_SLHDSA_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: export public PEM\n");
        goto cleanup;
    }
    verify_pubkey_pem(alg, pem, pem_len);

    pem_len = PEM_BUF_SZ;
    if (QUDO_SLHDSA_export_private_key_pem(sk, sig->length_secret_key, ps, pem,
                                           &pem_len)
        != QUDO_SLHDSA_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: export private PEM\n");
        goto cleanup;
    }
    verify_privkey_pem(alg, pem, pem_len);

cleanup:
    free(pk);
    free(sk);
    free(pem);
    QUDO_SLHDSA_free(sig);
}

static void test_mldsa(const char *alg)
{
    fprintf(stderr, "[%s]\n", alg);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(alg);
    if (!sig) {
        g_fail++;
        fprintf(stderr, "  FAIL: MLDSA_new\n");
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    char *pem = (char *)malloc(PEM_BUF_SZ);
    if (!pk || !sk || !pem) {
        g_fail++;
        goto cleanup;
    }

    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: keypair\n");
        goto cleanup;
    }

    size_t pem_len = PEM_BUF_SZ;
    if (QUDO_MLDSA_export_public_key_pem(pk, sig->length_public_key, pem,
                                         &pem_len)
        != QUDO_MLDSA_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: export public PEM\n");
        goto cleanup;
    }
    verify_pubkey_pem(alg, pem, pem_len);

    pem_len = PEM_BUF_SZ;
    if (QUDO_MLDSA_export_private_key_pem(sk, sig->length_secret_key, pem,
                                          &pem_len)
        != QUDO_MLDSA_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: export private PEM\n");
        goto cleanup;
    }
    verify_privkey_pem(alg, pem, pem_len);

cleanup:
    free(pk);
    free(sk);
    free(pem);
    QUDO_MLDSA_free(sig);
}

static void test_mlkem(const char *alg)
{
    fprintf(stderr, "[%s]\n", alg);

    QUDO_KEM *kem = QUDO_KEM_new(alg);
    if (!kem) {
        g_fail++;
        fprintf(stderr, "  FAIL: KEM_new\n");
        return;
    }

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
    char *pem = (char *)malloc(PEM_BUF_SZ);
    if (!pk || !sk || !pem) {
        g_fail++;
        goto cleanup;
    }

    if (QUDO_KEM_keypair(kem, pk, sk) != QUDO_KEM_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: keypair\n");
        goto cleanup;
    }

    size_t pem_len = PEM_BUF_SZ;
    if (QUDO_KEM_export_public_key_pem(pk, kem->length_public_key, pem,
                                       &pem_len)
        != QUDO_KEM_SUCCESS) {
        g_fail++;
        fprintf(stderr, "  FAIL: export public PEM\n");
        goto cleanup;
    }
    verify_pubkey_pem(alg, pem, pem_len);
    /* No private-key PEM export exists for ML-KEM. */

cleanup:
    free(pk);
    free(sk);
    free(pem);
    QUDO_KEM_free(kem);
}

int main(void)
{
    qudo_pqc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.conditional_errors = 1;
    if (qudo_pqc_init(&cfg) != 1) {
        fprintf(stderr, "FIPS init failed\n");
        return 1;
    }

    fprintf(stderr, "=== OpenSSL PEM interop validation ===\n\n");

    static const char *mldsa[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    for (size_t i = 0; i < 3; i++)
        test_mldsa(mldsa[i]);

    static const char *mlkem[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    for (size_t i = 0; i < 3; i++)
        test_mlkem(mlkem[i]);

    /* The s-variants are omitted for run time. */
    test_slhdsa("SLH-DSA-SHA2-128f", QUDO_SLHDSA_SHA2_128f);
    test_slhdsa("SLH-DSA-SHA2-256f", QUDO_SLHDSA_SHA2_256f);
    test_slhdsa("SLH-DSA-SHAKE-128f", QUDO_SLHDSA_SHAKE_128f);
    test_slhdsa("SLH-DSA-SHAKE-256f", QUDO_SLHDSA_SHAKE_256f);

    qudo_pqc_fini();

    fprintf(stderr, "\n=== OpenSSL PEM Interop: %d pass, %d fail ===\n", g_pass,
            g_fail);
    return g_fail == 0 ? 0 : 1;
}
