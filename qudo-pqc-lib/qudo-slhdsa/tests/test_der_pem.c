/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "slhdsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name, cond) do { \
    tests_run++; \
    if (cond) { tests_passed++; } \
    else { fprintf(stderr, "  FAIL: %s\n", name); } \
} while(0)

static int test_der_pem_variant(const char *alg_name) {
    fprintf(stderr, "Testing DER/PEM for %s...\n", alg_name);

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg_name);
    if (!sig) {
        fprintf(stderr, "  FAIL: QUDO_SLHDSA_new returned NULL\n");
        tests_run++;
        return 0;
    }

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    if (!pk || !sk) { free(pk); free(sk); QUDO_SLHDSA_free(sig); return 0; }

    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_keypair(sig, pk, sk);
    TEST("keypair", rc == QUDO_SLHDSA_SUCCESS);

    size_t der_pk_len = 0;
    rc = QUDO_SLHDSA_export_public_key_der(pk, sig->length_public_key, sig->param_set, NULL, &der_pk_len);
    TEST("pk_der_size", rc == QUDO_SLHDSA_SUCCESS && der_pk_len > 0);

    uint8_t *der_pk = (uint8_t *)malloc(der_pk_len);
    rc = QUDO_SLHDSA_export_public_key_der(pk, sig->length_public_key, sig->param_set, der_pk, &der_pk_len);
    TEST("pk_der_export", rc == QUDO_SLHDSA_SUCCESS);

    uint8_t pk_imported[SLH_DSA_MAX_PUBLIC_KEY_BYTES];
    size_t pk_imported_len = sizeof(pk_imported);
    rc = QUDO_SLHDSA_import_public_key_der(der_pk, der_pk_len, pk_imported, &pk_imported_len);
    TEST("pk_der_import", rc == QUDO_SLHDSA_SUCCESS);
    TEST("pk_der_roundtrip", pk_imported_len == sig->length_public_key &&
         memcmp(pk, pk_imported, pk_imported_len) == 0);
    free(der_pk);

    size_t der_sk_len = 0;
    rc = QUDO_SLHDSA_export_private_key_der(sk, sig->length_secret_key, sig->param_set, NULL, &der_sk_len);
    TEST("sk_der_size", rc == QUDO_SLHDSA_SUCCESS && der_sk_len > 0);

    uint8_t *der_sk = (uint8_t *)malloc(der_sk_len);
    rc = QUDO_SLHDSA_export_private_key_der(sk, sig->length_secret_key, sig->param_set, der_sk, &der_sk_len);
    TEST("sk_der_export", rc == QUDO_SLHDSA_SUCCESS);

    uint8_t sk_imported[SLH_DSA_MAX_SECRET_KEY_BYTES];
    size_t sk_imported_len = sizeof(sk_imported);
    rc = QUDO_SLHDSA_import_private_key_der(der_sk, der_sk_len, sk_imported, &sk_imported_len);
    TEST("sk_der_import", rc == QUDO_SLHDSA_SUCCESS);
    TEST("sk_der_roundtrip", sk_imported_len == sig->length_secret_key &&
         memcmp(sk, sk_imported, sk_imported_len) == 0);
    OPENSSL_cleanse(der_sk, der_sk_len);
    free(der_sk);

    size_t pem_pk_len = 0;
    rc = QUDO_SLHDSA_export_public_key_pem(pk, sig->length_public_key, sig->param_set, NULL, &pem_pk_len);
    TEST("pk_pem_size", rc == QUDO_SLHDSA_SUCCESS && pem_pk_len > 0);

    char *pem_pk = (char *)malloc(pem_pk_len);
    rc = QUDO_SLHDSA_export_public_key_pem(pk, sig->length_public_key, sig->param_set, pem_pk, &pem_pk_len);
    TEST("pk_pem_export", rc == QUDO_SLHDSA_SUCCESS);

    memset(pk_imported, 0, sizeof(pk_imported));
    pk_imported_len = sizeof(pk_imported);
    rc = QUDO_SLHDSA_import_public_key_pem(pem_pk, pem_pk_len, pk_imported, &pk_imported_len);
    TEST("pk_pem_import", rc == QUDO_SLHDSA_SUCCESS);
    TEST("pk_pem_roundtrip", pk_imported_len == sig->length_public_key &&
         memcmp(pk, pk_imported, pk_imported_len) == 0);
    free(pem_pk);

    size_t pem_sk_len = 0;
    rc = QUDO_SLHDSA_export_private_key_pem(sk, sig->length_secret_key, sig->param_set, NULL, &pem_sk_len);
    TEST("sk_pem_size", rc == QUDO_SLHDSA_SUCCESS && pem_sk_len > 0);

    char *pem_sk = (char *)malloc(pem_sk_len);
    rc = QUDO_SLHDSA_export_private_key_pem(sk, sig->length_secret_key, sig->param_set, pem_sk, &pem_sk_len);
    TEST("sk_pem_export", rc == QUDO_SLHDSA_SUCCESS);

    memset(sk_imported, 0, sizeof(sk_imported));
    sk_imported_len = sizeof(sk_imported);
    rc = QUDO_SLHDSA_import_private_key_pem(pem_sk, pem_sk_len, sk_imported, &sk_imported_len);
    TEST("sk_pem_import", rc == QUDO_SLHDSA_SUCCESS);
    TEST("sk_pem_roundtrip", sk_imported_len == sig->length_secret_key &&
         memcmp(sk, sk_imported, sk_imported_len) == 0);
    OPENSSL_cleanse(pem_sk, pem_sk_len);
    free(pem_sk);

    uint8_t *test_sig = (uint8_t *)malloc(sig->length_signature);
    const uint8_t msg[] = "DER/PEM round-trip verification";
    size_t msg_len = sizeof(msg) - 1;
    size_t test_sig_len = sig->length_signature;

    rc = QUDO_SLHDSA_sign(sig, test_sig, &test_sig_len, msg, msg_len, sk_imported);
    TEST("cross_sign", rc == QUDO_SLHDSA_SUCCESS);

    rc = QUDO_SLHDSA_verify(sig, msg, msg_len, test_sig, test_sig_len, pk_imported);
    TEST("cross_verify", rc == QUDO_SLHDSA_SUCCESS);

    free(test_sig);

    fprintf(stderr, "  %s: OK\n", alg_name);

    OPENSSL_cleanse(sk, sig->length_secret_key);
    OPENSSL_cleanse(sk_imported, sizeof(sk_imported));
    free(pk);
    free(sk);
    QUDO_SLHDSA_free(sig);
    return 1;
}

int main(void) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    fprintf(stderr, "\n=== QUDO SLH-DSA DER/PEM Test Suite ===\n\n");

    const char *algorithms[] = {
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-256f",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHA2-256s",
        "SLH-DSA-SHAKE-256s",
    };

    for (int i = 0; i < 12; i++) {
        test_der_pem_variant(algorithms[i]);
    }

    fprintf(stderr, "\n=== Results: %d/%d tests passed ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
