/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mldsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

#define TEST_PASSED 0
#define TEST_FAILED 1

static const char *TEST_MESSAGE = "SEED_PRIV cross-format interop test message";

static int test_standalone_to_openssl(const char *variant) {
    printf("\n--- Direction 1: Standalone -> OpenSSL [%s] ---\n", variant);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(variant);
    if (!sig) {
        printf("ERROR: Failed to create signature instance\n");
        return TEST_FAILED;
    }

    size_t pk_len = QUDO_MLDSA_get_public_key_bytes(sig);
    size_t sk_len = QUDO_MLDSA_get_secret_key_bytes(sig);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t seed[MLDSA_SEEDBYTES];
    int result = TEST_FAILED;

    if (!pk || !sk) {
        printf("ERROR: Memory allocation failed\n");
        goto cleanup;
    }

    memset(seed, 0xAB, MLDSA_SEEDBYTES);

    printf("  [1] Generate keypair from seed (standalone)...\n");
    if (QUDO_MLDSA_keypair_internal(sig, pk, sk, seed) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Keypair generation failed\n");
        goto cleanup;
    }
    printf("      pk=%zu, sk=%zu bytes\n", pk_len, sk_len);

    printf("  [2] Export SEED_PRIV DER (standalone)...\n");
    size_t seed_sk_len = MLDSA_SEEDBYTES + sk_len;
    uint8_t *seed_sk = malloc(seed_sk_len);
    if (!seed_sk) goto cleanup;
    memcpy(seed_sk, seed, MLDSA_SEEDBYTES);
    memcpy(seed_sk + MLDSA_SEEDBYTES, sk, sk_len);

    uint8_t der_buf[16384];
    size_t der_len = sizeof(der_buf);
    if (QUDO_MLDSA_export_private_key_der_format(seed_sk, seed_sk_len, der_buf, &der_len,
                                                 QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: SEED_PRIV DER export failed\n");
        free(seed_sk);
        goto cleanup;
    }
    free(seed_sk);
    printf("      DER size: %zu bytes\n", der_len);

    printf("  [3] Import DER with OpenSSL EVP (d2i_PrivateKey)...\n");
    const unsigned char *der_p = der_buf;
    EVP_PKEY *pkey = d2i_PrivateKey_ex(EVP_PKEY_NONE, NULL, &der_p, (long)der_len, NULL, NULL);
    if (!pkey) {
        printf("ERROR: OpenSSL d2i_PrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    const char *type_name = EVP_PKEY_get0_type_name(pkey);
    printf("      OpenSSL key type: %s\n", type_name ? type_name : "unknown");

    printf("  [4] Compare public keys...\n");
    uint8_t ossl_pk[4096];
    size_t ossl_pk_len = sizeof(ossl_pk);
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                          ossl_pk, sizeof(ossl_pk), &ossl_pk_len)) {
        printf("ERROR: Failed to extract pk from EVP_PKEY\n");
        EVP_PKEY_free(pkey);
        goto cleanup;
    }

    if (ossl_pk_len != pk_len || memcmp(pk, ossl_pk, pk_len) != 0) {
        printf("ERROR: pk mismatch! OpenSSL=%zu, standalone=%zu\n", ossl_pk_len, pk_len);
        EVP_PKEY_free(pkey);
        goto cleanup;
    }
    printf("      Public keys match\n");

    printf("  [5] Sign with OpenSSL EVP...\n");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL) != 1) {
        printf("ERROR: EVP_DigestSignInit failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        goto cleanup;
    }

    size_t msg_len = strlen(TEST_MESSAGE);
    size_t ossl_sig_len = 0;
    EVP_DigestSign(mdctx, NULL, &ossl_sig_len, (const unsigned char *)TEST_MESSAGE, msg_len);

    uint8_t *ossl_sig = malloc(ossl_sig_len);
    if (!ossl_sig || EVP_DigestSign(mdctx, ossl_sig, &ossl_sig_len,
                                     (const unsigned char *)TEST_MESSAGE, msg_len) != 1) {
        printf("ERROR: EVP_DigestSign failed\n");
        ERR_print_errors_fp(stderr);
        free(ossl_sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        goto cleanup;
    }
    printf("      OpenSSL signature: %zu bytes\n", ossl_sig_len);
    EVP_MD_CTX_free(mdctx);

    printf("  [6] Verify with standalone API...\n");
    if (QUDO_MLDSA_verify(sig, ossl_sig, ossl_sig_len,
                         (const uint8_t *)TEST_MESSAGE, msg_len, pk) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Standalone verify of OpenSSL signature FAILED\n");
        free(ossl_sig);
        EVP_PKEY_free(pkey);
        goto cleanup;
    }
    printf("      Standalone verified OpenSSL signature OK\n");

    free(ossl_sig);
    EVP_PKEY_free(pkey);
    result = TEST_PASSED;

cleanup:
    QUDO_MLDSA_free(sig);
    free(pk);
    free(sk);
    return result;
}

static int test_openssl_to_standalone(const char *variant) {
    printf("\n--- Direction 2: OpenSSL -> Standalone [%s] ---\n", variant);

    size_t expected_sk_len = 0, expected_pk_len = 0;
    if (strcmp(variant, "ML-DSA-44") == 0) {
        expected_sk_len = ML_DSA_44_SECRET_KEY_BYTES;
        expected_pk_len = ML_DSA_44_PUBLIC_KEY_BYTES;
    } else if (strcmp(variant, "ML-DSA-65") == 0) {
        expected_sk_len = ML_DSA_65_SECRET_KEY_BYTES;
        expected_pk_len = ML_DSA_65_PUBLIC_KEY_BYTES;
    } else if (strcmp(variant, "ML-DSA-87") == 0) {
        expected_sk_len = ML_DSA_87_SECRET_KEY_BYTES;
        expected_pk_len = ML_DSA_87_PUBLIC_KEY_BYTES;
    } else {
        printf("ERROR: Unknown variant: %s\n", variant);
        return TEST_FAILED;
    }

    int result = TEST_FAILED;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    QUDO_MLDSA *sig = NULL;
    uint8_t *sk_imported = NULL;
    uint8_t *pk_regen = NULL;

    printf("  [1] Generate ML-DSA key with OpenSSL EVP...\n");
    pctx = EVP_PKEY_CTX_new_from_name(NULL, variant, NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) != 1 || EVP_PKEY_keygen(pctx, &pkey) != 1) {
        printf("ERROR: OpenSSL keygen failed for %s\n", variant);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        return TEST_FAILED;
    }
    EVP_PKEY_CTX_free(pctx);

    const char *type_name = EVP_PKEY_get0_type_name(pkey);
    printf("      Key type: %s\n", type_name ? type_name : "unknown");

    uint8_t ossl_pk[4096];
    size_t ossl_pk_len = sizeof(ossl_pk);
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                          ossl_pk, sizeof(ossl_pk), &ossl_pk_len)) {
        printf("ERROR: Failed to extract pk from EVP_PKEY\n");
        goto cleanup2;
    }
    printf("      OpenSSL pk: %zu bytes\n", ossl_pk_len);

    printf("  [2] Export DER with i2d_PrivateKey...\n");
    int der_len = i2d_PrivateKey(pkey, NULL);
    if (der_len <= 0) {
        printf("ERROR: i2d_PrivateKey size query failed\n");
        goto cleanup2;
    }

    unsigned char *der_buf = malloc(der_len);
    if (!der_buf) goto cleanup2;
    unsigned char *der_p = der_buf;
    i2d_PrivateKey(pkey, &der_p);
    printf("      DER size: %d bytes\n", der_len);

    printf("  [3] Import with standalone library...\n");
    sk_imported = malloc(expected_sk_len + expected_pk_len);
    pk_regen = malloc(expected_pk_len);
    if (!sk_imported || !pk_regen) { free(der_buf); goto cleanup2; }

    size_t sk_imported_len = expected_sk_len + expected_pk_len;
    size_t pk_regen_len = expected_pk_len;
    QUDO_MLDSA_status_t rc = QUDO_MLDSA_import_private_key_der_format(
        der_buf, (size_t)der_len, sk_imported, &sk_imported_len,
        pk_regen, &pk_regen_len);
    free(der_buf);

    if (rc != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Standalone import failed (status=%d)\n", rc);
        goto cleanup2;
    }
    printf("      Imported sk: %zu bytes, regenerated pk: %zu bytes\n",
           sk_imported_len, pk_regen_len);

    printf("  [4] Compare public keys...\n");
    if (pk_regen_len != ossl_pk_len || memcmp(pk_regen, ossl_pk, ossl_pk_len) != 0) {
        printf("ERROR: pk mismatch! Regenerated=%zu, OpenSSL=%zu\n",
               pk_regen_len, ossl_pk_len);
        goto cleanup2;
    }
    printf("      Public keys match\n");

    printf("  [5] Sign with standalone API...\n");
    sig = QUDO_MLDSA_new(variant);
    if (!sig) { printf("ERROR: QUDO_MLDSA_new failed\n"); goto cleanup2; }

    size_t msg_len = strlen(TEST_MESSAGE);
    uint8_t standalone_sig[8192];
    size_t standalone_sig_len = sizeof(standalone_sig);

    if (QUDO_MLDSA_sign(sig, standalone_sig, &standalone_sig_len,
                       (const uint8_t *)TEST_MESSAGE, msg_len,
                       sk_imported) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Standalone sign failed\n");
        goto cleanup2;
    }
    printf("      Standalone signature: %zu bytes\n", standalone_sig_len);

    printf("  [6] Verify with OpenSSL EVP...\n");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL) != 1) {
        printf("ERROR: EVP_DigestVerifyInit failed\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        goto cleanup2;
    }

    int verify_rc = EVP_DigestVerify(mdctx, standalone_sig, standalone_sig_len,
                                      (const unsigned char *)TEST_MESSAGE, msg_len);
    EVP_MD_CTX_free(mdctx);

    if (verify_rc != 1) {
        printf("ERROR: OpenSSL verify FAILED (rc=%d)\n", verify_rc);
        ERR_print_errors_fp(stderr);
        goto cleanup2;
    }
    printf("      OpenSSL verified standalone signature OK\n");

    result = TEST_PASSED;

cleanup2:
    EVP_PKEY_free(pkey);
    QUDO_MLDSA_free(sig);
    free(sk_imported);
    free(pk_regen);
    return result;
}

int main(void) {
    int failed = 0;

    printf("===============================================================\n");
    printf("  SEED_PRIV Cross-Format Interop Test (in-process)\n");
    printf("  Standalone ML-DSA <-> OpenSSL native ML-DSA\n");
    printf("===============================================================\n");

    if (QUDO_MLDSA_init() != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Failed to initialize library\n");
        return 1;
    }

    const char *variants[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    for (int i = 0; i < 3; i++) {
        printf("\n=== %s ===\n", variants[i]);

        if (test_standalone_to_openssl(variants[i]) != TEST_PASSED) {
            printf("  FAILED: Standalone -> OpenSSL [%s]\n", variants[i]);
            failed++;
        } else {
            printf("  PASSED: Standalone -> OpenSSL [%s]\n", variants[i]);
        }

        if (test_openssl_to_standalone(variants[i]) != TEST_PASSED) {
            printf("  FAILED: OpenSSL -> Standalone [%s]\n", variants[i]);
            failed++;
        } else {
            printf("  PASSED: OpenSSL -> Standalone [%s]\n", variants[i]);
        }
    }

    QUDO_MLDSA_cleanup();

    printf("\n===============================================================\n");
    if (failed == 0) {
        printf("  ALL INTEROP TESTS PASSED (6/6)\n");
    } else {
        printf("  %d test(s) FAILED\n", failed);
    }
    printf("===============================================================\n");

    return failed ? 1 : 0;
}
