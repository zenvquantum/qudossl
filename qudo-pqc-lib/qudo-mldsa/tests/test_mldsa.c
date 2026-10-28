/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/crypto.h>
#include "mldsa_wrapper.h"

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test) do { \
    tests_run++; \
    printf("  Running %s...", #test); \
    if (test()) { \
        printf(" PASSED\n"); \
        tests_passed++; \
    } else { \
        printf(" FAILED\n"); \
    } \
} while(0)

static int test_mldsa44_direct() {
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t sig[ML_DSA_44_SIGNATURE_BYTES];
    size_t sig_len;

    const char *msg = "Test message for ML-DSA-44";

    if (QUDO_MLDSA_ML_DSA_44_keypair(pk, sk) != QUDO_MLDSA_SUCCESS) {
        return 0;
    }

    if (QUDO_MLDSA_ML_DSA_44_sign(sig, &sig_len, (const uint8_t*)msg,
                                 strlen(msg), sk) != QUDO_MLDSA_SUCCESS) {
        return 0;
    }

    if (QUDO_MLDSA_ML_DSA_44_verify(sig, sig_len, (const uint8_t*)msg,
                                   strlen(msg), pk) != QUDO_MLDSA_SUCCESS) {
        return 0;
    }

    sig[0] ^= 1;
    if (QUDO_MLDSA_ML_DSA_44_verify(sig, sig_len, (const uint8_t*)msg,
                                   strlen(msg), pk) == QUDO_MLDSA_SUCCESS) {
        return 0;
    }

    return 1;
}

static int test_mldsa65_direct() {
    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len;

    const char *msg = "Test message for ML-DSA-65";

    if (QUDO_MLDSA_ML_DSA_65_keypair(pk, sk) != QUDO_MLDSA_SUCCESS) return 0;
    if (QUDO_MLDSA_ML_DSA_65_sign(sig, &sig_len, (const uint8_t*)msg,
                                 strlen(msg), sk) != QUDO_MLDSA_SUCCESS) return 0;
    if (QUDO_MLDSA_ML_DSA_65_verify(sig, sig_len, (const uint8_t*)msg,
                                   strlen(msg), pk) != QUDO_MLDSA_SUCCESS) return 0;

    return 1;
}

static int test_mldsa87_direct() {
    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
    uint8_t sig[ML_DSA_87_SIGNATURE_BYTES];
    size_t sig_len;

    const char *msg = "Test message for ML-DSA-87";

    if (QUDO_MLDSA_ML_DSA_87_keypair(pk, sk) != QUDO_MLDSA_SUCCESS) return 0;
    if (QUDO_MLDSA_ML_DSA_87_sign(sig, &sig_len, (const uint8_t*)msg,
                                 strlen(msg), sk) != QUDO_MLDSA_SUCCESS) return 0;
    if (QUDO_MLDSA_ML_DSA_87_verify(sig, sig_len, (const uint8_t*)msg,
                                   strlen(msg), pk) != QUDO_MLDSA_SUCCESS) return 0;

    return 1;
}

static int test_object_api() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return 0;

    uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t signature[ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len = sizeof(signature);

    const char *msg = "Object API test";

    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (QUDO_MLDSA_sign(sig, signature, &sig_len, (const uint8_t*)msg,
                      strlen(msg), sk) != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (QUDO_MLDSA_verify(sig, signature, sig_len, (const uint8_t*)msg,
                        strlen(msg), pk) != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    QUDO_MLDSA_free(sig);
    return 1;
}

static int test_context_strings() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) return 0;

    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t signature[ML_DSA_44_SIGNATURE_BYTES];
    size_t sig_len = sizeof(signature);

    const char *msg = "Context test";
    const char *ctx = "test-context-v1";

    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (QUDO_MLDSA_sign_with_context(sig, signature, &sig_len,
                                    (const uint8_t*)msg, strlen(msg),
                                    (const uint8_t*)ctx, strlen(ctx),
                                    sk) != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (QUDO_MLDSA_verify_with_context(sig, signature, sig_len,
                                      (const uint8_t*)msg, strlen(msg),
                                      (const uint8_t*)ctx, strlen(ctx),
                                      pk) != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    const char *wrong_ctx = "wrong-context";
    if (QUDO_MLDSA_verify_with_context(sig, signature, sig_len,
                                      (const uint8_t*)msg, strlen(msg),
                                      (const uint8_t*)wrong_ctx, strlen(wrong_ctx),
                                      pk) == QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    QUDO_MLDSA_free(sig);
    return 1;
}

static int test_utility_functions() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return 0;

    if (QUDO_MLDSA_get_public_key_bytes(sig) != ML_DSA_65_PUBLIC_KEY_BYTES) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (QUDO_MLDSA_get_secret_key_bytes(sig) != ML_DSA_65_SECRET_KEY_BYTES) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (QUDO_MLDSA_get_signature_bytes(sig) != ML_DSA_65_SIGNATURE_BYTES) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (strcmp(QUDO_MLDSA_get_algorithm_name(sig), "ML-DSA-65") != 0) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    if (QUDO_MLDSA_get_security_level(sig) != QUDO_MLDSA_65) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    QUDO_MLDSA_free(sig);
    return 1;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    QUDO_MLDSA_init();

    printf("=== QUDO ML-DSA Test Suite ===\n\n");

    RUN_TEST(test_mldsa44_direct);
    RUN_TEST(test_mldsa65_direct);
    RUN_TEST(test_mldsa87_direct);
    RUN_TEST(test_object_api);
    RUN_TEST(test_context_strings);
    RUN_TEST(test_utility_functions);

    printf("\n=== Test Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);

    int ret;
    if (tests_passed == tests_run) {
        printf("\n✓ ALL TESTS PASSED\n");
        ret = 0;
    } else {
        printf("\n✗ SOME TESTS FAILED\n");
        ret = 1;
    }
    OPENSSL_cleanup();
    return ret;
}
