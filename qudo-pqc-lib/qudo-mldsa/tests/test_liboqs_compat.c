/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mldsa_wrapper.h"

#define TEST_PASS "\033[32mPASSED\033[0m"
#define TEST_FAIL "\033[31mFAILED\033[0m"

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test_func) do { \
    printf("  Running %s... ", #test_func); \
    fflush(stdout); \
    tests_run++; \
    if (test_func()) { \
        printf("%s\n", TEST_PASS); \
        tests_passed++; \
    } else { \
        printf("%s\n", TEST_FAIL); \
    } \
} while(0)

static int test_struct_public_members() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return 0;

    int result = (sig->method_name != NULL &&
                  strcmp(sig->method_name, "ML-DSA-65") == 0 &&
                  strcmp(sig->alg_version, "FIPS 204") == 0 &&
                  sig->claimed_nist_level == 3 &&
                  sig->euf_cma == true &&
                  sig->suf_cma == true &&
                  sig->sig_with_ctx_support == true &&
                  sig->length_public_key == 1952 &&
                  sig->length_secret_key == 4032 &&
                  sig->length_signature == 3309);

    QUDO_MLDSA_free(sig);
    return result;
}

static int test_alg_count() {
    return (QUDO_MLDSA_alg_count() == 3);
}

static int test_alg_identifier() {
    const char *alg0 = QUDO_MLDSA_alg_identifier(0);
    const char *alg1 = QUDO_MLDSA_alg_identifier(1);
    const char *alg2 = QUDO_MLDSA_alg_identifier(2);
    const char *alg3 = QUDO_MLDSA_alg_identifier(3);

    return (alg0 && strcmp(alg0, "ML-DSA-44") == 0 &&
            alg1 && strcmp(alg1, "ML-DSA-65") == 0 &&
            alg2 && strcmp(alg2, "ML-DSA-87") == 0 &&
            alg3 == NULL);
}

static int test_alg_is_enabled() {
    return (QUDO_MLDSA_alg_is_enabled("ML-DSA-44") == 1 &&
            QUDO_MLDSA_alg_is_enabled("ML-DSA-65") == 1 &&
            QUDO_MLDSA_alg_is_enabled("ML-DSA-87") == 1 &&
            QUDO_MLDSA_alg_is_enabled("Invalid") == 0 &&
            QUDO_MLDSA_alg_is_enabled(NULL) == 0);
}

static int test_supports_ctx_str() {
    return (QUDO_MLDSA_supports_ctx_str("ML-DSA-44") == 1 &&
            QUDO_MLDSA_supports_ctx_str("ML-DSA-65") == 1 &&
            QUDO_MLDSA_supports_ctx_str("ML-DSA-87") == 1 &&
            QUDO_MLDSA_supports_ctx_str("Invalid") == 0);
}

static int test_variant_metadata_44() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) return 0;

    int result = (sig->claimed_nist_level == 2 &&
                  sig->length_public_key == 1312 &&
                  sig->length_secret_key == 2560 &&
                  sig->length_signature == 2420);

    QUDO_MLDSA_free(sig);
    return result;
}

static int test_variant_metadata_87() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-87");
    if (!sig) return 0;

    int result = (sig->claimed_nist_level == 5 &&
                  sig->length_public_key == 2592 &&
                  sig->length_secret_key == 4896 &&
                  sig->length_signature == 4627);

    QUDO_MLDSA_free(sig);
    return result;
}

static int test_public_members_for_allocation() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return 0;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = sig->length_signature;

    if (!pk || !sk || !signature) {
        free(pk); free(sk); free(signature);
        QUDO_MLDSA_free(sig);
        return 0;
    }

    QUDO_MLDSA_status_t ret1 = QUDO_MLDSA_keypair(sig, pk, sk);
    const char *msg = "test";
    QUDO_MLDSA_status_t ret2 = QUDO_MLDSA_sign(sig, signature, &sig_len,
                                            (const uint8_t*)msg, strlen(msg), sk);

    int result = (ret1 == QUDO_MLDSA_SUCCESS && ret2 == QUDO_MLDSA_SUCCESS);

    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
    return result;
}

static int test_liboqs_style_iteration() {
    int count = QUDO_MLDSA_alg_count();
    int all_valid = 1;

    for (int i = 0; i < count; i++) {
        const char *alg = QUDO_MLDSA_alg_identifier(i);
        if (!alg || !QUDO_MLDSA_alg_is_enabled(alg)) {
            all_valid = 0;
            break;
        }

        QUDO_MLDSA *sig = QUDO_MLDSA_new(alg);
        if (!sig) {
            all_valid = 0;
            break;
        }

        if (strcmp(sig->method_name, alg) != 0) {
            QUDO_MLDSA_free(sig);
            all_valid = 0;
            break;
        }

        QUDO_MLDSA_free(sig);
    }

    return all_valid;
}

static int test_function_pointers_initialized() {
    const char *variants[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

    for (int i = 0; i < 3; i++) {
        QUDO_MLDSA *sig = QUDO_MLDSA_new(variants[i]);
        if (!sig) return 0;

        if (!sig->keypair || !sig->sign || !sig->verify) {
            QUDO_MLDSA_free(sig);
            return 0;
        }

        QUDO_MLDSA_free(sig);
    }

    return 1;
}

static int test_function_pointers_work() {
    QUDO_MLDSA *sig = QUDO_MLDSA_new(QUDO_MLDSA_alg_ml_dsa_65);
    if (!sig) return 0;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = sig->length_signature;

    if (!pk || !sk || !signature) {
        free(pk); free(sk); free(signature);
        QUDO_MLDSA_free(sig);
        return 0;
    }

    QUDO_MLDSA_status_t ret1 = sig->keypair(pk, sk);
    if (ret1 != QUDO_MLDSA_SUCCESS) {
        free(pk); free(sk); free(signature);
        QUDO_MLDSA_free(sig);
        return 0;
    }

    const uint8_t msg[] = "Function pointer test";
    QUDO_MLDSA_status_t ret2 = sig->sign(signature, &sig_len, msg, sizeof(msg) - 1, sk);
    if (ret2 != QUDO_MLDSA_SUCCESS) {
        free(pk); free(sk); free(signature);
        QUDO_MLDSA_free(sig);
        return 0;
    }

    QUDO_MLDSA_status_t ret3 = sig->verify(msg, sizeof(msg) - 1, signature, sig_len, pk);
    int result = (ret3 == QUDO_MLDSA_SUCCESS);

    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);

    return result;
}

static int test_algorithm_macros() {
    return (strcmp(QUDO_MLDSA_alg_ml_dsa_44, "ML-DSA-44") == 0 &&
            strcmp(QUDO_MLDSA_alg_ml_dsa_65, "ML-DSA-65") == 0 &&
            strcmp(QUDO_MLDSA_alg_ml_dsa_87, "ML-DSA-87") == 0);
}

int main(void) {

    QUDO_MLDSA_init();

    printf("\n=== liboqs Compatibility Test Suite ===\n\n");

    printf("Struct Member Tests:\n");
    RUN_TEST(test_struct_public_members);
    RUN_TEST(test_variant_metadata_44);
    RUN_TEST(test_variant_metadata_87);
    RUN_TEST(test_public_members_for_allocation);

    printf("\nUtility Function Tests:\n");
    RUN_TEST(test_alg_count);
    RUN_TEST(test_alg_identifier);
    RUN_TEST(test_alg_is_enabled);
    RUN_TEST(test_supports_ctx_str);

    printf("\nFunction Pointer Tests:\n");
    RUN_TEST(test_function_pointers_initialized);
    RUN_TEST(test_function_pointers_work);
    RUN_TEST(test_algorithm_macros);

    printf("\nIntegration Tests:\n");
    RUN_TEST(test_liboqs_style_iteration);

    printf("\n=== Test Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);

    if (tests_passed == tests_run) {
        printf("\n✓ ALL LIBOQS COMPATIBILITY TESTS PASSED\n\n");
        return 0;
    } else {
        printf("\n✗ SOME TESTS FAILED\n\n");
        return 1;
    }
}
