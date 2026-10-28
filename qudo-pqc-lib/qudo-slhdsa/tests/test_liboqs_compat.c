/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/slhdsa_wrapper.h"

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

static int test_struct_public_members(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128s");
    if (!sig) return 0;

    int result = (sig->method_name != NULL &&
                  strcmp(sig->method_name, "SLH-DSA-SHA2-128s") == 0 &&
                  strcmp(sig->alg_version, "FIPS 205") == 0 &&
                  sig->claimed_nist_level == 1 &&
                  sig->euf_cma == true &&
                  sig->suf_cma == false &&
                  sig->sig_with_ctx_support == true &&
                  sig->length_public_key == 32 &&
                  sig->length_secret_key == 64 &&
                  sig->length_signature == 7856);

    QUDO_SLHDSA_free(sig);
    return result;
}

static int test_alg_count(void) {
    return (QUDO_SLHDSA_alg_count() == 12);
}

static int test_alg_identifier(void) {
    const char *alg0 = QUDO_SLHDSA_alg_identifier(0);
    const char *alg11 = QUDO_SLHDSA_alg_identifier(11);
    const char *alg12 = QUDO_SLHDSA_alg_identifier(12);

    return (alg0 && strcmp(alg0, "SLH-DSA-SHA2-128s") == 0 &&
            alg11 && strcmp(alg11, "SLH-DSA-SHAKE-256f") == 0 &&
            alg12 == NULL);
}

static int test_alg_is_enabled(void) {
    return (QUDO_SLHDSA_alg_is_enabled("SLH-DSA-SHA2-128s") == 1 &&
            QUDO_SLHDSA_alg_is_enabled("SLH-DSA-SHA2-256f") == 1 &&
            QUDO_SLHDSA_alg_is_enabled("SLH-DSA-SHAKE-128f") == 1 &&
            QUDO_SLHDSA_alg_is_enabled("Invalid") == 0 &&
            QUDO_SLHDSA_alg_is_enabled(NULL) == 0);
}

static int test_init_cleanup(void) {
    QUDO_SLHDSA_status_t ret = QUDO_SLHDSA_init();
    if (ret != QUDO_SLHDSA_SUCCESS) return 0;

    if (!QUDO_SLHDSA_is_initialized()) return 0;

    QUDO_SLHDSA_cleanup();
    if (QUDO_SLHDSA_is_initialized()) return 0;

    return 1;
}

static int test_version_info(void) {
    const char *ver = QUDO_SLHDSA_get_version();
    const char *plat = QUDO_SLHDSA_get_platform();
    const char *arch = QUDO_SLHDSA_get_architecture();
    const char *feat = QUDO_SLHDSA_get_features();

    return (ver && strcmp(ver, "1.0.0") == 0 &&
            plat && strlen(plat) > 0 &&
            arch && strlen(arch) > 0 &&
            feat && strlen(feat) > 0);
}

static int test_error_string(void) {
    const char *s1 = QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_SUCCESS);
    const char *s2 = QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_ERROR_VERIFY);
    const char *s3 = QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_ERROR_NULL_PTR);

    return (s1 && strcmp(s1, "success") == 0 &&
            s2 && strcmp(s2, "verification failed") == 0 &&
            s3 && strcmp(s3, "null pointer") == 0);
}

static int test_security_level(void) {
    return (QUDO_SLHDSA_get_security_level(QUDO_SLHDSA_SHA2_128s) == 1 &&
            QUDO_SLHDSA_get_security_level(QUDO_SLHDSA_SHA2_192s) == 3 &&
            QUDO_SLHDSA_get_security_level(QUDO_SLHDSA_SHA2_256s) == 5 &&
            QUDO_SLHDSA_get_security_level(QUDO_SLHDSA_SHAKE_128f) == 1 &&
            QUDO_SLHDSA_get_security_level(QUDO_SLHDSA_SHAKE_256f) == 5);
}

static int test_platform_support(void) {
    return (QUDO_SLHDSA_is_platform_supported() == 1 &&
            QUDO_SLHDSA_get_cpu_count() >= 1 &&
            QUDO_SLHDSA_get_cache_line_size() >= 32);
}

static int test_all_algorithms(void) {
    for (int i = 0; i < QUDO_SLHDSA_alg_count(); i++) {
        const char *name = QUDO_SLHDSA_alg_identifier(i);
        if (!name) return 0;

        QUDO_SLHDSA *sig = QUDO_SLHDSA_new(name);
        if (!sig) {
            printf("\n    Failed to create %s", name);
            return 0;
        }

        if (sig->length_public_key == 0 || sig->length_secret_key == 0 ||
            sig->length_signature == 0) {
            QUDO_SLHDSA_free(sig);
            return 0;
        }

        QUDO_SLHDSA_free(sig);
    }
    return 1;
}

int main(void) {
    printf("=== SLH-DSA liboqs Compatibility Tests ===\n\n");

    RUN_TEST(test_struct_public_members);
    RUN_TEST(test_alg_count);
    RUN_TEST(test_alg_identifier);
    RUN_TEST(test_alg_is_enabled);
    RUN_TEST(test_init_cleanup);
    RUN_TEST(test_version_info);
    RUN_TEST(test_error_string);
    RUN_TEST(test_security_level);
    RUN_TEST(test_platform_support);
    RUN_TEST(test_all_algorithms);

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
