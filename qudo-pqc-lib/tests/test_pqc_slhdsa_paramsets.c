/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;
static int g_verbose = 0;

#define CHECK(cond, msg)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("    FAIL: %s (line %d)\n", msg, __LINE__); \
            return 0;                                          \
        }                                                      \
        if (g_verbose)                                         \
            printf("    OK: %s\n", msg);                       \
    } while (0)

#define RUN_TEST(fn)                       \
    do {                                   \
        if (g_verbose)                     \
            printf("  %s:\n", #fn);        \
        int _r = fn();                     \
        if (_r) {                          \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else {                           \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        }                                  \
    } while (0)

static int test_all_paramsets_roundtrip(void)
{
    int count = QUDO_SLHDSA_alg_count();
    CHECK(count == 12, "alg_count == 12");

    int i;
    for (i = 0; i < count; i++) {
        const char *alg = QUDO_SLHDSA_alg_identifier((size_t)i);
        CHECK(alg != NULL, "alg_identifier non-null");

        if (g_verbose)
            printf("    [%2d/12] %s\n", i + 1, alg);

        QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg);
        CHECK(sig != NULL, "QUDO_SLHDSA_new");
        CHECK(sig->length_public_key > 0, "length_public_key > 0");
        CHECK(sig->length_secret_key > 0, "length_secret_key > 0");
        CHECK(sig->length_signature > 0, "length_signature > 0");
        CHECK(strcmp(sig->method_name, alg) == 0, "method_name matches");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");

        CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS,
              "keypair");

        const uint8_t msg[] = "FIPS 205 paramset roundtrip";
        size_t sig_len = sig->length_signature;

        CHECK(
            QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, sizeof(msg) - 1, sk)
                == QUDO_SLHDSA_SUCCESS,
            "sign");
        CHECK(sig_len > 0 && sig_len <= sig->length_signature,
              "sig_len in range");
        CHECK(QUDO_SLHDSA_verify(sig, msg, sizeof(msg) - 1, signature, sig_len,
                                 pk)
                  == QUDO_SLHDSA_SUCCESS,
              "verify");

        signature[sig_len / 2] ^= 0xA5;
        CHECK(QUDO_SLHDSA_verify(sig, msg, sizeof(msg) - 1, signature, sig_len,
                                 pk)
                  != QUDO_SLHDSA_SUCCESS,
              "tampered sig rejected");

        free(pk);
        free(sk);
        free(signature);
        QUDO_SLHDSA_free(sig);
    }
    return 1;
}

static int test_context_string_roundtrip(void)
{

    static const char *algs[] = {
        "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256f",
    };
    size_t n = sizeof(algs) / sizeof(algs[0]);
    size_t i;

    for (i = 0; i < n; i++) {
        QUDO_SLHDSA *sig = QUDO_SLHDSA_new(algs[i]);
        CHECK(sig != NULL, "QUDO_SLHDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");

        CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS,
              "keypair");

        const uint8_t msg[] = "ctx-string roundtrip";
        const uint8_t ctx[] = "application-domain";
        size_t sig_len = sig->length_signature;

        CHECK(QUDO_SLHDSA_sign_with_ctx_str(sig, signature, &sig_len, msg,
                                            sizeof(msg) - 1, ctx,
                                            sizeof(ctx) - 1, sk)
                  == QUDO_SLHDSA_SUCCESS,
              "sign_with_ctx_str");
        CHECK(QUDO_SLHDSA_verify_with_ctx_str(sig, msg, sizeof(msg) - 1,
                                              signature, sig_len, ctx,
                                              sizeof(ctx) - 1, pk)
                  == QUDO_SLHDSA_SUCCESS,
              "verify_with_ctx_str");

        const uint8_t ctx_wrong[] = "different-domain";
        CHECK(QUDO_SLHDSA_verify_with_ctx_str(sig, msg, sizeof(msg) - 1,
                                              signature, sig_len, ctx_wrong,
                                              sizeof(ctx_wrong) - 1, pk)
                  != QUDO_SLHDSA_SUCCESS,
              "ctx mismatch rejected");

        free(pk);
        free(sk);
        free(signature);
        QUDO_SLHDSA_free(sig);
    }
    return 1;
}

static int test_ctx_str_indicator_gate(void)
{
    const char *alg = "SLH-DSA-SHA2-128f";
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg);
    CHECK(sig != NULL, "new SHA2-128f");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");

    CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS, "keypair");

    const uint8_t msg[] = "indicator gate";
    const uint8_t ctx[] = "ctx";
    size_t sig_len = sig->length_signature;

    CHECK(QUDO_SLHDSA_sign_with_ctx_str(sig, signature, &sig_len, msg,
                                        sizeof(msg) - 1, ctx, sizeof(ctx) - 1,
                                        sk)
              == QUDO_SLHDSA_SUCCESS,
          "ctx-str sign ok at min level 1");
    CHECK(QUDO_SLHDSA_verify_with_ctx_str(sig, msg, sizeof(msg) - 1, signature,
                                          sig_len, ctx, sizeof(ctx) - 1, pk)
              == QUDO_SLHDSA_SUCCESS,
          "ctx-str verify ok at min level 1");

    qudo_pqc_set_min_security_level(5);

#ifdef QUDO_FIPS_MODULE
    {
        size_t sl = sig->length_signature;
        QUDO_SLHDSA_status_t s_ref
            = QUDO_SLHDSA_sign(sig, signature, &sl, msg, sizeof(msg) - 1, sk);
        sl = sig->length_signature;
        QUDO_SLHDSA_status_t s_ctx = QUDO_SLHDSA_sign_with_ctx_str(
            sig, signature, &sl, msg, sizeof(msg) - 1, ctx, sizeof(ctx) - 1,
            sk);
        CHECK(s_ref != QUDO_SLHDSA_SUCCESS, "plain sign gated at min level 5");
        CHECK(s_ctx != QUDO_SLHDSA_SUCCESS,
              "ctx-str sign gated at min level 5 (IND_CHECK present)");
        CHECK(s_ref == s_ctx, "ctx-str sign consistent with plain sign");

        QUDO_SLHDSA_status_t v_ctx = QUDO_SLHDSA_verify_with_ctx_str(
            sig, msg, sizeof(msg) - 1, signature, sig_len, ctx, sizeof(ctx) - 1,
            pk);
        CHECK(v_ctx != QUDO_SLHDSA_SUCCESS,
              "ctx-str verify gated at min level 5 (IND_CHECK present)");
    }
#endif

    qudo_pqc_set_min_security_level(1);
    sig_len = sig->length_signature;
    CHECK(QUDO_SLHDSA_sign_with_ctx_str(sig, signature, &sig_len, msg,
                                        sizeof(msg) - 1, ctx, sizeof(ctx) - 1,
                                        sk)
              == QUDO_SLHDSA_SUCCESS,
          "ctx-str sign ok again after min level reset");

    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return 1;
}

static int test_invalid_algorithm_names(void)
{
    CHECK(QUDO_SLHDSA_new(NULL) == NULL, "new(NULL) returns NULL");
    CHECK(QUDO_SLHDSA_new("") == NULL, "new(\"\") returns NULL");
    CHECK(QUDO_SLHDSA_new("SLH-DSA-INVALID") == NULL,
          "new(invalid) returns NULL");
    CHECK(QUDO_SLHDSA_new("ML-DSA-44") == NULL,
          "new(wrong family) returns NULL");

    CHECK(QUDO_SLHDSA_new("slh-dsa-sha2-128f") == NULL,
          "new(lowercase) returns NULL");
    return 1;
}

static int test_alg_registry_bounds(void)
{
    int count = QUDO_SLHDSA_alg_count();
    CHECK(count == 12, "alg_count == 12");

    int i;
    for (i = 0; i < count; i++) {
        const char *alg = QUDO_SLHDSA_alg_identifier((size_t)i);
        CHECK(alg != NULL, "alg_identifier in-range");
        CHECK(QUDO_SLHDSA_alg_is_enabled(alg) == 1, "alg_is_enabled true");
    }

    CHECK(QUDO_SLHDSA_alg_identifier((size_t)count) == NULL,
          "alg_identifier out-of-range returns NULL");
    CHECK(QUDO_SLHDSA_alg_identifier((size_t)(count + 100)) == NULL,
          "alg_identifier far out-of-range returns NULL");

    CHECK(QUDO_SLHDSA_alg_is_enabled("SLH-DSA-NOT-REAL") == 0,
          "alg_is_enabled unknown = 0");
    CHECK(QUDO_SLHDSA_alg_is_enabled(NULL) == 0, "alg_is_enabled NULL = 0");
    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--roundtrip|--context|--negative|--registry] "
           "[-v]\n",
           prog);
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    const char *section = "--all";
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-')
            section = argv[i];
    }

    printf("=== SLH-DSA Parameter-Set Coverage Tests ===\n\n");

    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    if (strcmp(section, "--all") == 0 || strcmp(section, "--roundtrip") == 0) {
        printf("[All 12 paramsets — keypair/sign/verify/tamper]\n");
        RUN_TEST(test_all_paramsets_roundtrip);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--context") == 0) {
        printf("[Context-string sign/verify]\n");
        RUN_TEST(test_context_string_roundtrip);
        RUN_TEST(test_ctx_str_indicator_gate);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--negative") == 0) {
        printf("[Invalid algorithm names]\n");
        RUN_TEST(test_invalid_algorithm_names);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--registry") == 0) {
        printf("[Algorithm registry bounds]\n");
        RUN_TEST(test_alg_registry_bounds);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
