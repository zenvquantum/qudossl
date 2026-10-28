/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("    FAIL: %s (line %d)\n", msg, __LINE__); \
            return 0;                                          \
        }                                                      \
    } while (0)

#define RUN_TEST(fn)                       \
    do {                                   \
        int _r = fn();                     \
        if (_r) {                          \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else {                           \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        }                                  \
    } while (0)

static const char *kAlgs[] = {
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256f",
};
#define N_ALGS ((int)(sizeof(kAlgs) / sizeof(kAlgs[0])))

static int make_key(const char *alg, QUDO_SLHDSA **out_ctx, uint8_t **out_pk,
                    uint8_t **out_sk)
{
    QUDO_SLHDSA *ctx = QUDO_SLHDSA_new(alg);
    if (!ctx)
        return 0;
    uint8_t *pk = (uint8_t *)malloc(ctx->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(ctx->length_secret_key);
    if (!pk || !sk) {
        free(pk);
        free(sk);
        QUDO_SLHDSA_free(ctx);
        return 0;
    }
    if (QUDO_SLHDSA_keypair(ctx, pk, sk) != QUDO_SLHDSA_SUCCESS) {
        free(pk);
        free(sk);
        QUDO_SLHDSA_free(ctx);
        return 0;
    }
    *out_ctx = ctx;
    *out_pk = pk;
    *out_sk = sk;
    return 1;
}

static int test_size_query(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_SLHDSA *ctx;
        uint8_t *pk, *sk;
        CHECK(make_key(kAlgs[i], &ctx, &pk, &sk), "keypair");

        const uint8_t msg[] = "hello";
        size_t needed = 0;

        QUDO_SLHDSA_status_t rc
            = QUDO_SLHDSA_sign(ctx, NULL, &needed, msg, sizeof(msg), sk);
        CHECK(rc == QUDO_SLHDSA_SUCCESS, "size query OK");
        CHECK(needed == ctx->length_signature, "size query returns length");

        free(pk);
        free(sk);
        QUDO_SLHDSA_free(ctx);
    }
    return 1;
}

static int test_undersized_rejected(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_SLHDSA *ctx;
        uint8_t *pk, *sk;
        CHECK(make_key(kAlgs[i], &ctx, &pk, &sk), "keypair");

        const uint8_t msg[] = "hello";

        uint8_t small_sig[128];
        memset(small_sig, 0xEE, sizeof(small_sig));
        size_t slen = sizeof(small_sig);
        QUDO_SLHDSA_status_t rc
            = QUDO_SLHDSA_sign(ctx, small_sig, &slen, msg, sizeof(msg), sk);
        CHECK(rc == QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL, "undersized rejected");

        slen = 0;
        rc = QUDO_SLHDSA_sign(ctx, small_sig, &slen, msg, sizeof(msg), sk);
        CHECK(rc == QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL,
              "sentinel (*signature_len == 0) rejected");

        free(pk);
        free(sk);
        QUDO_SLHDSA_free(ctx);
    }
    return 1;
}

static int test_exact_size_ok(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_SLHDSA *ctx;
        uint8_t *pk, *sk;
        CHECK(make_key(kAlgs[i], &ctx, &pk, &sk), "keypair");

        const uint8_t msg[] = "hello";
        uint8_t *sig = (uint8_t *)malloc(ctx->length_signature);
        CHECK(sig != NULL, "malloc sig");
        size_t slen = ctx->length_signature;
        QUDO_SLHDSA_status_t rc
            = QUDO_SLHDSA_sign(ctx, sig, &slen, msg, sizeof(msg), sk);
        CHECK(rc == QUDO_SLHDSA_SUCCESS, "exact-size sign OK");
        CHECK(slen == ctx->length_signature, "signature length written");

        rc = QUDO_SLHDSA_verify(ctx, msg, sizeof(msg), sig, slen, pk);
        CHECK(rc == QUDO_SLHDSA_SUCCESS, "verify");

        free(sig);
        free(pk);
        free(sk);
        QUDO_SLHDSA_free(ctx);
    }
    return 1;
}

static int test_stack_undersized_asan(void)
{

    QUDO_SLHDSA *ctx;
    uint8_t *pk, *sk;
    CHECK(make_key("SLH-DSA-SHA2-128f", &ctx, &pk, &sk), "keypair");

    uint8_t canary_before[32];
    uint8_t small_sig[64];
    uint8_t canary_after[32];
    memset(canary_before, 0xCA, sizeof(canary_before));
    memset(canary_after, 0xFE, sizeof(canary_after));
    memset(small_sig, 0xBD, sizeof(small_sig));

    const uint8_t msg[] = "stack-guard";
    size_t slen = 0;
    QUDO_SLHDSA_status_t rc
        = QUDO_SLHDSA_sign(ctx, small_sig, &slen, msg, sizeof(msg), sk);
    CHECK(rc == QUDO_SLHDSA_ERROR_BUFFER_TOO_SMALL, "sentinel rejected");

    for (size_t j = 0; j < sizeof(canary_before); j++)
        CHECK(canary_before[j] == 0xCA, "canary_before intact");
    for (size_t j = 0; j < sizeof(canary_after); j++)
        CHECK(canary_after[j] == 0xFE, "canary_after intact");

    free(pk);
    free(sk);
    QUDO_SLHDSA_free(ctx);
    return 1;
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    printf("SLH-DSA sign output-buffer bounds\n");
    RUN_TEST(test_size_query);
    RUN_TEST(test_undersized_rejected);
    RUN_TEST(test_exact_size_ok);
    RUN_TEST(test_stack_undersized_asan);

    printf("\nTotal: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
