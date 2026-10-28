/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "qudo_pqc.h"
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

static const char *kAlgs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
#define N_ALGS ((int)(sizeof(kAlgs) / sizeof(kAlgs[0])))

static int make_key(const char *alg, QUDO_MLDSA **out_ctx, uint8_t **out_pk,
                    uint8_t **out_sk)
{
    QUDO_MLDSA *ctx = QUDO_MLDSA_new(alg);
    if (!ctx)
        return 0;
    uint8_t *pk = (uint8_t *)malloc(ctx->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(ctx->length_secret_key);
    if (!pk || !sk) {
        free(pk);
        free(sk);
        QUDO_MLDSA_free(ctx);
        return 0;
    }
    if (QUDO_MLDSA_keypair(ctx, pk, sk) != QUDO_MLDSA_SUCCESS) {
        free(pk);
        free(sk);
        QUDO_MLDSA_free(ctx);
        return 0;
    }
    *out_ctx = ctx;
    *out_pk = pk;
    *out_sk = sk;
    return 1;
}

static int test_mldsa_size_query(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_MLDSA *ctx;
        uint8_t *pk, *sk;
        CHECK(make_key(kAlgs[i], &ctx, &pk, &sk), "keypair");

        const uint8_t msg[] = "hello";
        size_t needed = 0;
        QUDO_MLDSA_status_t rc
            = QUDO_MLDSA_sign(ctx, NULL, &needed, msg, sizeof(msg), sk);
        CHECK(rc == QUDO_MLDSA_SUCCESS, "size query OK");
        CHECK(needed == ctx->length_signature, "size query returns length");

        free(pk);
        free(sk);
        QUDO_MLDSA_free(ctx);
    }
    return 1;
}

static int test_mldsa_undersized_rejected(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_MLDSA *ctx;
        uint8_t *pk, *sk;
        CHECK(make_key(kAlgs[i], &ctx, &pk, &sk), "keypair");

        const uint8_t msg[] = "hello";
        uint8_t small_sig[256];
        memset(small_sig, 0x77, sizeof(small_sig));
        size_t slen = sizeof(small_sig);
        QUDO_MLDSA_status_t rc
            = QUDO_MLDSA_sign(ctx, small_sig, &slen, msg, sizeof(msg), sk);
        CHECK(rc == QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL, "undersized rejected");

        free(pk);
        free(sk);
        QUDO_MLDSA_free(ctx);
    }
    return 1;
}

static int test_mldsa_exact_size_ok(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_MLDSA *ctx;
        uint8_t *pk, *sk;
        CHECK(make_key(kAlgs[i], &ctx, &pk, &sk), "keypair");

        const uint8_t msg[] = "hello";
        uint8_t *sig = (uint8_t *)malloc(ctx->length_signature);
        CHECK(sig != NULL, "malloc sig");
        size_t slen = ctx->length_signature;
        QUDO_MLDSA_status_t rc
            = QUDO_MLDSA_sign(ctx, sig, &slen, msg, sizeof(msg), sk);
        CHECK(rc == QUDO_MLDSA_SUCCESS, "exact-size sign OK");
        CHECK(slen == ctx->length_signature, "signature length written");

        rc = QUDO_MLDSA_verify(ctx, sig, slen, msg, sizeof(msg), pk);
        CHECK(rc == QUDO_MLDSA_SUCCESS, "verify");

        free(sig);
        free(pk);
        free(sk);
        QUDO_MLDSA_free(ctx);
    }
    return 1;
}

static int test_mldsa_verify_wrong_size(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_MLDSA *ctx;
        uint8_t *pk, *sk;
        CHECK(make_key(kAlgs[i], &ctx, &pk, &sk), "keypair");

        const uint8_t msg[] = "hello";
        uint8_t *sig = (uint8_t *)malloc(ctx->length_signature);
        CHECK(sig != NULL, "malloc sig");
        size_t slen = ctx->length_signature;
        CHECK(QUDO_MLDSA_sign(ctx, sig, &slen, msg, sizeof(msg), sk)
                  == QUDO_MLDSA_SUCCESS,
              "sign");

        QUDO_MLDSA_status_t rc
            = QUDO_MLDSA_verify(ctx, sig, slen - 1, msg, sizeof(msg), pk);
        CHECK(rc == QUDO_MLDSA_ERROR_INVALID_SIGNATURE,
              "verify short length rejected");

        rc = QUDO_MLDSA_verify(ctx, sig, slen + 1, msg, sizeof(msg), pk);
        CHECK(rc == QUDO_MLDSA_ERROR_INVALID_SIGNATURE,
              "verify long length rejected");

        rc = QUDO_MLDSA_verify_with_context(ctx, sig, slen - 1, msg,
                                            sizeof(msg), NULL, 0, pk);
        CHECK(rc == QUDO_MLDSA_ERROR_INVALID_SIGNATURE,
              "verify_with_context short length rejected");

        free(sig);
        free(pk);
        free(sk);
        QUDO_MLDSA_free(ctx);
    }
    return 1;
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    printf("ML-DSA sign/verify bounds\n");
    RUN_TEST(test_mldsa_size_query);
    RUN_TEST(test_mldsa_undersized_rejected);
    RUN_TEST(test_mldsa_exact_size_ok);
    RUN_TEST(test_mldsa_verify_wrong_size);

    printf("\nTotal: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
