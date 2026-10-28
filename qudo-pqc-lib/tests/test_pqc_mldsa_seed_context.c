/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "qudo_pqc.h"
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

static const char *kAlgs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
#define N_ALGS ((int)(sizeof(kAlgs) / sizeof(kAlgs[0])))

static int test_keypair_internal_determinism(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_MLDSA *sig = QUDO_MLDSA_new(kAlgs[i]);
        CHECK(sig != NULL, "QUDO_MLDSA_new");

        uint8_t *pk1 = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk1 = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *pk2 = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk2 = (uint8_t *)malloc(sig->length_secret_key);
        CHECK(pk1 && sk1 && pk2 && sk2, "malloc");

        uint8_t seed[MLDSA_SEEDBYTES];
        size_t j;
        for (j = 0; j < sizeof(seed); j++)
            seed[j] = (uint8_t)(j + 7);

        CHECK(QUDO_MLDSA_keypair_internal(sig, pk1, sk1, seed)
                  == QUDO_MLDSA_SUCCESS,
              "keypair_internal #1");
        CHECK(QUDO_MLDSA_keypair_internal(sig, pk2, sk2, seed)
                  == QUDO_MLDSA_SUCCESS,
              "keypair_internal #2");
        CHECK(memcmp(pk1, pk2, sig->length_public_key) == 0,
              "deterministic pk");
        CHECK(memcmp(sk1, sk2, sig->length_secret_key) == 0,
              "deterministic sk");

        seed[0] ^= 0xFF;
        CHECK(QUDO_MLDSA_keypair_internal(sig, pk2, sk2, seed)
                  == QUDO_MLDSA_SUCCESS,
              "keypair_internal #3");
        CHECK(memcmp(pk1, pk2, sig->length_public_key) != 0, "pk differs");

        free(pk1);
        free(sk1);
        free(pk2);
        free(sk2);
        QUDO_MLDSA_free(sig);
    }
    return 1;
}

static int test_sign_internal_roundtrip(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_MLDSA *sig = QUDO_MLDSA_new(kAlgs[i]);
        CHECK(sig != NULL, "QUDO_MLDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");

        CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

        const uint8_t msg[] = "FIPS 204 sign_internal roundtrip";
        const uint8_t prefix[] = {0x00, 0x00};
        uint8_t rnd[MLDSA_RNDBYTES];
        memset(rnd, 0, sizeof(rnd));
        size_t sig_len = sig->length_signature;

        CHECK(QUDO_MLDSA_sign_internal(sig, signature, &sig_len, msg,
                                       sizeof(msg) - 1, prefix, sizeof(prefix),
                                       rnd, sk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "sign_internal");
        CHECK(QUDO_MLDSA_verify_internal(sig, signature, sig_len, msg,
                                         sizeof(msg) - 1, prefix,
                                         sizeof(prefix), pk, 0)
                  == QUDO_MLDSA_SUCCESS,
              "verify_internal");

        signature[sig_len / 2] ^= 0x5A;
        CHECK(QUDO_MLDSA_verify_internal(sig, signature, sig_len, msg,
                                         sizeof(msg) - 1, prefix,
                                         sizeof(prefix), pk, 0)
                  != QUDO_MLDSA_SUCCESS,
              "tampered sig rejected");

        free(pk);
        free(sk);
        free(signature);
        QUDO_MLDSA_free(sig);
    }
    return 1;
}

static int test_extmu_roundtrip(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_MLDSA *sig = QUDO_MLDSA_new(kAlgs[i]);
        CHECK(sig != NULL, "QUDO_MLDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");

        CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

        uint8_t mu[64];
        size_t j;
        for (j = 0; j < sizeof(mu); j++)
            mu[j] = (uint8_t)(0x40 + j);

        size_t sig_len = sig->length_signature;
        CHECK(QUDO_MLDSA_sign_extmu(sig, signature, &sig_len, mu, sk)
                  == QUDO_MLDSA_SUCCESS,
              "sign_extmu");
        CHECK(QUDO_MLDSA_verify_extmu(sig, signature, sig_len, mu, pk)
                  == QUDO_MLDSA_SUCCESS,
              "verify_extmu");

        mu[0] ^= 0xFF;
        CHECK(QUDO_MLDSA_verify_extmu(sig, signature, sig_len, mu, pk)
                  != QUDO_MLDSA_SUCCESS,
              "mu mismatch rejected");

        free(pk);
        free(sk);
        free(signature);
        QUDO_MLDSA_free(sig);
    }
    return 1;
}

static int test_concat_open_roundtrip(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_MLDSA *sig = QUDO_MLDSA_new(kAlgs[i]);
        CHECK(sig != NULL, "QUDO_MLDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        CHECK(pk && sk, "malloc");

        CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

        const uint8_t msg[] = "concat format test";
        const uint8_t ctx[] = "domain-ctx";
        size_t signed_len_max = sig->length_signature + sizeof(msg);
        uint8_t *signed_msg = (uint8_t *)malloc(signed_len_max);
        uint8_t *extracted = (uint8_t *)malloc(signed_len_max);
        CHECK(signed_msg && extracted, "malloc");

        size_t signed_len = signed_len_max;
        CHECK(QUDO_MLDSA_sign_concat(sig, signed_msg, &signed_len, msg,
                                     sizeof(msg) - 1, ctx, sizeof(ctx) - 1, sk)
                  == QUDO_MLDSA_SUCCESS,
              "sign_concat");
        CHECK(signed_len > sig->length_signature, "signed_len > sig_len");

        size_t msg_out_len = signed_len_max;
        CHECK(QUDO_MLDSA_open(sig, extracted, &msg_out_len, signed_msg,
                              signed_len, ctx, sizeof(ctx) - 1, pk)
                  == QUDO_MLDSA_SUCCESS,
              "open");
        CHECK(msg_out_len == sizeof(msg) - 1, "extracted len matches");
        CHECK(memcmp(extracted, msg, msg_out_len) == 0,
              "extracted msg matches");

        const uint8_t ctx_wrong[] = "different-ctx";
        msg_out_len = signed_len_max;
        CHECK(QUDO_MLDSA_open(sig, extracted, &msg_out_len, signed_msg,
                              signed_len, ctx_wrong, sizeof(ctx_wrong) - 1, pk)
                  != QUDO_MLDSA_SUCCESS,
              "open wrong ctx rejected");

        free(pk);
        free(sk);
        free(signed_msg);
        free(extracted);
        QUDO_MLDSA_free(sig);
    }
    return 1;
}

static int test_sign_with_context_roundtrip(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_MLDSA *sig = QUDO_MLDSA_new(kAlgs[i]);
        CHECK(sig != NULL, "QUDO_MLDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");
        CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

        const uint8_t msg[] = "ctx-string test";
        const uint8_t ctx[] = "application-label";
        size_t sig_len = sig->length_signature;

        CHECK(QUDO_MLDSA_sign_with_context(sig, signature, &sig_len, msg,
                                           sizeof(msg) - 1, ctx,
                                           sizeof(ctx) - 1, sk)
                  == QUDO_MLDSA_SUCCESS,
              "sign_with_context");
        CHECK(QUDO_MLDSA_verify_with_context(sig, signature, sig_len, msg,
                                             sizeof(msg) - 1, ctx,
                                             sizeof(ctx) - 1, pk)
                  == QUDO_MLDSA_SUCCESS,
              "verify_with_context");

        CHECK(QUDO_MLDSA_sign_with_context(sig, signature, &sig_len, msg,
                                           sizeof(msg) - 1, NULL, 0, sk)
                  == QUDO_MLDSA_SUCCESS,
              "sign empty ctx");
        CHECK(QUDO_MLDSA_verify_with_context(sig, signature, sig_len, msg,
                                             sizeof(msg) - 1, NULL, 0, pk)
                  == QUDO_MLDSA_SUCCESS,
              "verify empty ctx");

        CHECK(QUDO_MLDSA_sign_with_context(sig, signature, &sig_len, msg,
                                           sizeof(msg) - 1, ctx,
                                           sizeof(ctx) - 1, sk)
                  == QUDO_MLDSA_SUCCESS,
              "re-sign with ctx");
        const uint8_t ctx_wrong[] = "other-label";
        CHECK(QUDO_MLDSA_verify_with_context(sig, signature, sig_len, msg,
                                             sizeof(msg) - 1, ctx_wrong,
                                             sizeof(ctx_wrong) - 1, pk)
                  != QUDO_MLDSA_SUCCESS,
              "ctx mismatch rejected");

        free(pk);
        free(sk);
        free(signature);
        QUDO_MLDSA_free(sig);
    }
    return 1;
}

static int test_pre_hash_internal_hash_algs(void)
{

    struct hash_spec {
        int alg_id;
        size_t digest_len;
    };
    static const struct hash_spec specs[] = {
        {QUDO_PREHASH_SHA2_256, 32}, {QUDO_PREHASH_SHA2_384, 48},
        {QUDO_PREHASH_SHA2_512, 64}, {QUDO_PREHASH_SHA3_256, 32},
        {QUDO_PREHASH_SHA3_512, 64},
    };
    size_t n_algs = sizeof(specs) / sizeof(specs[0]);

    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    CHECK(sig != NULL, "QUDO_MLDSA_new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");
    CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

    uint8_t pre_hash[64];
    size_t j;
    for (j = 0; j < sizeof(pre_hash); j++)
        pre_hash[j] = (uint8_t)(0x11 * (j + 1));

    const uint8_t ctx[] = "prehash-ctx";
    uint8_t rnd[MLDSA_RNDBYTES];
    memset(rnd, 0, sizeof(rnd));

    size_t a;
    for (a = 0; a < n_algs; a++) {
        size_t sig_len = sig->length_signature;
        int ok = (QUDO_MLDSA_sign_pre_hash_internal(
                      sig, signature, &sig_len, pre_hash, specs[a].digest_len,
                      ctx, sizeof(ctx) - 1, rnd, sk, specs[a].alg_id)
                  == QUDO_MLDSA_SUCCESS)
                 && (QUDO_MLDSA_verify_pre_hash_internal(
                         sig, signature, sig_len, pre_hash, specs[a].digest_len,
                         ctx, sizeof(ctx) - 1, pk, specs[a].alg_id)
                     == QUDO_MLDSA_SUCCESS);
        if (g_verbose)
            printf("    hash_alg=%d len=%zu %s\n", specs[a].alg_id,
                   specs[a].digest_len, ok ? "OK" : "FAIL");
        CHECK(ok, "sign/verify pre_hash_internal per hash_alg");
    }

    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
    return 1;
}

static int test_internal_null_args(void)
{
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    CHECK(sig != NULL, "QUDO_MLDSA_new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    uint8_t seed[MLDSA_SEEDBYTES] = {0};
    uint8_t rnd[MLDSA_RNDBYTES] = {0};
    uint8_t mu[64] = {0};
    CHECK(pk && sk && signature, "malloc");

    CHECK(QUDO_MLDSA_keypair_internal(NULL, pk, sk, seed) != QUDO_MLDSA_SUCCESS,
          "keypair_internal NULL sig");
    CHECK(QUDO_MLDSA_keypair_internal(sig, NULL, sk, seed)
              != QUDO_MLDSA_SUCCESS,
          "keypair_internal NULL pk");
    CHECK(QUDO_MLDSA_keypair_internal(sig, pk, NULL, seed)
              != QUDO_MLDSA_SUCCESS,
          "keypair_internal NULL sk");
    CHECK(QUDO_MLDSA_keypair_internal(sig, pk, sk, NULL) != QUDO_MLDSA_SUCCESS,
          "keypair_internal NULL seed");

    CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

    size_t sig_len = sig->length_signature;
    CHECK(QUDO_MLDSA_sign_extmu(NULL, signature, &sig_len, mu, sk)
              != QUDO_MLDSA_SUCCESS,
          "sign_extmu NULL sig");
    CHECK(QUDO_MLDSA_sign_extmu(sig, NULL, &sig_len, mu, sk)
              != QUDO_MLDSA_SUCCESS,
          "sign_extmu NULL signature");
    CHECK(QUDO_MLDSA_sign_extmu(sig, signature, NULL, mu, sk)
              != QUDO_MLDSA_SUCCESS,
          "sign_extmu NULL sig_len");
    CHECK(QUDO_MLDSA_sign_extmu(sig, signature, &sig_len, NULL, sk)
              != QUDO_MLDSA_SUCCESS,
          "sign_extmu NULL mu");
    CHECK(QUDO_MLDSA_sign_extmu(sig, signature, &sig_len, mu, NULL)
              != QUDO_MLDSA_SUCCESS,
          "sign_extmu NULL sk");

    CHECK(QUDO_MLDSA_sign_internal(sig, signature, &sig_len, (uint8_t *)"m", 1,
                                   NULL, 0, rnd, NULL, 0)
              != QUDO_MLDSA_SUCCESS,
          "sign_internal NULL sk");

    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--seed|--sign_internal|--extmu|--concat|--ctx|"
           "--prehash|--negative] [-v]\n",
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

    printf("=== ML-DSA Seed / Context / Internal Coverage Tests ===\n\n");

    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    if (strcmp(section, "--all") == 0 || strcmp(section, "--seed") == 0) {
        printf("[keypair_internal determinism]\n");
        RUN_TEST(test_keypair_internal_determinism);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0
        || strcmp(section, "--sign_internal") == 0) {
        printf("[sign_internal / verify_internal]\n");
        RUN_TEST(test_sign_internal_roundtrip);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--extmu") == 0) {
        printf("[sign_extmu / verify_extmu]\n");
        RUN_TEST(test_extmu_roundtrip);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--concat") == 0) {
        printf("[sign_concat / open]\n");
        RUN_TEST(test_concat_open_roundtrip);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--ctx") == 0) {
        printf("[sign_with_context / verify_with_context]\n");
        RUN_TEST(test_sign_with_context_roundtrip);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--prehash") == 0) {
        printf("[sign_pre_hash_internal per hash_alg]\n");
        RUN_TEST(test_pre_hash_internal_hash_algs);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--negative") == 0) {
        printf("[NULL args on internal APIs]\n");
        RUN_TEST(test_internal_null_args);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
