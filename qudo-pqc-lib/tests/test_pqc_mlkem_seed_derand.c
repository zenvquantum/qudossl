/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mlkem_wrapper.h"
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

static const char *kAlgs[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
#define N_ALGS ((int)(sizeof(kAlgs) / sizeof(kAlgs[0])))

static int test_keypair_from_seed_determinism(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk1 = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk1 = (uint8_t *)malloc(kem->length_secret_key);
        uint8_t *pk2 = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk2 = (uint8_t *)malloc(kem->length_secret_key);
        CHECK(pk1 && sk1 && pk2 && sk2, "malloc");

        uint8_t seed[QUDO_KEM_SEED_BYTES];
        size_t j;
        for (j = 0; j < QUDO_KEM_SEED_BYTES; j++)
            seed[j] = (uint8_t)(j + 1);

        CHECK(QUDO_KEM_keypair_from_seed(kem, pk1, sk1, seed)
                  == QUDO_KEM_SUCCESS,
              "from_seed #1");
        CHECK(QUDO_KEM_keypair_from_seed(kem, pk2, sk2, seed)
                  == QUDO_KEM_SUCCESS,
              "from_seed #2");

        CHECK(memcmp(pk1, pk2, kem->length_public_key) == 0,
              "deterministic pk");
        CHECK(memcmp(sk1, sk2, kem->length_secret_key) == 0,
              "deterministic sk");

        seed[0] ^= 0xFF;
        CHECK(QUDO_KEM_keypair_from_seed(kem, pk2, sk2, seed)
                  == QUDO_KEM_SUCCESS,
              "from_seed #3 (different)");
        CHECK(memcmp(pk1, pk2, kem->length_public_key) != 0, "pk differs");

        free(pk1);
        free(sk1);
        free(pk2);
        free(sk2);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_keypair_derand_roundtrip(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk1 = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk1 = (uint8_t *)malloc(kem->length_secret_key);
        uint8_t *pk2 = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk2 = (uint8_t *)malloc(kem->length_secret_key);
        uint8_t seed_out[QUDO_KEM_SEED_BYTES];
        CHECK(pk1 && sk1 && pk2 && sk2, "malloc");

        CHECK(QUDO_KEM_keypair_derand(kem, pk1, sk1, seed_out, sizeof(seed_out))
                  == QUDO_KEM_SUCCESS,
              "keypair_derand");

        CHECK(QUDO_KEM_keypair_from_seed(kem, pk2, sk2, seed_out)
                  == QUDO_KEM_SUCCESS,
              "from_seed with seed_out");
        CHECK(memcmp(pk1, pk2, kem->length_public_key) == 0, "pk matches");
        CHECK(memcmp(sk1, sk2, kem->length_secret_key) == 0, "sk matches");

        free(pk1);
        free(sk1);
        free(pk2);
        free(sk2);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_encaps_derand_determinism(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
        uint8_t *ct1 = (uint8_t *)malloc(kem->length_ciphertext);
        uint8_t *ct2 = (uint8_t *)malloc(kem->length_ciphertext);
        uint8_t *ss1 = (uint8_t *)malloc(kem->length_shared_secret);
        uint8_t *ss2 = (uint8_t *)malloc(kem->length_shared_secret);
        uint8_t *ss_dec = (uint8_t *)malloc(kem->length_shared_secret);
        CHECK(pk && sk && ct1 && ct2 && ss1 && ss2 && ss_dec, "malloc");

        CHECK(QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS, "keypair");

        uint8_t rnd[32];
        size_t j;
        for (j = 0; j < 32; j++)
            rnd[j] = (uint8_t)(0xA0 + j);

        CHECK(QUDO_KEM_encaps_derand(kem, ct1, ss1, pk, rnd)
                  == QUDO_KEM_SUCCESS,
              "encaps_derand #1");
        CHECK(QUDO_KEM_encaps_derand(kem, ct2, ss2, pk, rnd)
                  == QUDO_KEM_SUCCESS,
              "encaps_derand #2");
        CHECK(memcmp(ct1, ct2, kem->length_ciphertext) == 0,
              "deterministic ct");
        CHECK(memcmp(ss1, ss2, kem->length_shared_secret) == 0,
              "deterministic ss");

        CHECK(QUDO_KEM_decaps(kem, ss_dec, ct1, sk) == QUDO_KEM_SUCCESS,
              "decaps");
        CHECK(memcmp(ss_dec, ss1, kem->length_shared_secret) == 0,
              "encaps/decaps agree");

        rnd[0] ^= 0x5A;
        CHECK(QUDO_KEM_encaps_derand(kem, ct2, ss2, pk, rnd)
                  == QUDO_KEM_SUCCESS,
              "encaps_derand #3");
        CHECK(memcmp(ct1, ct2, kem->length_ciphertext) != 0,
              "different rnd => different ct");

        free(pk);
        free(sk);
        free(ct1);
        free(ct2);
        free(ss1);
        free(ss2);
        free(ss_dec);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_seed_full_roundtrip(void)
{
    int i;
    for (i = 0; i < N_ALGS; i++) {
        if (g_verbose)
            printf("    [%s]\n", kAlgs[i]);
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
        uint8_t *ct = (uint8_t *)malloc(kem->length_ciphertext);
        uint8_t *ss_enc = (uint8_t *)malloc(kem->length_shared_secret);
        uint8_t *ss_dec = (uint8_t *)malloc(kem->length_shared_secret);
        CHECK(pk && sk && ct && ss_enc && ss_dec, "malloc");

        uint8_t seed[QUDO_KEM_SEED_BYTES];
        memset(seed, 0x42, sizeof(seed));

        CHECK(QUDO_KEM_keypair_from_seed(kem, pk, sk, seed) == QUDO_KEM_SUCCESS,
              "keypair_from_seed");
        CHECK(QUDO_KEM_encaps(kem, ct, ss_enc, pk) == QUDO_KEM_SUCCESS,
              "encaps");
        CHECK(QUDO_KEM_decaps(kem, ss_dec, ct, sk) == QUDO_KEM_SUCCESS,
              "decaps");
        CHECK(memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0,
              "encaps/decaps agree");

        free(pk);
        free(sk);
        free(ct);
        free(ss_enc);
        free(ss_dec);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_deterministic_null_args(void)
{
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
    CHECK(kem != NULL, "QUDO_KEM_new");

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
    uint8_t *ct = (uint8_t *)malloc(kem->length_ciphertext);
    uint8_t *ss = (uint8_t *)malloc(kem->length_shared_secret);
    CHECK(pk && sk && ct && ss, "malloc");

    uint8_t seed[QUDO_KEM_SEED_BYTES] = {0};
    uint8_t rnd[32] = {0};

    CHECK(QUDO_KEM_keypair_from_seed(NULL, pk, sk, seed) != QUDO_KEM_SUCCESS,
          "from_seed NULL kem");
    CHECK(QUDO_KEM_keypair_from_seed(kem, NULL, sk, seed) != QUDO_KEM_SUCCESS,
          "from_seed NULL pk");
    CHECK(QUDO_KEM_keypair_from_seed(kem, pk, NULL, seed) != QUDO_KEM_SUCCESS,
          "from_seed NULL sk");
    CHECK(QUDO_KEM_keypair_from_seed(kem, pk, sk, NULL) != QUDO_KEM_SUCCESS,
          "from_seed NULL seed");

    uint8_t seed_out[QUDO_KEM_SEED_BYTES];
    CHECK(QUDO_KEM_keypair_derand(NULL, pk, sk, seed_out, sizeof(seed_out))
              != QUDO_KEM_SUCCESS,
          "derand NULL kem");
    CHECK(QUDO_KEM_keypair_derand(kem, NULL, sk, seed_out, sizeof(seed_out))
              != QUDO_KEM_SUCCESS,
          "derand NULL pk");
    CHECK(QUDO_KEM_keypair_derand(kem, pk, NULL, seed_out, sizeof(seed_out))
              != QUDO_KEM_SUCCESS,
          "derand NULL sk");

    CHECK(QUDO_KEM_keypair_derand(kem, pk, sk, NULL, 0) == QUDO_KEM_SUCCESS,
          "derand NULL seed_out (permitted)");

    CHECK(QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS, "keypair");

    CHECK(QUDO_KEM_encaps_derand(NULL, ct, ss, pk, rnd) != QUDO_KEM_SUCCESS,
          "encaps_derand NULL kem");
    CHECK(QUDO_KEM_encaps_derand(kem, NULL, ss, pk, rnd) != QUDO_KEM_SUCCESS,
          "encaps_derand NULL ct");
    CHECK(QUDO_KEM_encaps_derand(kem, ct, NULL, pk, rnd) != QUDO_KEM_SUCCESS,
          "encaps_derand NULL ss");
    CHECK(QUDO_KEM_encaps_derand(kem, ct, ss, NULL, rnd) != QUDO_KEM_SUCCESS,
          "encaps_derand NULL pk");
    CHECK(QUDO_KEM_encaps_derand(kem, ct, ss, pk, NULL) != QUDO_KEM_SUCCESS,
          "encaps_derand NULL rnd");

    free(pk);
    free(sk);
    free(ct);
    free(ss);
    QUDO_KEM_free(kem);
    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--determinism|--derand|--encaps|--roundtrip|"
           "--negative] [-v]\n",
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

    printf("=== ML-KEM Seed / Derand Coverage Tests ===\n\n");

    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    if (strcmp(section, "--all") == 0
        || strcmp(section, "--determinism") == 0) {
        printf("[keypair_from_seed determinism]\n");
        RUN_TEST(test_keypair_from_seed_determinism);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--derand") == 0) {
        printf("[keypair_derand -> from_seed round-trip]\n");
        RUN_TEST(test_keypair_derand_roundtrip);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--encaps") == 0) {
        printf("[encaps_derand determinism + full round-trip]\n");
        RUN_TEST(test_encaps_derand_determinism);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--roundtrip") == 0) {
        printf("[seed-based keygen + encaps + decaps]\n");
        RUN_TEST(test_seed_full_roundtrip);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--negative") == 0) {
        printf("[NULL args on deterministic APIs]\n");
        RUN_TEST(test_deterministic_null_args);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
