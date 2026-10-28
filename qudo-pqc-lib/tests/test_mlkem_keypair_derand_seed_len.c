/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mlkem_wrapper.h"
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

static const char *kAlgs[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
#define N_ALGS ((int)(sizeof(kAlgs) / sizeof(kAlgs[0])))

static int test_undersized_buffer_rejected(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
        CHECK(pk && sk, "malloc");

        uint8_t small_seed[63];
        memset(small_seed, 0xAA, sizeof(small_seed));
        QUDO_KEM_status_t rc = QUDO_KEM_keypair_derand(kem, pk, sk, small_seed,
                                                       sizeof(small_seed));
        CHECK(rc == QUDO_KEM_ERROR_BUFFER_TOO_SMALL,
              "63-byte seed rejected with BUFFER_TOO_SMALL");

        for (size_t j = 0; j < sizeof(small_seed); j++) {
            CHECK(small_seed[j] == 0xAA, "seed buffer untouched on reject");
        }

        free(pk);
        free(sk);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_exact_size_buffer_ok(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
        CHECK(pk && sk, "malloc");

        uint8_t seed[QUDO_KEM_SEED_BYTES];
        memset(seed, 0, sizeof(seed));
        QUDO_KEM_status_t rc
            = QUDO_KEM_keypair_derand(kem, pk, sk, seed, sizeof(seed));
        CHECK(rc == QUDO_KEM_SUCCESS, "exact-size seed OK");

        int any_nz = 0;
        for (size_t j = 0; j < sizeof(seed); j++)
            if (seed[j] != 0) {
                any_nz = 1;
                break;
            }
        CHECK(any_nz, "seed was written");

        free(pk);
        free(sk);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_null_seed_out_permitted(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
        CHECK(pk && sk, "malloc");

        QUDO_KEM_status_t rc = QUDO_KEM_keypair_derand(kem, pk, sk, NULL, 0);
        CHECK(rc == QUDO_KEM_SUCCESS, "NULL seed_out permitted");

        free(pk);
        free(sk);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_oversize_buffer_ok(void)
{
    for (int i = 0; i < N_ALGS; i++) {
        QUDO_KEM *kem = QUDO_KEM_new(kAlgs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
        CHECK(pk && sk, "malloc");

        uint8_t seed[128];
        memset(seed, 0xFF, sizeof(seed));
        QUDO_KEM_status_t rc
            = QUDO_KEM_keypair_derand(kem, pk, sk, seed, sizeof(seed));
        CHECK(rc == QUDO_KEM_SUCCESS, "128-byte seed OK");

        for (size_t j = QUDO_KEM_SEED_BYTES; j < sizeof(seed); j++)
            CHECK(seed[j] == 0xFF, "no write beyond SEED_BYTES");

        free(pk);
        free(sk);
        QUDO_KEM_free(kem);
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

    printf("QUDO_KEM_keypair_derand seed-buffer length\n");
    RUN_TEST(test_undersized_buffer_rejected);
    RUN_TEST(test_exact_size_buffer_ok);
    RUN_TEST(test_null_seed_out_permitted);
    RUN_TEST(test_oversize_buffer_ok);

    printf("\nTotal: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
