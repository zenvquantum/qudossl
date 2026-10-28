/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "test_fips_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;
static int g_verbose = 0;

#define VLOG(...)                       \
    do {                                \
        if (g_verbose)                  \
            printf("    " __VA_ARGS__); \
    } while (0)

#define RUN_TEST(fn)                       \
    do {                                   \
        if (g_verbose)                     \
            printf("  %s:\n", #fn);        \
        int _r = fn();                     \
        if (_r > 0) {                      \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else if (_r == 0) {              \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        } else {                           \
            g_skip++;                      \
            printf("  %-55s SKIP\n", #fn); \
        }                                  \
    } while (0)

static int test_ctrdrbg_init_valid(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx;
    uint8_t seed[48];
    uint8_t out[32];
    int ret;
    int all_zero = 1;
    size_t i;

    memset(seed, 0x42, sizeof(seed));
    memset(out, 0, sizeof(out));

    ctx = qudo_pqc_ctrdrbg_new();
    if (ctx == NULL)
        return -1;

    ret = qudo_pqc_ctrdrbg_init(ctx, 32, seed, 48);
    if (ret != 0) {
        VLOG("init failed: %d\n", ret);
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    ret = qudo_pqc_ctrdrbg_generate(ctx, out, sizeof(out), NULL, 0);
    if (ret != 0) {
        VLOG("generate failed: %d\n", ret);
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    for (i = 0; i < sizeof(out); i++) {
        if (out[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    qudo_pqc_ctrdrbg_free(ctx);

    if (all_zero) {
        VLOG("output is all zeros\n");
        return 0;
    }
    return 1;
}

static int test_ctrdrbg_all_key_sizes(void)
{
    static const size_t keylens[] = {16, 24, 32};
    size_t k;
    int ok = 1;

    for (k = 0; k < 3; k++) {
        qudo_pqc_ctrdrbg_ctx_t *ctx;
        size_t seedlen = keylens[k] + 16;
        uint8_t seed[48];
        uint8_t out[32];
        int all_zero = 1;
        size_t i;

        memset(seed, 0xAA + (uint8_t)k, seedlen);
        memset(out, 0, sizeof(out));

        ctx = qudo_pqc_ctrdrbg_new();
        if (ctx == NULL) {
            ok = 0;
            continue;
        }
        if (qudo_pqc_ctrdrbg_init(ctx, keylens[k], seed, seedlen) != 0) {
            VLOG("init failed for keylen=%zu\n", keylens[k]);
            qudo_pqc_ctrdrbg_free(ctx);
            ok = 0;
            continue;
        }
        if (qudo_pqc_ctrdrbg_generate(ctx, out, sizeof(out), NULL, 0) != 0) {
            VLOG("generate failed for keylen=%zu\n", keylens[k]);
            ok = 0;
        }
        for (i = 0; i < sizeof(out); i++) {
            if (out[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            VLOG("all-zero output for keylen=%zu\n", keylens[k]);
            ok = 0;
        }
        qudo_pqc_ctrdrbg_free(ctx);
    }
    return ok;
}

static int test_ctrdrbg_deterministic(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx1;
    qudo_pqc_ctrdrbg_ctx_t *ctx2;
    uint8_t seed[48];
    uint8_t out1[64], out2[64];
    int match;

    memset(seed, 0x55, sizeof(seed));

    ctx1 = qudo_pqc_ctrdrbg_new();
    ctx2 = qudo_pqc_ctrdrbg_new();
    if (ctx1 == NULL || ctx2 == NULL) {
        qudo_pqc_ctrdrbg_free(ctx1);
        qudo_pqc_ctrdrbg_free(ctx2);
        return -1;
    }

    if (qudo_pqc_ctrdrbg_init(ctx1, 32, seed, 48) != 0
        || qudo_pqc_ctrdrbg_init(ctx2, 32, seed, 48) != 0) {
        qudo_pqc_ctrdrbg_free(ctx1);
        qudo_pqc_ctrdrbg_free(ctx2);
        return 0;
    }

    if (qudo_pqc_ctrdrbg_generate(ctx1, out1, sizeof(out1), NULL, 0) != 0
        || qudo_pqc_ctrdrbg_generate(ctx2, out2, sizeof(out2), NULL, 0) != 0) {
        qudo_pqc_ctrdrbg_free(ctx1);
        qudo_pqc_ctrdrbg_free(ctx2);
        return 0;
    }

    match = (memcmp(out1, out2, sizeof(out1)) == 0);
    if (!match)
        VLOG("deterministic output mismatch\n");

    qudo_pqc_ctrdrbg_free(ctx1);
    qudo_pqc_ctrdrbg_free(ctx2);
    return match ? 1 : 0;
}

static int test_ctrdrbg_reseed(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx;
    uint8_t seed[48], reseed_material[48];
    uint8_t out_before[32], out_after[32];
    int differ;

    memset(seed, 0x11, sizeof(seed));
    memset(reseed_material, 0x77, sizeof(reseed_material));

    ctx = qudo_pqc_ctrdrbg_new();
    if (ctx == NULL)
        return -1;

    if (qudo_pqc_ctrdrbg_init(ctx, 32, seed, 48) != 0) {
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }
    if (qudo_pqc_ctrdrbg_generate(ctx, out_before, sizeof(out_before), NULL, 0)
        != 0) {
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }
    if (qudo_pqc_ctrdrbg_reseed(ctx, reseed_material, 48) != 0) {
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }
    if (qudo_pqc_ctrdrbg_generate(ctx, out_after, sizeof(out_after), NULL, 0)
        != 0) {
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    differ = (memcmp(out_before, out_after, sizeof(out_before)) != 0);
    if (!differ)
        VLOG("output unchanged after reseed\n");

    qudo_pqc_ctrdrbg_free(ctx);
    return differ ? 1 : 0;
}

static int test_ctrdrbg_additional_input(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx1;
    qudo_pqc_ctrdrbg_ctx_t *ctx2;
    uint8_t seed[48];
    uint8_t adin[48];
    uint8_t out_no_adin[32], out_with_adin[32];
    int differ;

    memset(seed, 0x33, sizeof(seed));
    memset(adin, 0xCC, sizeof(adin));

    ctx1 = qudo_pqc_ctrdrbg_new();
    ctx2 = qudo_pqc_ctrdrbg_new();
    if (ctx1 == NULL || ctx2 == NULL) {
        qudo_pqc_ctrdrbg_free(ctx1);
        qudo_pqc_ctrdrbg_free(ctx2);
        return -1;
    }

    if (qudo_pqc_ctrdrbg_init(ctx1, 32, seed, 48) != 0
        || qudo_pqc_ctrdrbg_init(ctx2, 32, seed, 48) != 0) {
        qudo_pqc_ctrdrbg_free(ctx1);
        qudo_pqc_ctrdrbg_free(ctx2);
        return 0;
    }

    qudo_pqc_ctrdrbg_generate(ctx1, out_no_adin, sizeof(out_no_adin), NULL, 0);
    qudo_pqc_ctrdrbg_generate(ctx2, out_with_adin, sizeof(out_with_adin), adin,
                              48);

    differ = (memcmp(out_no_adin, out_with_adin, sizeof(out_no_adin)) != 0);
    if (!differ)
        VLOG("additional input had no effect\n");

    qudo_pqc_ctrdrbg_free(ctx1);
    qudo_pqc_ctrdrbg_free(ctx2);
    return differ ? 1 : 0;
}

static int test_ctrdrbg_zeroization(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx;
    uint8_t seed[48];
    uint8_t dummy[16];
    int zeroed;

    memset(seed, 0xDE, sizeof(seed));

    ctx = qudo_pqc_ctrdrbg_new();
    if (ctx == NULL)
        return -1;

    if (qudo_pqc_ctrdrbg_init(ctx, 32, seed, 48) != 0) {
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }
    qudo_pqc_ctrdrbg_generate(ctx, dummy, sizeof(dummy), NULL, 0);

    qudo_pqc_ctrdrbg_uninit(ctx);

    zeroed = qudo_pqc_ctrdrbg_is_zeroized(ctx);
    if (!zeroed)
        VLOG("DRBG state not zeroed after uninit\n");

    qudo_pqc_ctrdrbg_free(ctx);
    return zeroed ? 1 : 0;
}

static int test_ctrdrbg_null_params(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx;
    uint8_t seed[48];
    int ok = 1;

    memset(seed, 0x11, sizeof(seed));

    ctx = qudo_pqc_ctrdrbg_new();
    if (ctx == NULL)
        return -1;

    if (qudo_pqc_ctrdrbg_init(NULL, 32, seed, 48) != -1) {
        VLOG("accepted NULL context\n");
        ok = 0;
    }

    if (qudo_pqc_ctrdrbg_init(ctx, 32, NULL, 48) != -1) {
        VLOG("accepted NULL seed\n");
        ok = 0;
    }

    if (qudo_pqc_ctrdrbg_init(ctx, 20, seed, 36) != -1) {
        VLOG("accepted invalid keylen=20\n");
        ok = 0;
    }

    if (qudo_pqc_ctrdrbg_init(ctx, 32, seed, 32) != -1) {
        VLOG("accepted mismatched seedlen\n");
        ok = 0;
    }

    qudo_pqc_ctrdrbg_free(NULL);

    if (qudo_pqc_ctrdrbg_reseed(NULL, seed, 48) != -1) {
        VLOG("NULL ctx reseed should return -1\n");
        ok = 0;
    }

    qudo_pqc_ctrdrbg_free(ctx);
    return ok;
}

static int test_ctrdrbg_max_request(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx;
    uint8_t seed[48];
    uint8_t *big_out;
    int ok = 1;

    memset(seed, 0x44, sizeof(seed));

    ctx = qudo_pqc_ctrdrbg_new();
    if (ctx == NULL)
        return -1;
    if (qudo_pqc_ctrdrbg_init(ctx, 32, seed, 48) != 0) {
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    big_out = (uint8_t *)malloc(QUDO_PQC_CTRDRBG_MAX_REQUEST + 1);
    if (big_out == NULL) {
        qudo_pqc_ctrdrbg_free(ctx);
        return -1;
    }

    if (qudo_pqc_ctrdrbg_generate(ctx, big_out, QUDO_PQC_CTRDRBG_MAX_REQUEST,
                                  NULL, 0)
        != 0) {
        VLOG("max request failed\n");
        ok = 0;
    }

    if (qudo_pqc_ctrdrbg_generate(ctx, big_out,
                                  QUDO_PQC_CTRDRBG_MAX_REQUEST + 1, NULL, 0)
        != -1) {
        VLOG("accepted over-max request\n");
        ok = 0;
    }

    free(big_out);
    qudo_pqc_ctrdrbg_free(ctx);
    return ok;
}

static int test_ctrdrbg_zero_length(void)
{
    qudo_pqc_ctrdrbg_ctx_t *ctx;
    uint8_t seed[48];
    uint8_t out[1] = {0xFF};
    int rv;

    memset(seed, 0x55, sizeof(seed));

    ctx = qudo_pqc_ctrdrbg_new();
    if (ctx == NULL)
        return -1;
    if (qudo_pqc_ctrdrbg_init(ctx, 32, seed, 48) != 0) {
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    rv = qudo_pqc_ctrdrbg_generate(ctx, out, 0, NULL, 0);
    qudo_pqc_ctrdrbg_free(ctx);

    if (rv != 0) {
        VLOG("zero-length generate failed\n");
        return 0;
    }
    return 1;
}

static int test_fips_rand_init_explicit(void)
{
    uint8_t entropy[48];
    uint8_t out[32];
    int all_zero = 1;
    size_t i;

    qudo_pqc_rand_cleanup();
    memset(entropy, 0xAB, sizeof(entropy));

    if (qudo_pqc_rand_init(entropy, sizeof(entropy)) != 0) {
        VLOG("init with explicit entropy failed\n");
        return 0;
    }

    if (!qudo_pqc_rand_is_ready()) {
        VLOG("DRBG not ready after init\n");
        qudo_pqc_rand_cleanup();
        return 0;
    }

    if (qudo_pqc_rand_bytes(out, sizeof(out)) != 0) {
        VLOG("generate after init failed\n");
        qudo_pqc_rand_cleanup();
        return 0;
    }

    for (i = 0; i < sizeof(out); i++) {
        if (out[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    qudo_pqc_rand_cleanup();
    if (all_zero) {
        VLOG("output is all zeros\n");
        return 0;
    }
    return 1;
}

static int test_fips_rand_init_platform(void)
{
    uint8_t out[64];

    qudo_pqc_rand_cleanup();

    if (qudo_pqc_rand_seed_from_platform() != 0) {
        VLOG("platform seeding failed\n");
        return 0;
    }

    if (!qudo_pqc_rand_is_ready()) {
        VLOG("DRBG not ready after platform seed\n");
        qudo_pqc_rand_cleanup();
        return 0;
    }

    if (qudo_pqc_rand_bytes(out, sizeof(out)) != 0) {
        VLOG("generate after platform seed failed\n");
        qudo_pqc_rand_cleanup();
        return 0;
    }

    qudo_pqc_rand_cleanup();
    return 1;
}

static int test_fips_rand_null_params(void)
{
    int ok = 1;
    uint8_t short_entropy[16];
    uint8_t out[16];

    if (qudo_pqc_rand_init(NULL, 48) != -1) {
        VLOG("accepted NULL entropy\n");
        ok = 0;
    }

    memset(short_entropy, 0x11, sizeof(short_entropy));
    if (qudo_pqc_rand_init(short_entropy, sizeof(short_entropy)) != -1) {
        VLOG("accepted short entropy\n");
        ok = 0;
    }

    qudo_pqc_rand_cleanup();
    if (qudo_pqc_rand_bytes(out, sizeof(out)) != -1) {
        VLOG("generated bytes when not ready\n");
        ok = 0;
    }

    if (qudo_pqc_rand_bytes(NULL, 16) != -1) {
        VLOG("accepted NULL output\n");
        ok = 0;
    }

    return ok;
}

static int test_fips_rand_reseed(void)
{
    uint8_t entropy[48], fresh[48];
    uint8_t out1[32], out2[32];

    qudo_pqc_rand_cleanup();
    memset(entropy, 0x22, sizeof(entropy));
    memset(fresh, 0x99, sizeof(fresh));

    if (qudo_pqc_rand_init(entropy, sizeof(entropy)) != 0)
        return 0;

    qudo_pqc_rand_bytes(out1, sizeof(out1));

    if (qudo_pqc_rand_reseed(fresh, sizeof(fresh)) != 0) {
        VLOG("reseed failed\n");
        qudo_pqc_rand_cleanup();
        return 0;
    }

    qudo_pqc_rand_bytes(out2, sizeof(out2));
    qudo_pqc_rand_cleanup();
    return 1;
}

static int test_fips_rand_cleanup_state(void)
{
    uint8_t entropy[48];
    uint8_t out[16];

    memset(entropy, 0xDD, sizeof(entropy));
    qudo_pqc_rand_cleanup();

    if (qudo_pqc_rand_init(entropy, sizeof(entropy)) != 0)
        return 0;

    if (!qudo_pqc_rand_is_ready()) {
        qudo_pqc_rand_cleanup();
        return 0;
    }

    qudo_pqc_rand_cleanup();

    if (qudo_pqc_rand_is_ready()) {
        VLOG("still ready after cleanup\n");
        return 0;
    }

    if (qudo_pqc_rand_bytes(out, sizeof(out)) != -1) {
        VLOG("generated bytes after cleanup\n");
        return 0;
    }

    return 1;
}

static int test_fips_rand_zero_length(void)
{
    uint8_t entropy[48];
    uint8_t out[1] = {0xFF};
    int rv;

    memset(entropy, 0xEE, sizeof(entropy));
    qudo_pqc_rand_cleanup();

    if (qudo_pqc_rand_init(entropy, sizeof(entropy)) != 0)
        return 0;

    rv = qudo_pqc_rand_bytes(out, 0);
    qudo_pqc_rand_cleanup();

    if (rv != 0) {
        VLOG("zero-length request failed\n");
        return 0;
    }
    return 1;
}

static int test_pqc_rand_bytes(void)
{
    uint8_t out[64];
    int all_zero = 1;
    size_t i;

    qudo_pqc_rand_cleanup();
    if (qudo_pqc_rand_seed_from_platform() != 0) {
        VLOG("platform seeding failed\n");
        return -1;
    }

    memset(out, 0, sizeof(out));

    if (qudo_pqc_rand_bytes(out, sizeof(out)) != 0) {
        VLOG("qudo_pqc_rand_bytes failed\n");
        qudo_pqc_rand_cleanup();
        return 0;
    }

    for (i = 0; i < sizeof(out); i++) {
        if (out[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    qudo_pqc_rand_cleanup();
    if (all_zero) {
        VLOG("output is all zeros\n");
        return 0;
    }
    return 1;
}

static int test_pqc_rand_uniqueness(void)
{
    uint8_t out1[32], out2[32], out3[32];
    int ok = 1;

    qudo_pqc_rand_cleanup();
    if (qudo_pqc_rand_seed_from_platform() != 0)
        return -1;

    qudo_pqc_rand_bytes(out1, sizeof(out1));
    qudo_pqc_rand_bytes(out2, sizeof(out2));
    qudo_pqc_rand_bytes(out3, sizeof(out3));

    if (memcmp(out1, out2, sizeof(out1)) == 0) {
        VLOG("out1 == out2\n");
        ok = 0;
    }
    if (memcmp(out2, out3, sizeof(out2)) == 0) {
        VLOG("out2 == out3\n");
        ok = 0;
    }
    if (memcmp(out1, out3, sizeof(out1)) == 0) {
        VLOG("out1 == out3\n");
        ok = 0;
    }

    qudo_pqc_rand_cleanup();
    return ok;
}

static int test_ctrdrbg_kat(void)
{
    static const uint8_t entropy[48] = {
        0x36, 0x40, 0x19, 0x40, 0xfa, 0x28, 0x0a, 0x60, 0x32, 0x7b, 0x82, 0xa2,
        0x60, 0x39, 0x30, 0x09, 0xac, 0x61, 0xdd, 0x39, 0x41, 0xa8, 0xfb, 0x3f,
        0xb3, 0x3a, 0x30, 0x92, 0x07, 0x4e, 0x36, 0x45, 0xe8, 0x4e, 0x11, 0x78,
        0x6a, 0x53, 0xcd, 0x85, 0x0c, 0xa2, 0x38, 0xc4, 0xf1, 0xc6, 0x8e, 0x68};

    static const uint8_t expected[64]
        = {0xac, 0x8a, 0x82, 0x71, 0xb0, 0x10, 0x14, 0xae, 0xc7, 0x0b, 0x42,
           0xd2, 0xba, 0x7a, 0xeb, 0x80, 0x48, 0xf8, 0xc8, 0x22, 0xb8, 0x73,
           0x50, 0xb9, 0x9e, 0xe4, 0xfe, 0x4f, 0x76, 0xa9, 0x63, 0x5e, 0x1c,
           0x1a, 0x08, 0x94, 0x9d, 0xc9, 0x58, 0x52, 0x62, 0xac, 0xfe, 0x2e,
           0xe5, 0x90, 0xcc, 0xe1, 0xdc, 0x89, 0xfe, 0xe4, 0x79, 0xb7, 0x8f,
           0xaa, 0xac, 0xc0, 0xf5, 0x9b, 0xd0, 0xe2, 0x13, 0xea};

    qudo_pqc_ctrdrbg_ctx_t *ctx;
    uint8_t discard[64], output[64];

    ctx = qudo_pqc_ctrdrbg_new();
    if (ctx == NULL)
        return -1;

    if (qudo_pqc_ctrdrbg_init(ctx, 32, entropy, 48) != 0) {
        VLOG("KAT init failed\n");
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    if (qudo_pqc_ctrdrbg_generate(ctx, discard, 64, NULL, 0) != 0) {
        VLOG("KAT first generate failed\n");
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }
    if (qudo_pqc_ctrdrbg_generate(ctx, output, 64, NULL, 0) != 0) {
        VLOG("KAT second generate failed\n");
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    if (memcmp(output, expected, 64) != 0) {
        VLOG("KAT output mismatch\n");
        if (g_verbose) {
            size_t i;
            printf("    Expected: ");
            for (i = 0; i < 16; i++)
                printf("%02x", expected[i]);
            printf("...\n    Got:      ");
            for (i = 0; i < 16; i++)
                printf("%02x", output[i]);
            printf("...\n");
        }
        qudo_pqc_ctrdrbg_free(ctx);
        return 0;
    }

    VLOG("KAT matched NIST vector\n");
    qudo_pqc_ctrdrbg_free(ctx);
    return 1;
}

static int test_fips_rand_stress(void)
{
    uint8_t out[64];
    int i;
    int ok = 1;

    qudo_pqc_rand_cleanup();
    if (qudo_pqc_rand_seed_from_platform() != 0)
        return -1;

    for (i = 0; i < 1000; i++) {
        if (qudo_pqc_rand_bytes(out, sizeof(out)) != 0) {
            VLOG("generate failed at iteration %d\n", i);
            ok = 0;
            break;
        }
    }

    qudo_pqc_rand_cleanup();
    return ok;
}

static void run_section_ctrdrbg(void)
{
    printf("\n--- Section 1: CTR-DRBG Core ---\n");
    RUN_TEST(test_ctrdrbg_init_valid);
    RUN_TEST(test_ctrdrbg_all_key_sizes);
    RUN_TEST(test_ctrdrbg_deterministic);
    RUN_TEST(test_ctrdrbg_reseed);
    RUN_TEST(test_ctrdrbg_additional_input);
    RUN_TEST(test_ctrdrbg_zeroization);
}

static void run_section_edge(void)
{
    printf("\n--- Section 2: CTR-DRBG Edge Cases ---\n");
    RUN_TEST(test_ctrdrbg_null_params);
    RUN_TEST(test_ctrdrbg_max_request);
    RUN_TEST(test_ctrdrbg_zero_length);
}

static void run_section_fips_rand(void)
{
    printf("\n--- Section 3: FIPS RNG ---\n");
    RUN_TEST(test_fips_rand_init_explicit);
    RUN_TEST(test_fips_rand_init_platform);
    RUN_TEST(test_fips_rand_null_params);
    RUN_TEST(test_fips_rand_reseed);
    RUN_TEST(test_fips_rand_cleanup_state);
    RUN_TEST(test_fips_rand_zero_length);
}

static void run_section_public_api(void)
{
    printf("\n--- Section 4: Public API ---\n");
    RUN_TEST(test_pqc_rand_bytes);
    RUN_TEST(test_pqc_rand_uniqueness);
}

static void run_section_kat(void)
{
    printf("\n--- Section 5: CTR-DRBG KAT ---\n");
    RUN_TEST(test_ctrdrbg_kat);
}

static void run_section_stress(void)
{
    printf("\n--- Section 6: Stress ---\n");
    RUN_TEST(test_fips_rand_stress);
}

int main(int argc, char *argv[])
{
    test_fips_init_set_args(&argc, argv);
    const char *section = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strncmp(argv[i], "--", 2) == 0)
            section = argv[i] + 2;
    }

    printf("=== QUDO PQC DRBG Tests ===\n");

    if (!test_fips_init()) {
        fprintf(stderr, "FAIL: qudo_pqc_init returned error\n");
        return 1;
    }

    if (section == NULL || strcmp(section, "ctrdrbg") == 0)
        run_section_ctrdrbg();
    if (section == NULL || strcmp(section, "edge") == 0)
        run_section_edge();
    if (section == NULL || strcmp(section, "rand") == 0)
        run_section_fips_rand();
    if (section == NULL || strcmp(section, "api") == 0)
        run_section_public_api();
    if (section == NULL || strcmp(section, "kat") == 0)
        run_section_kat();
    if (section == NULL || strcmp(section, "stress") == 0)
        run_section_stress();

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
