/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_error.h"
#include "mldsa_types.h"
#include "mldsa_wrapper.h"
#include "mlkem_error.h"
#include "mlkem_types.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "slhdsa_error.h"
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
        int _r = fn();                     \
        if (_r) {                          \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else {                           \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        }                                  \
    } while (0)

#define MLDSA_LEVEL_ADVANCED(NAME, PK_BYTES, SK_BYTES, SIG_BYTES)              \
    do {                                                                       \
        uint8_t *pk = (uint8_t *)malloc(PK_BYTES);                             \
        uint8_t *sk = (uint8_t *)malloc(SK_BYTES);                             \
        uint8_t *signature = (uint8_t *)malloc(SIG_BYTES);                     \
        uint8_t *signed_message = (uint8_t *)malloc(SIG_BYTES + 16);           \
        uint8_t *extracted = (uint8_t *)malloc(SIG_BYTES + 16);                \
        CHECK(pk &&sk &&signature &&signed_message &&extracted, "malloc");     \
                                                                               \
        uint8_t seed[MLDSA_SEEDBYTES];                                         \
        memset(seed, 0x11, sizeof(seed));                                      \
                                                                               \
        CHECK(QUDO_MLDSA_##NAME##_keypair_internal(pk, sk, seed)               \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_keypair_internal");                                      \
                                                                               \
        const uint8_t msg[] = "final-cov";                                     \
        uint8_t rnd[MLDSA_RNDBYTES];                                           \
        memset(rnd, 0, sizeof(rnd));                                           \
        size_t sig_len = SIG_BYTES;                                            \
                                                                               \
        CHECK(QUDO_MLDSA_##NAME##_sign_internal(signature, &sig_len, msg,      \
                                                sizeof(msg) - 1, NULL, 0, rnd, \
                                                sk, 0)                         \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_sign_internal");                                         \
        CHECK(QUDO_MLDSA_##NAME##_verify_internal(                             \
                  signature, sig_len, msg, sizeof(msg) - 1, NULL, 0, pk, 0)    \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_verify_internal");                                       \
                                                                               \
        size_t signed_len = SIG_BYTES + sizeof(msg);                           \
        CHECK(QUDO_MLDSA_##NAME##_sign_concat(signed_message, &signed_len,     \
                                              msg, sizeof(msg) - 1, NULL, 0,   \
                                              sk)                              \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_sign_concat");                                           \
        size_t extracted_len = SIG_BYTES + sizeof(msg);                        \
        CHECK(QUDO_MLDSA_##NAME##_open(extracted, &extracted_len,              \
                                       signed_message, signed_len, NULL, 0,    \
                                       pk)                                     \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_open");                                                  \
                                                                               \
        uint8_t mu[MLDSA_CRHBYTES];                                            \
        memset(mu, 0x33, sizeof(mu));                                          \
        sig_len = SIG_BYTES;                                                   \
        CHECK(QUDO_MLDSA_##NAME##_sign_extmu(signature, &sig_len, mu, sk)      \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_sign_extmu");                                            \
        CHECK(QUDO_MLDSA_##NAME##_verify_extmu(signature, sig_len, mu, pk)     \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_verify_extmu");                                          \
                                                                               \
        uint8_t pre_hash[64];                                                  \
        memset(pre_hash, 0x77, sizeof(pre_hash));                              \
        sig_len = SIG_BYTES;                                                   \
        CHECK(QUDO_MLDSA_##NAME##_sign_pre_hash(                               \
                  signature, &sig_len, pre_hash, sizeof(pre_hash), NULL, 0,    \
                  rnd, sk, QUDO_PREHASH_SHA2_512)                              \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_sign_pre_hash");                                         \
        CHECK(QUDO_MLDSA_##NAME##_verify_pre_hash(                             \
                  signature, sig_len, pre_hash, sizeof(pre_hash), NULL, 0, pk, \
                  QUDO_PREHASH_SHA2_512)                                       \
                  == QUDO_MLDSA_SUCCESS,                                       \
              #NAME "_verify_pre_hash");                                       \
                                                                               \
        free(pk);                                                              \
        free(sk);                                                              \
        free(signature);                                                       \
        free(signed_message);                                                  \
        free(extracted);                                                       \
    } while (0)

static int test_mldsa_per_level_advanced(void)
{

    QUDO_MLDSA *probe = QUDO_MLDSA_new("ML-DSA-44");
    size_t pk44 = probe->length_public_key, sk44 = probe->length_secret_key,
           sg44 = probe->length_signature;
    QUDO_MLDSA_free(probe);
    probe = QUDO_MLDSA_new("ML-DSA-65");
    size_t pk65 = probe->length_public_key, sk65 = probe->length_secret_key,
           sg65 = probe->length_signature;
    QUDO_MLDSA_free(probe);
    probe = QUDO_MLDSA_new("ML-DSA-87");
    size_t pk87 = probe->length_public_key, sk87 = probe->length_secret_key,
           sg87 = probe->length_signature;
    QUDO_MLDSA_free(probe);

    MLDSA_LEVEL_ADVANCED(ML_DSA_44, pk44, sk44, sg44);
    MLDSA_LEVEL_ADVANCED(ML_DSA_65, pk65, sk65, sg65);
    MLDSA_LEVEL_ADVANCED(ML_DSA_87, pk87, sk87, sg87);
    return 1;
}

static int test_error_string_enums(void)
{

    QUDO_MLDSA_status_t mldsa_codes[] = {
        QUDO_MLDSA_SUCCESS,
        QUDO_MLDSA_ERROR,
        QUDO_MLDSA_ERROR_INVALID_ARG,
        QUDO_MLDSA_ERROR_NULL_PTR,
        QUDO_MLDSA_ERROR_ALLOC,
        QUDO_MLDSA_ERROR_RNG,
        QUDO_MLDSA_ERROR_VERIFY,
        QUDO_MLDSA_ERROR_DECODE,
        QUDO_MLDSA_ERROR_NOT_IMPL,
        QUDO_MLDSA_ERROR_CRYPTO,
        QUDO_MLDSA_ERROR_FILE_IO,
        QUDO_MLDSA_ERROR_ENCODE,
        QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL,
        QUDO_MLDSA_ERROR_INVALID_SIGNATURE,
    };
    for (size_t i = 0; i < sizeof(mldsa_codes) / sizeof(mldsa_codes[0]); i++) {
        CHECK(QUDO_MLDSA_error_string(mldsa_codes[i]) != NULL,
              "MLDSA_error_string enum");
        CHECK(QUDO_MLDSA_get_error_string(mldsa_codes[i]) != NULL,
              "MLDSA_get_error_string enum");
    }

    const QUDO_MLDSA_error_info_t *info = QUDO_MLDSA_get_last_error();
    (void)info;
    QUDO_MLDSA_clear_error();

    QUDO_KEM_status_t kem_codes[] = {
        QUDO_KEM_SUCCESS,           QUDO_KEM_ERROR,
        QUDO_KEM_ERROR_INVALID_ARG, QUDO_KEM_ERROR_NULL_PTR,
        QUDO_KEM_ERROR_ALLOC,       QUDO_KEM_ERROR_RNG,
        QUDO_KEM_ERROR_CRYPTO,      QUDO_KEM_ERROR_NOT_IMPL,
    };
    for (size_t i = 0; i < sizeof(kem_codes) / sizeof(kem_codes[0]); i++) {
        CHECK(QUDO_KEM_get_error_string(kem_codes[i]) != NULL,
              "KEM_get_error_string enum");
        CHECK(QUDO_KEM_error_string(kem_codes[i]) != NULL,
              "KEM_error_string enum");
    }
    const QUDO_KEM_error_info_t *kem_info = QUDO_KEM_get_last_error();
    (void)kem_info;
    QUDO_KEM_clear_error();

    QUDO_SLHDSA_status_t slh_codes[] = {
        QUDO_SLHDSA_SUCCESS,           QUDO_SLHDSA_ERROR,
        QUDO_SLHDSA_ERROR_INVALID_ARG, QUDO_SLHDSA_ERROR_NULL_PTR,
        QUDO_SLHDSA_ERROR_ALLOC,       QUDO_SLHDSA_ERROR_NOT_IMPL,
    };
    for (size_t i = 0; i < sizeof(slh_codes) / sizeof(slh_codes[0]); i++) {
        CHECK(QUDO_SLHDSA_get_error_string(slh_codes[i]) != NULL,
              "SLHDSA_get_error_string enum");
        CHECK(QUDO_SLHDSA_error_string(slh_codes[i]) != NULL,
              "SLHDSA_error_string enum");
    }
    const QUDO_SLHDSA_error_info_t *slh_info = QUDO_SLHDSA_get_last_error();
    (void)slh_info;
    QUDO_SLHDSA_clear_error();
    return 1;
}

static int test_memory_helpers(void)
{

    uint8_t buf[64];
    memset(buf, 0xAB, sizeof(buf));
    QUDO_MLDSA_secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++)
        CHECK(buf[i] == 0, "MLDSA_secure_zero");

    void *p = QUDO_MLDSA_secure_alloc(128);
    CHECK(p != NULL, "MLDSA_secure_alloc");
    QUDO_MLDSA_secure_free(p, 128);

    uint8_t a[16], b[16], r[16];
    memset(a, 0x01, sizeof(a));
    memset(b, 0x01, sizeof(b));
    CHECK(QUDO_MLDSA_constant_time_compare(a, b, sizeof(a)) == 0,
          "MLDSA_constant_time_compare equal");
    b[0] = 0x02;
    CHECK(QUDO_MLDSA_constant_time_compare(a, b, sizeof(a)) != 0,
          "MLDSA_constant_time_compare diff");

    QUDO_MLDSA_constant_time_select(r, a, b, 1, sizeof(a));
    QUDO_MLDSA_constant_time_select(r, a, b, 0, sizeof(a));

    memset(buf, 0xCC, sizeof(buf));
    QUDO_KEM_secure_zero(buf, sizeof(buf));
    p = QUDO_KEM_secure_alloc(64);
    CHECK(p != NULL, "KEM_secure_alloc");
    QUDO_KEM_secure_free(p, 64);

    memset(buf, 0xEE, sizeof(buf));
    QUDO_SLHDSA_secure_zero(buf, sizeof(buf));
    p = QUDO_SLHDSA_secure_alloc(64);
    CHECK(p != NULL, "SLHDSA_secure_alloc");
    QUDO_SLHDSA_secure_free(p, 64);

    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--mldsa-adv|--errors|--memory] [-v]\n", prog);
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    const char *section = "--all";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-')
            section = argv[i];
    }

    printf("=== Final Function-Coverage Sweep ===\n\n");

    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    if (strcmp(section, "--all") == 0 || strcmp(section, "--mldsa-adv") == 0) {
        printf("[MLDSA per-level advanced variants]\n");
        RUN_TEST(test_mldsa_per_level_advanced);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--errors") == 0) {
        printf("[Error-string enumeration across families]\n");
        RUN_TEST(test_error_string_enums);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--memory") == 0) {
        printf("[Memory helpers — secure_zero/alloc/free, constant_time]\n");
        RUN_TEST(test_memory_helpers);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
