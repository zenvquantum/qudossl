/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
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
        int _r = fn();                     \
        if (_r) {                          \
            g_pass++;                      \
            printf("  %-55s PASS\n", #fn); \
        } else {                           \
            g_fail++;                      \
            printf("  %-55s FAIL\n", #fn); \
        }                                  \
    } while (0)

static int test_mlkem_info_getters(void)
{

    const char *v = QUDO_KEM_get_version();
    CHECK(v != NULL, "KEM_get_version");
    CHECK(QUDO_KEM_get_platform() != NULL, "KEM_get_platform");
    CHECK(QUDO_KEM_get_architecture() != NULL, "KEM_get_architecture");
    CHECK(QUDO_KEM_get_features() != NULL, "KEM_get_features");

    (void)QUDO_KEM_has_avx2();
    (void)QUDO_KEM_has_neon();
    CHECK(QUDO_KEM_get_cpu_count() >= 1, "KEM_get_cpu_count");
    CHECK(QUDO_KEM_get_cache_line_size() > 0, "KEM_get_cache_line_size");
    (void)QUDO_KEM_is_platform_supported();
    QUDO_KEM_print_system_info();

    CHECK(QUDO_KEM_is_algorithm_supported("ML-KEM-512") == 1,
          "is_algorithm_supported 512");
    CHECK(QUDO_KEM_is_algorithm_supported("INVALID") == 0,
          "is_algorithm_supported invalid");

    CHECK(QUDO_KEM_get_public_key_size(QUDO_KEM_LEVEL_512) > 0, "pk_size 1");
    CHECK(QUDO_KEM_get_secret_key_size(QUDO_KEM_LEVEL_768) > 0, "sk_size 3");
    CHECK(QUDO_KEM_get_ciphertext_size(QUDO_KEM_LEVEL_1024) > 0, "ct_size 5");
    CHECK(QUDO_KEM_get_shared_secret_size(QUDO_KEM_LEVEL_512) > 0, "ss_size 1");
    CHECK(QUDO_KEM_get_shared_secret_size((QUDO_KEM_security_level_t)999) == 0,
          "ss_size invalid level = 0");
    CHECK(QUDO_KEM_get_algorithm_name(QUDO_KEM_LEVEL_512) != NULL,
          "alg_name 1");

    QUDO_KEM_security_level_t lvl = QUDO_KEM_LEVEL_512;
    CHECK(QUDO_KEM_get_level_from_name("ML-KEM-768", &lvl) == QUDO_KEM_SUCCESS,
          "level_from_name");
    CHECK(lvl == QUDO_KEM_LEVEL_768, "level is 3");
    CHECK(QUDO_KEM_get_level_from_name("BAD", &lvl) != QUDO_KEM_SUCCESS,
          "level_from_name bad");

    for (int s = -10; s <= 5; s++)
        CHECK(QUDO_KEM_get_error_string((QUDO_KEM_status_t)s) != NULL,
              "error_string");
    return 1;
}

static int test_mlkem_level_based_api(void)
{
    const QUDO_KEM_security_level_t levels[]
        = {QUDO_KEM_LEVEL_512, QUDO_KEM_LEVEL_768, QUDO_KEM_LEVEL_1024};
    for (size_t i = 0; i < 3; i++) {
        QUDO_KEM_security_level_t lvl = levels[i];
        size_t pk_len = QUDO_KEM_get_public_key_size(lvl);
        size_t sk_len = QUDO_KEM_get_secret_key_size(lvl);
        size_t ct_len = QUDO_KEM_get_ciphertext_size(lvl);
        size_t ss_len = QUDO_KEM_get_shared_secret_size(lvl);

        uint8_t *pk = (uint8_t *)malloc(pk_len);
        uint8_t *sk = (uint8_t *)malloc(sk_len);
        uint8_t *ct = (uint8_t *)malloc(ct_len);
        uint8_t *ss_e = (uint8_t *)malloc(ss_len);
        uint8_t *ss_d = (uint8_t *)malloc(ss_len);
        CHECK(pk && sk && ct && ss_e && ss_d, "malloc");

        CHECK(QUDO_KEM_keypair_generate(lvl, pk, sk) == QUDO_KEM_SUCCESS,
              "keypair_generate");
        CHECK(QUDO_KEM_encapsulate(lvl, ct, ss_e, pk) == QUDO_KEM_SUCCESS,
              "encapsulate");
        CHECK(QUDO_KEM_decapsulate(lvl, ss_d, ct, sk) == QUDO_KEM_SUCCESS,
              "decapsulate");
        CHECK(memcmp(ss_e, ss_d, ss_len) == 0, "ss match");

        QUDO_KEM *kem = QUDO_KEM_new_by_level(lvl);
        CHECK(kem != NULL, "new_by_level");
        QUDO_KEM_free(kem);

        free(pk);
        free(sk);
        free(ct);
        free(ss_e);
        free(ss_d);
    }
    return 1;
}

static int test_mlkem_algorithm_info(void)
{

    const QUDO_KEM *kem = NULL;
    if (QUDO_KEM_get_algorithm_info("ML-KEM-512", &kem) == QUDO_KEM_SUCCESS) {
        CHECK(kem != NULL, "algorithm_info kem non-null");
        CHECK(kem->length_public_key > 0, "kem pk len");
    }
    CHECK(QUDO_KEM_get_algorithm_info("BAD", &kem) != QUDO_KEM_SUCCESS,
          "algorithm_info bad name");
    CHECK(QUDO_KEM_get_algorithm_info("ML-KEM-512", NULL) != QUDO_KEM_SUCCESS,
          "algorithm_info NULL out");

    {
        size_t la_count = 0;
        (void)QUDO_KEM_list_algorithms(&la_count);
    }
    return 1;
}

static int test_mldsa_info_getters(void)
{
    CHECK(QUDO_MLDSA_get_version() != NULL, "MLDSA_get_version");
    CHECK(QUDO_MLDSA_get_platform() != NULL, "MLDSA_get_platform");
    CHECK(QUDO_MLDSA_get_architecture() != NULL, "MLDSA_get_architecture");
    CHECK(QUDO_MLDSA_get_features() != NULL, "MLDSA_get_features");

    (void)QUDO_MLDSA_has_avx2();
    (void)QUDO_MLDSA_has_neon();
    CHECK(QUDO_MLDSA_get_cpu_count() >= 1, "MLDSA_get_cpu_count");
    CHECK(QUDO_MLDSA_get_cache_line_size() > 0, "MLDSA_cache_line");
    (void)QUDO_MLDSA_is_platform_supported();
    QUDO_MLDSA_print_system_info();

    int n = QUDO_MLDSA_alg_count();
    CHECK(n == 3, "alg_count == 3");
    for (int i = 0; i < n; i++) {
        const char *name = QUDO_MLDSA_alg_identifier((size_t)i);
        CHECK(name != NULL, "alg_identifier");
        CHECK(QUDO_MLDSA_alg_is_enabled(name) == 1, "alg_is_enabled");
    }
    CHECK(QUDO_MLDSA_alg_is_enabled("ML-DSA-INVALID") == 0,
          "alg_is_enabled invalid");

    for (int s = -10; s <= 5; s++)
        CHECK(QUDO_MLDSA_get_error_string((QUDO_MLDSA_status_t)s) != NULL,
              "MLDSA_error_string");

    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    CHECK(sig != NULL, "new");
    CHECK(QUDO_MLDSA_get_public_key_bytes(sig) > 0, "pk_bytes");
    CHECK(QUDO_MLDSA_get_secret_key_bytes(sig) > 0, "sk_bytes");
    CHECK(QUDO_MLDSA_get_signature_bytes(sig) > 0, "sig_bytes");
    CHECK(QUDO_MLDSA_get_algorithm_name(sig) != NULL, "alg_name");
    CHECK(QUDO_MLDSA_get_security_level(sig) == 3, "security_level");
    (void)QUDO_MLDSA_supports_ctx_str("ML-DSA-65");
    QUDO_MLDSA_free(sig);
    return 1;
}

#define MLDSA_LEVEL_ROUNDTRIP(NAME, PK_BYTES, SK_BYTES, SIG_BYTES)       \
    do {                                                                 \
        uint8_t *pk = (uint8_t *)malloc(PK_BYTES);                       \
        uint8_t *sk = (uint8_t *)malloc(SK_BYTES);                       \
        uint8_t *signature = (uint8_t *)malloc(SIG_BYTES);               \
        size_t sig_len = SIG_BYTES;                                      \
        CHECK(pk &&sk &&signature, "malloc");                            \
        CHECK(QUDO_MLDSA_##NAME##_keypair(pk, sk) == QUDO_MLDSA_SUCCESS, \
              #NAME "_keypair");                                         \
        uint8_t msg[] = "msg";                                           \
        CHECK(QUDO_MLDSA_##NAME##_sign(signature, &sig_len, msg,         \
                                       sizeof(msg) - 1, sk)              \
                  == QUDO_MLDSA_SUCCESS,                                 \
              #NAME "_sign");                                            \
        CHECK(QUDO_MLDSA_##NAME##_verify(signature, sig_len, msg,        \
                                         sizeof(msg) - 1, pk)            \
                  == QUDO_MLDSA_SUCCESS,                                 \
              #NAME "_verify");                                          \
        free(pk);                                                        \
        free(sk);                                                        \
        free(signature);                                                 \
    } while (0)

static int test_mldsa_per_level_api(void)
{

    QUDO_MLDSA *probe = QUDO_MLDSA_new("ML-DSA-44");
    if (probe == NULL)
        return 0;
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

    MLDSA_LEVEL_ROUNDTRIP(ML_DSA_44, pk44, sk44, sg44);
    MLDSA_LEVEL_ROUNDTRIP(ML_DSA_65, pk65, sk65, sg65);
    MLDSA_LEVEL_ROUNDTRIP(ML_DSA_87, pk87, sk87, sg87);
    return 1;
}

static int test_mldsa_shake256_ctx(void)
{
    QUDO_MLDSA_shake256_ctx *ctx = NULL;
    CHECK(QUDO_MLDSA_shake256_init(&ctx) == QUDO_MLDSA_SUCCESS,
          "shake256_init");
    CHECK(ctx != NULL, "ctx non-null");

    const uint8_t data[] = "shake";
    QUDO_MLDSA_shake256_absorb(ctx, data, sizeof(data) - 1);

    QUDO_MLDSA_shake256_ctx *dup = NULL;
    CHECK(QUDO_MLDSA_shake256_dup(&dup, ctx) == QUDO_MLDSA_SUCCESS,
          "shake256_dup");

    uint8_t out[32];
    QUDO_MLDSA_shake256_squeeze(ctx, out, sizeof(out));
    QUDO_MLDSA_shake256_squeeze(dup, out, sizeof(out));

    QUDO_MLDSA_shake256_free(ctx);
    QUDO_MLDSA_shake256_free(dup);

    QUDO_MLDSA_shake256(out, sizeof(out), data, sizeof(data) - 1);
    return 1;
}

static int test_slhdsa_info_getters(void)
{
    CHECK(QUDO_SLHDSA_get_version() != NULL, "SLHDSA_get_version");
    CHECK(QUDO_SLHDSA_get_platform() != NULL, "SLHDSA_get_platform");
    CHECK(QUDO_SLHDSA_get_architecture() != NULL, "SLHDSA_get_architecture");
    CHECK(QUDO_SLHDSA_get_features() != NULL, "SLHDSA_get_features");

    (void)QUDO_SLHDSA_has_avx2();
    (void)QUDO_SLHDSA_has_neon();
    CHECK(QUDO_SLHDSA_get_cpu_count() >= 1, "SLHDSA_get_cpu_count");
    CHECK(QUDO_SLHDSA_get_cache_line_size() > 0, "SLHDSA_cache_line");
    (void)QUDO_SLHDSA_is_platform_supported();
    QUDO_SLHDSA_print_system_info();
    (void)QUDO_SLHDSA_is_initialized();

    for (int s = -10; s <= 5; s++)
        CHECK(QUDO_SLHDSA_get_error_string((QUDO_SLHDSA_status_t)s) != NULL,
              "SLHDSA_error_string");

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    CHECK(sig != NULL, "SLHDSA_new");
    CHECK(QUDO_SLHDSA_get_security_level(sig->param_set) == 1,
          "security_level");
    QUDO_SLHDSA_free(sig);
    return 1;
}

#define SLHDSA_PARAMSET_CALL(SUFFIX, ALGNAME)                                \
    do {                                                                     \
        QUDO_SLHDSA *__s = QUDO_SLHDSA_new("SLH-DSA-" ALGNAME);              \
        CHECK(__s != NULL, "new " #SUFFIX);                                  \
        uint8_t *pk = (uint8_t *)malloc(__s->length_public_key);             \
        uint8_t *sk = (uint8_t *)malloc(__s->length_secret_key);             \
        uint8_t *signature = (uint8_t *)malloc(__s->length_signature);       \
        CHECK(pk &&sk &&signature, "malloc");                                \
        CHECK(QUDO_SLHDSA_##SUFFIX##_keypair(pk, sk) == QUDO_SLHDSA_SUCCESS, \
              #SUFFIX "_keypair");                                           \
        size_t sig_len = __s->length_signature;                              \
        uint8_t msg[] = "m";                                                 \
        CHECK(QUDO_SLHDSA_##SUFFIX##_sign(signature, &sig_len, msg, 1, sk)   \
                  == QUDO_SLHDSA_SUCCESS,                                    \
              #SUFFIX "_sign");                                              \
        CHECK(QUDO_SLHDSA_##SUFFIX##_verify(msg, 1, signature, sig_len, pk)  \
                  == QUDO_SLHDSA_SUCCESS,                                    \
              #SUFFIX "_verify");                                            \
        free(pk);                                                            \
        free(sk);                                                            \
        free(signature);                                                     \
        QUDO_SLHDSA_free(__s);                                               \
    } while (0)

static int test_slhdsa_per_paramset_fast(void)
{
    SLHDSA_PARAMSET_CALL(SHA2_128f, "SHA2-128f");
    SLHDSA_PARAMSET_CALL(SHA2_192f, "SHA2-192f");
    SLHDSA_PARAMSET_CALL(SHA2_256f, "SHA2-256f");
    SLHDSA_PARAMSET_CALL(SHAKE_128f, "SHAKE-128f");
    SLHDSA_PARAMSET_CALL(SHAKE_192f, "SHAKE-192f");
    SLHDSA_PARAMSET_CALL(SHAKE_256f, "SHAKE-256f");
    return 1;
}

static int test_slhdsa_per_paramset_slow(void)
{

    SLHDSA_PARAMSET_CALL(SHA2_128s, "SHA2-128s");
    SLHDSA_PARAMSET_CALL(SHA2_192s, "SHA2-192s");
    SLHDSA_PARAMSET_CALL(SHA2_256s, "SHA2-256s");
    SLHDSA_PARAMSET_CALL(SHAKE_128s, "SHAKE-128s");
    SLHDSA_PARAMSET_CALL(SHAKE_192s, "SHAKE-192s");
    SLHDSA_PARAMSET_CALL(SHAKE_256s, "SHAKE-256s");
    return 1;
}

static int test_slhdsa_sign_ex_and_prehash(void)
{
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    CHECK(sig != NULL, "new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");
    CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS, "keypair");

    const uint8_t msg[] = "x";
    size_t sig_len = sig->length_signature;

    CHECK(
        QUDO_SLHDSA_sign_ex(sig, signature, &sig_len, msg, 1, NULL, 0, NULL, sk)
            == QUDO_SLHDSA_SUCCESS,
        "sign_ex");

    const uint8_t pre_hash[32] = {0};
    sig_len = sig->length_signature;
    CHECK(QUDO_SLHDSA_sign_pre_hash(sig, signature, &sig_len, pre_hash,
                                    sizeof(pre_hash), NULL, 0, "SHA2-256", NULL,
                                    sk)
              == QUDO_SLHDSA_SUCCESS,
          "sign_pre_hash");

    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return 1;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--all|--mlkem|--mlkem-level|--mlkem-info|--mldsa|"
           "--mldsa-level|--mldsa-shake|--slhdsa|--slhdsa-f|--slhdsa-s|"
           "--slhdsa-ex] [-v]\n",
           prog);
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

    printf("=== Wrapper Function-Coverage Sweep ===\n\n");

    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    if (strcmp(section, "--all") == 0 || strcmp(section, "--mlkem-info") == 0) {
        printf("[MLKEM info / getters / error-strings]\n");
        RUN_TEST(test_mlkem_info_getters);
        RUN_TEST(test_mlkem_algorithm_info);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0
        || strcmp(section, "--mlkem-level") == 0) {
        printf("[MLKEM level-based API]\n");
        RUN_TEST(test_mlkem_level_based_api);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--mldsa") == 0) {
        printf("[MLDSA info / getters]\n");
        RUN_TEST(test_mldsa_info_getters);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0
        || strcmp(section, "--mldsa-level") == 0) {
        printf("[MLDSA per-level convenience]\n");
        RUN_TEST(test_mldsa_per_level_api);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0
        || strcmp(section, "--mldsa-shake") == 0) {
        printf("[MLDSA SHAKE256 context]\n");
        RUN_TEST(test_mldsa_shake256_ctx);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--slhdsa") == 0) {
        printf("[SLHDSA info / getters]\n");
        RUN_TEST(test_slhdsa_info_getters);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--slhdsa-f") == 0) {
        printf("[SLHDSA per-paramset _f fast variants]\n");
        RUN_TEST(test_slhdsa_per_paramset_fast);
        printf("\n");
    }
    if (strcmp(section, "--slhdsa-s") == 0) {
        printf("[SLHDSA per-paramset _s slow variants]\n");
        RUN_TEST(test_slhdsa_per_paramset_slow);
        printf("\n");
    }
    if (strcmp(section, "--all") == 0 || strcmp(section, "--slhdsa-ex") == 0) {
        printf("[SLHDSA sign_ex + sign_pre_hash]\n");
        RUN_TEST(test_slhdsa_sign_ex_and_prehash);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
