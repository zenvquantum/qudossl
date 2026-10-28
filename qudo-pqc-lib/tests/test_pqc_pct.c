/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "slhdsa_wrapper.h"
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

static int g_module_ready = 0;

static void ensure_module_ready(void)
{
    if (g_module_ready)
        return;

    if (test_fips_init())
        g_module_ready = 1;
}

static int test_mlkem_pct(const char *alg_name)
{
    QUDO_KEM *kem = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    int ret = 0;

    ensure_module_ready();

    VLOG("Creating %s instance\n", alg_name);
    kem = QUDO_KEM_new(alg_name);
    if (kem == NULL) {
        fprintf(stderr, "    QUDO_KEM_new(%s) failed\n", alg_name);
        return 0;
    }

    VLOG("  pk_size=%zu sk_size=%zu ct_size=%zu\n", kem->length_public_key,
         kem->length_secret_key, kem->length_ciphertext);
    pk = (uint8_t *)malloc(kem->length_public_key);
    sk = (uint8_t *)malloc(kem->length_secret_key);
    if (pk == NULL || sk == NULL)
        goto cleanup;

    VLOG("Generating keypair\n");
    if (QUDO_KEM_keypair(kem, pk, sk) != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "    keypair generation failed for %s\n", alg_name);
        goto cleanup;
    }

    VLOG("Running PCT (fixed entropy — keygen mode)\n");
    {
        int pct_ret = qudo_pqc_mlkem_pct(kem, pk, sk, 0);
        VLOG("Expected: returns 1 (pass)\n");
        VLOG("Got:      returns %d\n", pct_ret);
        if (!pct_ret)
            goto cleanup;
    }

    VLOG("Running PCT (random entropy — validate/import mode)\n");
    {
        int pct_ret = qudo_pqc_mlkem_pct(kem, pk, sk, 1);
        VLOG("Expected: returns 1 (pass)\n");
        VLOG("Got:      returns %d\n", pct_ret);
        if (!pct_ret)
            goto cleanup;
    }

    ret = 1;
cleanup:
    if (sk != NULL) {
        qudo_cleanse(sk, kem ? kem->length_secret_key : 0);
        free(sk);
    }
    free(pk);
    QUDO_KEM_free(kem);
    return ret;
}

static int test_mlkem_pct_512(void)
{
    return test_mlkem_pct("ML-KEM-512");
}
static int test_mlkem_pct_768(void)
{
    return test_mlkem_pct("ML-KEM-768");
}
static int test_mlkem_pct_1024(void)
{
    return test_mlkem_pct("ML-KEM-1024");
}

static int test_mldsa_pct(const char *alg_name)
{
    QUDO_MLDSA *sig = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    int ret = 0;

    ensure_module_ready();

    VLOG("Creating %s instance\n", alg_name);
    sig = QUDO_MLDSA_new(alg_name);
    if (sig == NULL) {
        fprintf(stderr, "    QUDO_MLDSA_new(%s) failed\n", alg_name);
        return 0;
    }

    VLOG("  pk_size=%zu sk_size=%zu sig_size=%zu\n", sig->length_public_key,
         sig->length_secret_key, sig->length_signature);
    pk = (uint8_t *)malloc(sig->length_public_key);
    sk = (uint8_t *)malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL)
        goto cleanup;

    VLOG("Generating keypair\n");
    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "    keypair generation failed for %s\n", alg_name);
        goto cleanup;
    }

    VLOG("Running PCT (sign \"Plugh\" + verify)\n");
    {
        int pct_ret = qudo_pqc_mldsa_pct(sig, pk, sk);
        VLOG("Expected: returns 1 (pass)\n");
        VLOG("Got:      returns %d\n", pct_ret);
        if (!pct_ret)
            goto cleanup;
    }

    ret = 1;
cleanup:
    if (sk != NULL) {
        qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
        free(sk);
    }
    free(pk);
    QUDO_MLDSA_free(sig);
    return ret;
}

static int test_mldsa_pct_44(void)
{
    return test_mldsa_pct("ML-DSA-44");
}
static int test_mldsa_pct_65(void)
{
    return test_mldsa_pct("ML-DSA-65");
}
static int test_mldsa_pct_87(void)
{
    return test_mldsa_pct("ML-DSA-87");
}

static int test_slhdsa_pct(const char *param_set)
{
    QUDO_SLHDSA *sig = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    int ret = 0;

    ensure_module_ready();

    VLOG("Creating %s instance\n", param_set);
    sig = QUDO_SLHDSA_new(param_set);
    if (sig == NULL) {
        fprintf(stderr, "    QUDO_SLHDSA_new(%s) failed\n", param_set);
        return 0;
    }

    VLOG("  pk_size=%zu sk_size=%zu sig_size=%zu\n", sig->length_public_key,
         sig->length_secret_key, sig->length_signature);
    pk = (uint8_t *)malloc(sig->length_public_key);
    sk = (uint8_t *)malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL)
        goto cleanup;

    VLOG("Generating keypair\n");
    if (QUDO_SLHDSA_keypair(sig, pk, sk) != QUDO_SLHDSA_SUCCESS) {
        fprintf(stderr, "    keypair generation failed for %s\n", param_set);
        goto cleanup;
    }

    VLOG("Running PCT (sign 16-zero-bytes + verify)\n");
    {
        int pct_ret = qudo_pqc_slhdsa_pct(sig, pk, sk);
        VLOG("Expected: returns 1 (pass)\n");
        VLOG("Got:      returns %d\n", pct_ret);
        if (!pct_ret)
            goto cleanup;
    }

    ret = 1;
cleanup:
    if (sk != NULL) {
        qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
        free(sk);
    }
    free(pk);
    QUDO_SLHDSA_free(sig);
    return ret;
}

static int test_slhdsa_pct_sha2_128s(void)
{
    return test_slhdsa_pct("SLH-DSA-SHA2-128s");
}
static int test_slhdsa_pct_sha2_128f(void)
{
    return test_slhdsa_pct("SLH-DSA-SHA2-128f");
}
static int test_slhdsa_pct_sha2_192s(void)
{
    return test_slhdsa_pct("SLH-DSA-SHA2-192s");
}
static int test_slhdsa_pct_sha2_192f(void)
{
    return test_slhdsa_pct("SLH-DSA-SHA2-192f");
}
static int test_slhdsa_pct_sha2_256s(void)
{
    return test_slhdsa_pct("SLH-DSA-SHA2-256s");
}
static int test_slhdsa_pct_sha2_256f(void)
{
    return test_slhdsa_pct("SLH-DSA-SHA2-256f");
}
static int test_slhdsa_pct_shake_128s(void)
{
    return test_slhdsa_pct("SLH-DSA-SHAKE-128s");
}
static int test_slhdsa_pct_shake_128f(void)
{
    return test_slhdsa_pct("SLH-DSA-SHAKE-128f");
}
static int test_slhdsa_pct_shake_192s(void)
{
    return test_slhdsa_pct("SLH-DSA-SHAKE-192s");
}
static int test_slhdsa_pct_shake_192f(void)
{
    return test_slhdsa_pct("SLH-DSA-SHAKE-192f");
}
static int test_slhdsa_pct_shake_256s(void)
{
    return test_slhdsa_pct("SLH-DSA-SHAKE-256s");
}
static int test_slhdsa_pct_shake_256f(void)
{
    return test_slhdsa_pct("SLH-DSA-SHAKE-256f");
}

static int test_pct_null_kem_instance(void)
{
    uint8_t dummy = 0;
    int ret;

    VLOG("Calling mlkem_pct(NULL, ...) — fail-closed: PCT must not pass\n");
    ret = qudo_pqc_mlkem_pct(NULL, &dummy, &dummy, 0);
    VLOG("Expected: returns 0 (fail-closed)\n");
    VLOG("Got:      returns %d\n", ret);
    if (ret != 0)
        return 0;
    return 1;
}

static int test_pct_null_mldsa_instance(void)
{
    uint8_t dummy = 0;
    int ret;

    VLOG("Calling mldsa_pct(NULL, ...) — fail-closed: PCT must not pass\n");
    ret = qudo_pqc_mldsa_pct(NULL, &dummy, &dummy);
    VLOG("Expected: returns 0 (fail-closed)\n");
    VLOG("Got:      returns %d\n", ret);
    if (ret != 0)
        return 0;
    return 1;
}

static int test_pct_null_slhdsa_instance(void)
{
    uint8_t dummy = 0;
    int ret;

    VLOG("Calling slhdsa_pct(NULL, ...) — fail-closed: PCT must not pass\n");
    ret = qudo_pqc_slhdsa_pct(NULL, &dummy, &dummy);
    VLOG("Expected: returns 0 (fail-closed)\n");
    VLOG("Got:      returns %d\n", ret);
    if (ret != 0)
        return 0;
    return 1;
}

static int test_pct_null_keys_kem(void)
{
    QUDO_KEM *kem;
    int ret;

    ensure_module_ready();

    kem = QUDO_KEM_new("ML-KEM-512");
    if (kem == NULL)
        return 0;

    VLOG("Calling mlkem_pct(kem, NULL, NULL) — valid instance, no keys\n");
    ret = qudo_pqc_mlkem_pct(kem, NULL, NULL, 0);
    QUDO_KEM_free(kem);

    VLOG("Expected: returns 0 (error)\n");
    VLOG("Got:      returns %d\n", ret);
    if (ret != 0)
        return 0;
    return 1;
}

static int test_pct_null_keys_mldsa(void)
{
    QUDO_MLDSA *sig;
    int ret;

    ensure_module_ready();

    sig = QUDO_MLDSA_new("ML-DSA-44");
    if (sig == NULL)
        return 0;

    VLOG("Calling mldsa_pct(sig, NULL, NULL) — valid instance, no keys\n");
    ret = qudo_pqc_mldsa_pct(sig, NULL, NULL);
    QUDO_MLDSA_free(sig);

    VLOG("Expected: returns 0 (error)\n");
    VLOG("Got:      returns %d\n", ret);
    if (ret != 0)
        return 0;
    return 1;
}

static int test_pct_null_keys_slhdsa(void)
{
    QUDO_SLHDSA *sig;
    int ret;

    ensure_module_ready();

    sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    if (sig == NULL)
        return 0;

    VLOG("Calling slhdsa_pct(sig, NULL, NULL) — valid instance, no keys\n");
    ret = qudo_pqc_slhdsa_pct(sig, NULL, NULL);
    QUDO_SLHDSA_free(sig);

    VLOG("Expected: returns 0 (error)\n");
    VLOG("Got:      returns %d\n", ret);
    if (ret != 0)
        return 0;
    return 1;
}

static int run_section(const char *filter, const char *name)
{
    if (filter == NULL)
        return 1;
    return (strcmp(filter, name) == 0);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [SECTION]\n\n", prog);
    printf("Sections:\n");
    printf("  --mlkem        ML-KEM PCT (all security levels)\n");
    printf("  --mldsa        ML-DSA PCT (all security levels)\n");
    printf("  --slhdsa       SLH-DSA PCT (fast parameter sets)\n");
    printf("  --edge         Edge cases (NULL instance, NULL keys)\n");
    printf("  (no args)      Run all sections\n");
}

int main(int argc, char *argv[])
{
    test_fips_init_set_args(&argc, argv);
    const char *section = NULL;

    if (argc >= 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        section = argv[1];
    }

    printf("=== QUDO PQC PCT Tests ===\n");
#ifdef QUDO_FIPS_MODULE
    printf("Build mode: FIPS\n");
#else
    printf("Build mode: Standard\n");
#endif
    printf("Sections: --mlkem --mldsa --slhdsa --edge\n\n");

    if (section != NULL)
        g_verbose = 1;

    if (run_section(section, "--mlkem")) {
        printf("[ML-KEM PCT — All Security Levels]\n");
        RUN_TEST(test_mlkem_pct_512);
        RUN_TEST(test_mlkem_pct_768);
        RUN_TEST(test_mlkem_pct_1024);
    }

    if (run_section(section, "--mldsa")) {
        printf("\n[ML-DSA PCT — All Security Levels]\n");
        RUN_TEST(test_mldsa_pct_44);
        RUN_TEST(test_mldsa_pct_65);
        RUN_TEST(test_mldsa_pct_87);
    }

    if (run_section(section, "--slhdsa")) {
        printf("\n[SLH-DSA PCT — Fast Parameter Sets]\n");
        RUN_TEST(test_slhdsa_pct_sha2_128s);
        RUN_TEST(test_slhdsa_pct_sha2_128f);
        RUN_TEST(test_slhdsa_pct_sha2_192s);
        RUN_TEST(test_slhdsa_pct_sha2_192f);
        RUN_TEST(test_slhdsa_pct_sha2_256s);
        RUN_TEST(test_slhdsa_pct_sha2_256f);
        RUN_TEST(test_slhdsa_pct_shake_128s);
        RUN_TEST(test_slhdsa_pct_shake_128f);
        RUN_TEST(test_slhdsa_pct_shake_192s);
        RUN_TEST(test_slhdsa_pct_shake_192f);
        RUN_TEST(test_slhdsa_pct_shake_256s);
        RUN_TEST(test_slhdsa_pct_shake_256f);
    }

    if (run_section(section, "--edge")) {
        printf("\n[Edge Cases — NULL Instance]\n");
        RUN_TEST(test_pct_null_kem_instance);
        RUN_TEST(test_pct_null_mldsa_instance);
        RUN_TEST(test_pct_null_slhdsa_instance);

        printf("\n[Edge Cases — NULL Keys]\n");
        RUN_TEST(test_pct_null_keys_kem);
        RUN_TEST(test_pct_null_keys_mldsa);
        RUN_TEST(test_pct_null_keys_slhdsa);
    }

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n", g_pass,
           g_fail, g_skip);

    return g_fail > 0 ? 1 : 0;
}
