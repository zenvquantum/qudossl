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

static int test_check_pk_valid(void)
{
    const char *algs[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    int i;

    for (i = 0; i < 3; i++) {
        QUDO_KEM *kem = QUDO_KEM_new(algs[i]);
        CHECK(kem != NULL, "QUDO_KEM_new");

        uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
        CHECK(pk && sk, "malloc");

        CHECK(QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS, "keypair");
        CHECK(QUDO_KEM_check_pk(kem, pk, kem->length_public_key)
                  == QUDO_KEM_SUCCESS,
              "check_pk valid");
        CHECK(QUDO_KEM_check_sk(kem, sk, kem->length_secret_key)
                  == QUDO_KEM_SUCCESS,
              "check_sk valid");

        free(pk);
        free(sk);
        QUDO_KEM_free(kem);
    }
    return 1;
}

static int test_check_pk_wrong_length(void)
{
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-512");
    CHECK(kem != NULL, "QUDO_KEM_new");

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
    CHECK(pk && sk, "malloc");
    CHECK(QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS, "keypair");

    CHECK(QUDO_KEM_check_pk(kem, pk, kem->length_public_key + 1)
              == QUDO_KEM_ERROR_VERIFY,
          "check_pk too long rejected");

    CHECK(QUDO_KEM_check_pk(kem, pk, kem->length_public_key - 1)
              == QUDO_KEM_ERROR_VERIFY,
          "check_pk too short rejected");

    CHECK(QUDO_KEM_check_pk(kem, pk, 0) == QUDO_KEM_ERROR_VERIFY,
          "check_pk zero length rejected");

    CHECK(QUDO_KEM_check_sk(kem, sk, kem->length_secret_key + 416)
              == QUDO_KEM_ERROR_VERIFY,
          "check_sk wrong length rejected");

    free(pk);
    free(sk);
    QUDO_KEM_free(kem);
    return 1;
}

static int test_check_pk_corrupted(void)
{
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
    CHECK(kem != NULL, "QUDO_KEM_new");

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
    CHECK(pk && sk, "malloc");
    CHECK(QUDO_KEM_keypair(kem, pk, sk) == QUDO_KEM_SUCCESS, "keypair");

    CHECK(QUDO_KEM_check_pk(kem, pk, kem->length_public_key)
              == QUDO_KEM_SUCCESS,
          "check_pk valid before corruption");

    pk[0] = 0xFF;
    pk[1] = 0xFF;

    QUDO_KEM_status_t rc = QUDO_KEM_check_pk(kem, pk, kem->length_public_key);
    if (g_verbose)
        printf("    Corrupted pk check: %s\n",
               rc == QUDO_KEM_SUCCESS ? "valid (within modulus)" : "invalid");

    free(pk);
    free(sk);
    QUDO_KEM_free(kem);
    return 1;
}

static int test_check_pk_null(void)
{
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-512");
    CHECK(kem != NULL, "QUDO_KEM_new");

    CHECK(QUDO_KEM_check_pk(kem, NULL, 800) == QUDO_KEM_ERROR_INVALID_ARG,
          "check_pk NULL rejected");
    CHECK(QUDO_KEM_check_pk(NULL, (uint8_t *)1, 800)
              == QUDO_KEM_ERROR_INVALID_ARG,
          "check_pk NULL kem rejected");
    CHECK(QUDO_KEM_check_sk(kem, NULL, 1632) == QUDO_KEM_ERROR_INVALID_ARG,
          "check_sk NULL rejected");

    QUDO_KEM_free(kem);
    return 1;
}

static int test_mldsa_prehash_roundtrip(void)
{

    static const struct {
        int alg;
        const char *name;
    } hash_algs[] = {
        {QUDO_PREHASH_SHA2_224, "SHA2-224"},
        {QUDO_PREHASH_SHA2_256, "SHA2-256"},
        {QUDO_PREHASH_SHA2_384, "SHA2-384"},
        {QUDO_PREHASH_SHA2_512, "SHA2-512"},
        {QUDO_PREHASH_SHA2_512_224, "SHA2-512/224"},
        {QUDO_PREHASH_SHA2_512_256, "SHA2-512/256"},
        {QUDO_PREHASH_SHA3_224, "SHA3-224"},
        {QUDO_PREHASH_SHA3_256, "SHA3-256"},
        {QUDO_PREHASH_SHA3_384, "SHA3-384"},
        {QUDO_PREHASH_SHA3_512, "SHA3-512"},
        {QUDO_PREHASH_SHAKE_128, "SHAKE-128"},
        {QUDO_PREHASH_SHAKE_256, "SHAKE-256"},
    };

    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    CHECK(sig != NULL, "QUDO_MLDSA_new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");

    CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

    const uint8_t msg[] = "Test message for pre-hash signing";
    size_t msg_len = sizeof(msg) - 1;
    uint8_t rnd[MLDSA_RNDBYTES];
    memset(rnd, 0x42, sizeof(rnd));
    int i;

    for (i = 0; i < 12; i++) {
        size_t sig_len = 0;
        QUDO_MLDSA_status_t rc;

        rc = QUDO_MLDSA_sign_pre_hash(sig, signature, &sig_len, msg, msg_len,
                                      NULL, 0, rnd, sk, hash_algs[i].alg);
        if (rc != QUDO_MLDSA_SUCCESS) {
            printf("    FAIL: sign_pre_hash(%s) returned %d\n",
                   hash_algs[i].name, rc);
            free(pk);
            free(sk);
            free(signature);
            QUDO_MLDSA_free(sig);
            return 0;
        }

        rc = QUDO_MLDSA_verify_pre_hash(sig, signature, sig_len, msg, msg_len,
                                        NULL, 0, pk, hash_algs[i].alg);
        if (rc != QUDO_MLDSA_SUCCESS) {
            printf("    FAIL: verify_pre_hash(%s) returned %d\n",
                   hash_algs[i].name, rc);
            free(pk);
            free(sk);
            free(signature);
            QUDO_MLDSA_free(sig);
            return 0;
        }

        if (g_verbose)
            printf("    OK: %s roundtrip\n", hash_algs[i].name);
    }

    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
    return 1;
}

static int test_mldsa_prehash_wrong_alg(void)
{
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    CHECK(sig != NULL, "QUDO_MLDSA_new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");
    CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

    const uint8_t msg[] = "Cross-algorithm test";
    uint8_t rnd[MLDSA_RNDBYTES];
    memset(rnd, 0, sizeof(rnd));
    size_t sig_len = 0;

    CHECK(QUDO_MLDSA_sign_pre_hash(sig, signature, &sig_len, msg,
                                   sizeof(msg) - 1, NULL, 0, rnd, sk,
                                   QUDO_PREHASH_SHA2_256)
              == QUDO_MLDSA_SUCCESS,
          "sign SHA2-256");

    CHECK(QUDO_MLDSA_verify_pre_hash(sig, signature, sig_len, msg,
                                     sizeof(msg) - 1, NULL, 0, pk,
                                     QUDO_PREHASH_SHA2_512)
              != QUDO_MLDSA_SUCCESS,
          "verify wrong alg rejected");

    free(pk);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
    return 1;
}

static int test_mldsa_prehash_all_levels(void)
{
    const char *algs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    int i;

    for (i = 0; i < 3; i++) {
        QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[i]);
        CHECK(sig != NULL, "QUDO_MLDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");
        CHECK(QUDO_MLDSA_keypair(sig, pk, sk) == QUDO_MLDSA_SUCCESS, "keypair");

        const uint8_t msg[] = "Level test";
        uint8_t rnd[MLDSA_RNDBYTES];
        memset(rnd, 0, sizeof(rnd));
        size_t sig_len = 0;

        CHECK(QUDO_MLDSA_sign_pre_hash(sig, signature, &sig_len, msg,
                                       sizeof(msg) - 1, NULL, 0, rnd, sk,
                                       QUDO_PREHASH_SHA3_256)
                  == QUDO_MLDSA_SUCCESS,
              "sign pre_hash");
        CHECK(QUDO_MLDSA_verify_pre_hash(sig, signature, sig_len, msg,
                                         sizeof(msg) - 1, NULL, 0, pk,
                                         QUDO_PREHASH_SHA3_256)
                  == QUDO_MLDSA_SUCCESS,
              "verify pre_hash");

        if (g_verbose)
            printf("    OK: %s pre-hash roundtrip\n", algs[i]);

        free(pk);
        free(sk);
        free(signature);
        QUDO_MLDSA_free(sig);
    }
    return 1;
}

static int test_slhdsa_prehash_roundtrip(void)
{

    static const char *param_sets[]
        = {"SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-256f"};
    static const char *hash_algs[] = {"SHA2-256", "SHA3-256"};
    int i;

    for (i = 0; i < 2; i++) {
        QUDO_SLHDSA *sig = QUDO_SLHDSA_new(param_sets[i]);
        CHECK(sig != NULL, "QUDO_SLHDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");
        CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS,
              "keypair");

        const uint8_t msg[] = "SLH-DSA pre-hash test message";
        size_t sig_len = sig->length_signature;

        CHECK(QUDO_SLHDSA_sign_pre_hash(sig, signature, &sig_len, msg,
                                        sizeof(msg) - 1, NULL, 0, hash_algs[i],
                                        NULL, sk)
                  == QUDO_SLHDSA_SUCCESS,
              "sign_pre_hash");

        CHECK(QUDO_SLHDSA_verify_pre_hash(sig, msg, sizeof(msg) - 1, signature,
                                          sig_len, NULL, 0, hash_algs[i], pk)
                  == QUDO_SLHDSA_SUCCESS,
              "verify_pre_hash");

        if (g_verbose)
            printf("    OK: %s + %s roundtrip\n", param_sets[i], hash_algs[i]);

        free(pk);
        free(sk);
        free(signature);
        QUDO_SLHDSA_free(sig);
    }
    return 1;
}

static int test_slhdsa_prehash_wrong_alg(void)
{
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    CHECK(sig != NULL, "QUDO_SLHDSA_new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");
    CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS, "keypair");

    const uint8_t msg[] = "Cross-alg test";
    size_t sig_len = sig->length_signature;

    CHECK(QUDO_SLHDSA_sign_pre_hash(sig, signature, &sig_len, msg,
                                    sizeof(msg) - 1, NULL, 0, "SHA2-256", NULL,
                                    sk)
              == QUDO_SLHDSA_SUCCESS,
          "sign SHA2-256");

    CHECK(QUDO_SLHDSA_verify_pre_hash(sig, msg, sizeof(msg) - 1, signature,
                                      sig_len, NULL, 0, "SHA2-512", pk)
              != QUDO_SLHDSA_SUCCESS,
          "verify wrong alg rejected");

    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return 1;
}

static int test_slhdsa_internal_roundtrip(void)
{
    static const char *param_sets[]
        = {"SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"};
    int i;

    for (i = 0; i < 2; i++) {
        QUDO_SLHDSA *sig = QUDO_SLHDSA_new(param_sets[i]);
        CHECK(sig != NULL, "QUDO_SLHDSA_new");

        uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        CHECK(pk && sk && signature, "malloc");
        CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS,
              "keypair");

        const uint8_t msg[] = "Internal mode test message";
        size_t sig_len = sig->length_signature;

        CHECK(QUDO_SLHDSA_sign_internal(sig, signature, &sig_len, msg,
                                        sizeof(msg) - 1, NULL, sk)
                  == QUDO_SLHDSA_SUCCESS,
              "sign_internal");

        CHECK(QUDO_SLHDSA_verify_internal(sig, msg, sizeof(msg) - 1, signature,
                                          sig_len, pk)
                  == QUDO_SLHDSA_SUCCESS,
              "verify_internal");

        if (g_verbose)
            printf("    OK: %s internal roundtrip\n", param_sets[i]);

        free(pk);
        free(sk);
        free(signature);
        QUDO_SLHDSA_free(sig);
    }
    return 1;
}

static int test_slhdsa_internal_vs_external(void)
{
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    CHECK(sig != NULL, "QUDO_SLHDSA_new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");
    CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS, "keypair");

    const uint8_t msg[] = "Internal vs external mismatch test";
    size_t sig_len = sig->length_signature;

    CHECK(QUDO_SLHDSA_sign_internal(sig, signature, &sig_len, msg,
                                    sizeof(msg) - 1, NULL, sk)
              == QUDO_SLHDSA_SUCCESS,
          "sign_internal");

    QUDO_SLHDSA_status_t rc
        = QUDO_SLHDSA_verify(sig, msg, sizeof(msg) - 1, signature, sig_len, pk);
    CHECK(rc != QUDO_SLHDSA_SUCCESS,
          "internal sig rejected by external verify");

    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return 1;
}

static int test_slhdsa_internal_corrupted(void)
{
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHAKE-128f");
    CHECK(sig != NULL, "QUDO_SLHDSA_new");

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    CHECK(pk && sk && signature, "malloc");
    CHECK(QUDO_SLHDSA_keypair(sig, pk, sk) == QUDO_SLHDSA_SUCCESS, "keypair");

    const uint8_t msg[] = "Corruption test";
    size_t sig_len = sig->length_signature;

    CHECK(QUDO_SLHDSA_sign_internal(sig, signature, &sig_len, msg,
                                    sizeof(msg) - 1, NULL, sk)
              == QUDO_SLHDSA_SUCCESS,
          "sign_internal");

    signature[sig_len / 2] ^= 0xFF;

    CHECK(QUDO_SLHDSA_verify_internal(sig, msg, sizeof(msg) - 1, signature,
                                      sig_len, pk)
              != QUDO_SLHDSA_SUCCESS,
          "corrupted sig rejected");

    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return 1;
}

static void usage(const char *prog)
{
    printf(
        "Usage: %s [--all|--check_pk|--mldsa_prehash|--slhdsa_prehash|--slhdsa_internal] [-v]\n",
        prog);
}

int main(int argc, char **argv)
{
    test_fips_init_set_args(&argc, argv);
    const char *section = "--all";
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0
                   || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            section = argv[i];
        }
    }

    if (strcmp(section, "--all") != 0 && strcmp(section, "--check_pk") != 0
        && strcmp(section, "--mldsa_prehash") != 0
        && strcmp(section, "--slhdsa_prehash") != 0
        && strcmp(section, "--slhdsa_internal") != 0) {
        fprintf(stderr, "Unknown option: %s\n", section);
        usage(argv[0]);
        return 1;
    }

    printf("=== QUDO PQC New API Tests ===\n\n");

    if (!test_fips_init()) {
        printf("qudo_pqc_init failed\n");
        return 1;
    }

    if (strcmp(section, "--all") == 0 || strcmp(section, "--check_pk") == 0) {
        printf("[ML-KEM check_pk / check_sk]\n");
        RUN_TEST(test_check_pk_valid);
        RUN_TEST(test_check_pk_wrong_length);
        RUN_TEST(test_check_pk_corrupted);
        RUN_TEST(test_check_pk_null);
        printf("\n");
    }

    if (strcmp(section, "--all") == 0
        || strcmp(section, "--mldsa_prehash") == 0) {
        printf("[ML-DSA sign_pre_hash / verify_pre_hash]\n");
        RUN_TEST(test_mldsa_prehash_roundtrip);
        RUN_TEST(test_mldsa_prehash_wrong_alg);
        RUN_TEST(test_mldsa_prehash_all_levels);
        printf("\n");
    }

    if (strcmp(section, "--all") == 0
        || strcmp(section, "--slhdsa_prehash") == 0) {
        printf("[SLH-DSA sign_pre_hash / verify_pre_hash]\n");
        RUN_TEST(test_slhdsa_prehash_roundtrip);
        RUN_TEST(test_slhdsa_prehash_wrong_alg);
        printf("\n");
    }

    if (strcmp(section, "--all") == 0
        || strcmp(section, "--slhdsa_internal") == 0) {
        printf("[SLH-DSA sign_internal / verify_internal]\n");
        RUN_TEST(test_slhdsa_internal_roundtrip);
        RUN_TEST(test_slhdsa_internal_vs_external);
        RUN_TEST(test_slhdsa_internal_corrupted);
        printf("\n");
    }

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
