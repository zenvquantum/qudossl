/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/mlkem_wrapper.h"
#include "../include/mlkem_config.h"
#include "../include/mlkem_error.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-50s ", tests_run, name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

static void test_new_by_name(void) {
    const char *algs[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
    size_t expected_pk[] = {
        QUDO_KEM_512_PUBLIC_KEY_BYTES,
        QUDO_KEM_768_PUBLIC_KEY_BYTES,
        QUDO_KEM_1024_PUBLIC_KEY_BYTES
    };
    size_t expected_sk[] = {
        QUDO_KEM_512_SECRET_KEY_BYTES,
        QUDO_KEM_768_SECRET_KEY_BYTES,
        QUDO_KEM_1024_SECRET_KEY_BYTES
    };

    for (int i = 0; i < 3; i++) {
        TEST("QUDO_KEM_new() with valid name");
        QUDO_KEM *kem = QUDO_KEM_new(algs[i]);
        if (!kem) { FAIL("returned NULL"); continue; }
        if (kem->length_public_key != expected_pk[i]) { FAIL("wrong pk size"); QUDO_KEM_free(kem); continue; }
        if (kem->length_secret_key != expected_sk[i]) { FAIL("wrong sk size"); QUDO_KEM_free(kem); continue; }
        if (strcmp(kem->algorithm_name, algs[i]) != 0) { FAIL("wrong name"); QUDO_KEM_free(kem); continue; }
        if (!kem->ind_cca) { FAIL("should be IND-CCA2"); QUDO_KEM_free(kem); continue; }
        QUDO_KEM_free(kem);
        PASS();
    }
}

static void test_new_invalid(void) {
    TEST("QUDO_KEM_new(NULL)");
    QUDO_KEM *kem = QUDO_KEM_new(NULL);
    if (kem != NULL) { FAIL("should return NULL"); QUDO_KEM_free(kem); } else { PASS(); }

    TEST("QUDO_KEM_new(\"invalid\")");
    kem = QUDO_KEM_new("invalid-algorithm");
    if (kem != NULL) { FAIL("should return NULL"); QUDO_KEM_free(kem); } else { PASS(); }

    TEST("QUDO_KEM_new(\"\")");
    kem = QUDO_KEM_new("");
    if (kem != NULL) { FAIL("should return NULL"); QUDO_KEM_free(kem); } else { PASS(); }
}

static void test_new_by_level(void) {
    QUDO_KEM_security_level_t levels[] = { QUDO_KEM_LEVEL_512, QUDO_KEM_LEVEL_768, QUDO_KEM_LEVEL_1024 };
    const char *names[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

    for (int i = 0; i < 3; i++) {
        TEST("QUDO_KEM_new_by_level() valid level");
        QUDO_KEM *kem = QUDO_KEM_new_by_level(levels[i]);
        if (!kem) { FAIL("returned NULL"); continue; }
        if (strcmp(kem->algorithm_name, names[i]) != 0) { FAIL("wrong algorithm"); QUDO_KEM_free(kem); continue; }
        QUDO_KEM_free(kem);
        PASS();
    }

    TEST("QUDO_KEM_new_by_level(invalid)");
    QUDO_KEM *kem = QUDO_KEM_new_by_level(99);
    if (kem != NULL) { FAIL("should return NULL"); QUDO_KEM_free(kem); } else { PASS(); }
}

static void test_free_null(void) {
    TEST("QUDO_KEM_free(NULL)");
    QUDO_KEM_free(NULL);
    PASS();
}

static void test_keypair_all_levels(void) {
    QUDO_KEM_security_level_t levels[] = { QUDO_KEM_LEVEL_512, QUDO_KEM_LEVEL_768, QUDO_KEM_LEVEL_1024 };

    for (int i = 0; i < 3; i++) {
        TEST("QUDO_KEM_keypair() full cycle");
        QUDO_KEM *kem = QUDO_KEM_new_by_level(levels[i]);
        if (!kem) { FAIL("new failed"); continue; }

        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        uint8_t *ct = malloc(kem->length_ciphertext);
        uint8_t *ss1 = malloc(kem->length_shared_secret);
        uint8_t *ss2 = malloc(kem->length_shared_secret);

        QUDO_KEM_status_t rc = QUDO_KEM_keypair(kem, pk, sk);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("keypair failed"); goto cleanup_cycle; }

        rc = QUDO_KEM_encaps(kem, ct, ss1, pk);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("encaps failed"); goto cleanup_cycle; }

        rc = QUDO_KEM_decaps(kem, ss2, ct, sk);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("decaps failed"); goto cleanup_cycle; }

        if (memcmp(ss1, ss2, kem->length_shared_secret) != 0) {
            FAIL("shared secrets don't match");
            goto cleanup_cycle;
        }
        PASS();
cleanup_cycle:
        free(pk); free(sk); free(ct); free(ss1); free(ss2);
        QUDO_KEM_free(kem);
    }
}

static void test_keypair_null_args(void) {
    TEST("QUDO_KEM_keypair(NULL kem)");
    uint8_t buf[4096];
    QUDO_KEM_status_t rc = QUDO_KEM_keypair(NULL, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_keypair(NULL pk)");
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-512");
    if (!kem) { FAIL("new failed"); return; }
    rc = QUDO_KEM_keypair(kem, NULL, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
    QUDO_KEM_free(kem);

    TEST("QUDO_KEM_keypair(NULL sk)");
    kem = QUDO_KEM_new("ML-KEM-512");
    if (!kem) { FAIL("new failed"); return; }
    rc = QUDO_KEM_keypair(kem, buf, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
    QUDO_KEM_free(kem);
}

static void test_encaps_null_args(void) {
    TEST("QUDO_KEM_encaps(NULL kem)");
    uint8_t buf[4096];
    QUDO_KEM_status_t rc = QUDO_KEM_encaps(NULL, buf, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-512");
    if (!kem) { return; }

    TEST("QUDO_KEM_encaps(NULL ct)");
    rc = QUDO_KEM_encaps(kem, NULL, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_encaps(NULL ss)");
    rc = QUDO_KEM_encaps(kem, buf, NULL, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_encaps(NULL pk)");
    rc = QUDO_KEM_encaps(kem, buf, buf, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_KEM_free(kem);
}

static void test_decaps_null_args(void) {
    TEST("QUDO_KEM_decaps(NULL kem)");
    uint8_t buf[4096];
    QUDO_KEM_status_t rc = QUDO_KEM_decaps(NULL, buf, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
    if (!kem) { return; }

    TEST("QUDO_KEM_decaps(NULL ss)");
    rc = QUDO_KEM_decaps(kem, NULL, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_decaps(NULL ct)");
    rc = QUDO_KEM_decaps(kem, buf, NULL, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_decaps(NULL sk)");
    rc = QUDO_KEM_decaps(kem, buf, buf, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_KEM_free(kem);
}

static void test_keypair_derand(void) {
    QUDO_KEM_security_level_t levels[] = { QUDO_KEM_LEVEL_512, QUDO_KEM_LEVEL_768, QUDO_KEM_LEVEL_1024 };

    for (int i = 0; i < 3; i++) {
        TEST("QUDO_KEM_keypair_derand() with seed");
        QUDO_KEM *kem = QUDO_KEM_new_by_level(levels[i]);
        if (!kem) { FAIL("new failed"); continue; }

        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        uint8_t seed[QUDO_KEM_SEED_BYTES];

        QUDO_KEM_status_t rc = QUDO_KEM_keypair_derand(kem, pk, sk, seed,
                                                       sizeof(seed));
        if (rc != QUDO_KEM_SUCCESS) { FAIL("keypair_derand failed"); }
        else {

            uint8_t zero[QUDO_KEM_SEED_BYTES];
            memset(zero, 0, sizeof(zero));
            if (memcmp(seed, zero, sizeof(zero)) == 0) { FAIL("seed all zeros"); }
            else { PASS(); }
        }

        free(pk); free(sk);
        QUDO_KEM_free(kem);
    }

    TEST("QUDO_KEM_keypair_derand(NULL seed) permitted");
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-512");
    if (kem) {
        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);

        QUDO_KEM_status_t rc = QUDO_KEM_keypair_derand(kem, pk, sk, NULL, 0);
        if (rc == QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("NULL seed_out should succeed"); }
        free(pk); free(sk);
        QUDO_KEM_free(kem);
    }
}

static void test_encaps_derand(void) {
    const char *levels[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", NULL };

    for (int li = 0; levels[li] != NULL; li++) {
        TEST("QUDO_KEM_encaps_derand() deterministic");
        QUDO_KEM *kem = QUDO_KEM_new(levels[li]);
        if (!kem) { FAIL("new failed"); continue; }

        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        uint8_t *ct1 = malloc(kem->length_ciphertext);
        uint8_t *ct2 = malloc(kem->length_ciphertext);
        uint8_t *ss1 = malloc(kem->length_shared_secret);
        uint8_t *ss2 = malloc(kem->length_shared_secret);

        QUDO_KEM_keypair(kem, pk, sk);

        uint8_t randomness[32];
        memset(randomness, 0x42, sizeof(randomness));

        QUDO_KEM_status_t rc1 = QUDO_KEM_encaps_derand(kem, ct1, ss1, pk, randomness);
        QUDO_KEM_status_t rc2 = QUDO_KEM_encaps_derand(kem, ct2, ss2, pk, randomness);

        if (rc1 != QUDO_KEM_SUCCESS || rc2 != QUDO_KEM_SUCCESS) {
            FAIL("encaps_derand failed");
        } else if (memcmp(ct1, ct2, kem->length_ciphertext) != 0) {
            FAIL("ciphertexts differ for same randomness");
        } else if (memcmp(ss1, ss2, kem->length_shared_secret) != 0) {
            FAIL("shared secrets differ for same randomness");
        } else {
            PASS();
        }

        free(pk); free(sk); free(ct1); free(ct2); free(ss1); free(ss2);
        QUDO_KEM_free(kem);
    }
}

static void test_direct_api(void) {
    TEST("QUDO_KEM_init/cleanup/is_initialized");
    QUDO_KEM_status_t rc = QUDO_KEM_init();
    if (rc != QUDO_KEM_SUCCESS) { FAIL("init failed"); return; }
    if (!QUDO_KEM_is_initialized()) { FAIL("not initialized"); QUDO_KEM_cleanup(); return; }
    PASS();

    QUDO_KEM_security_level_t levels[] = { QUDO_KEM_LEVEL_512, QUDO_KEM_LEVEL_768, QUDO_KEM_LEVEL_1024 };
    size_t pk_sizes[] = {
        QUDO_KEM_512_PUBLIC_KEY_BYTES,
        QUDO_KEM_768_PUBLIC_KEY_BYTES,
        QUDO_KEM_1024_PUBLIC_KEY_BYTES
    };
    size_t sk_sizes[] = {
        QUDO_KEM_512_SECRET_KEY_BYTES,
        QUDO_KEM_768_SECRET_KEY_BYTES,
        QUDO_KEM_1024_SECRET_KEY_BYTES
    };
    size_t ct_sizes[] = {
        QUDO_KEM_512_CIPHERTEXT_BYTES,
        QUDO_KEM_768_CIPHERTEXT_BYTES,
        QUDO_KEM_1024_CIPHERTEXT_BYTES
    };

    for (int i = 0; i < 3; i++) {
        TEST("Direct API keypair/encaps/decaps cycle");
        uint8_t *pk = malloc(pk_sizes[i]);
        uint8_t *sk = malloc(sk_sizes[i]);
        uint8_t *ct = malloc(ct_sizes[i]);
        uint8_t ss1[32], ss2[32];

        rc = QUDO_KEM_keypair_generate(levels[i], pk, sk);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("keypair_generate failed"); goto dcleanup; }

        rc = QUDO_KEM_encapsulate(levels[i], ct, ss1, pk);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("encapsulate failed"); goto dcleanup; }

        rc = QUDO_KEM_decapsulate(levels[i], ss2, ct, sk);
        if (rc != QUDO_KEM_SUCCESS) { FAIL("decapsulate failed"); goto dcleanup; }

        if (memcmp(ss1, ss2, 32) != 0) { FAIL("shared secrets mismatch"); goto dcleanup; }
        PASS();
dcleanup:
        free(pk); free(sk); free(ct);
    }

    TEST("Direct API invalid level");
    uint8_t buf[4096];
    rc = QUDO_KEM_keypair_generate(99, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("Direct API NULL args keypair_generate");
    rc = QUDO_KEM_keypair_generate(QUDO_KEM_LEVEL_512, NULL, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("Direct API NULL args encapsulate");
    rc = QUDO_KEM_encapsulate(QUDO_KEM_LEVEL_512, NULL, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("Direct API NULL args decapsulate");
    rc = QUDO_KEM_decapsulate(QUDO_KEM_LEVEL_512, NULL, buf, buf);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_KEM_cleanup();

    TEST("QUDO_KEM_is_initialized after cleanup");
    if (QUDO_KEM_is_initialized()) { FAIL("should not be initialized"); } else { PASS(); }
}

static void test_get_sizes(void) {
    TEST("QUDO_KEM_get_public_key_size()");
    if (QUDO_KEM_get_public_key_size(QUDO_KEM_LEVEL_512) == QUDO_KEM_512_PUBLIC_KEY_BYTES &&
        QUDO_KEM_get_public_key_size(QUDO_KEM_LEVEL_768) == QUDO_KEM_768_PUBLIC_KEY_BYTES &&
        QUDO_KEM_get_public_key_size(QUDO_KEM_LEVEL_1024) == QUDO_KEM_1024_PUBLIC_KEY_BYTES &&
        QUDO_KEM_get_public_key_size(99) == 0) { PASS(); } else { FAIL("wrong size"); }

    TEST("QUDO_KEM_get_secret_key_size()");
    if (QUDO_KEM_get_secret_key_size(QUDO_KEM_LEVEL_512) == QUDO_KEM_512_SECRET_KEY_BYTES &&
        QUDO_KEM_get_secret_key_size(QUDO_KEM_LEVEL_768) == QUDO_KEM_768_SECRET_KEY_BYTES &&
        QUDO_KEM_get_secret_key_size(QUDO_KEM_LEVEL_1024) == QUDO_KEM_1024_SECRET_KEY_BYTES &&
        QUDO_KEM_get_secret_key_size(99) == 0) { PASS(); } else { FAIL("wrong size"); }

    TEST("QUDO_KEM_get_ciphertext_size()");
    if (QUDO_KEM_get_ciphertext_size(QUDO_KEM_LEVEL_512) == QUDO_KEM_512_CIPHERTEXT_BYTES &&
        QUDO_KEM_get_ciphertext_size(QUDO_KEM_LEVEL_768) == QUDO_KEM_768_CIPHERTEXT_BYTES &&
        QUDO_KEM_get_ciphertext_size(QUDO_KEM_LEVEL_1024) == QUDO_KEM_1024_CIPHERTEXT_BYTES &&
        QUDO_KEM_get_ciphertext_size(99) == 0) { PASS(); } else { FAIL("wrong size"); }

    TEST("QUDO_KEM_get_shared_secret_size()");

    if (QUDO_KEM_get_shared_secret_size(QUDO_KEM_LEVEL_512) == QUDO_KEM_512_SHARED_SECRET_BYTES &&
        QUDO_KEM_get_shared_secret_size(QUDO_KEM_LEVEL_768) == QUDO_KEM_768_SHARED_SECRET_BYTES &&
        QUDO_KEM_get_shared_secret_size(QUDO_KEM_LEVEL_1024) == QUDO_KEM_1024_SHARED_SECRET_BYTES &&
        QUDO_KEM_get_shared_secret_size(99) == 0) { PASS(); } else { FAIL("wrong size"); }
}

static void test_algorithm_name(void) {
    TEST("QUDO_KEM_get_algorithm_name()");
    const char *n512 = QUDO_KEM_get_algorithm_name(QUDO_KEM_LEVEL_512);
    const char *n768 = QUDO_KEM_get_algorithm_name(QUDO_KEM_LEVEL_768);
    const char *n1024 = QUDO_KEM_get_algorithm_name(QUDO_KEM_LEVEL_1024);
    const char *ninv = QUDO_KEM_get_algorithm_name(99);
    if (n512 && strcmp(n512, "ML-KEM-512") == 0 &&
        n768 && strcmp(n768, "ML-KEM-768") == 0 &&
        n1024 && strcmp(n1024, "ML-KEM-1024") == 0 &&
        ninv == NULL) { PASS(); } else { FAIL("wrong name"); }
}

static void test_level_from_name(void) {
    TEST("QUDO_KEM_get_level_from_name() valid");
    QUDO_KEM_security_level_t level;
    QUDO_KEM_status_t rc;

    rc = QUDO_KEM_get_level_from_name("ML-KEM-512", &level);
    if (rc != QUDO_KEM_SUCCESS || level != QUDO_KEM_LEVEL_512) { FAIL("512 failed"); return; }
    rc = QUDO_KEM_get_level_from_name("ML-KEM-768", &level);
    if (rc != QUDO_KEM_SUCCESS || level != QUDO_KEM_LEVEL_768) { FAIL("768 failed"); return; }
    rc = QUDO_KEM_get_level_from_name("ML-KEM-1024", &level);
    if (rc != QUDO_KEM_SUCCESS || level != QUDO_KEM_LEVEL_1024) { FAIL("1024 failed"); return; }
    PASS();

    TEST("QUDO_KEM_get_level_from_name() invalid");
    rc = QUDO_KEM_get_level_from_name("invalid", &level);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_get_level_from_name(NULL)");
    rc = QUDO_KEM_get_level_from_name(NULL, &level);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_get_level_from_name(NULL level)");
    rc = QUDO_KEM_get_level_from_name("ML-KEM-512", NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
}

static void test_list_algorithms(void) {
    TEST("QUDO_KEM_list_algorithms()");
    size_t count = 0;
    const char **algs = QUDO_KEM_list_algorithms(&count);
    if (!algs) { FAIL("returned NULL"); return; }
    if (count != 3) { FAIL("expected 3 algorithms"); return; }

    int found[3] = {0, 0, 0};
    for (size_t i = 0; i < count; i++) {
        if (strcmp(algs[i], "ML-KEM-512") == 0) found[0] = 1;
        if (strcmp(algs[i], "ML-KEM-768") == 0) found[1] = 1;
        if (strcmp(algs[i], "ML-KEM-1024") == 0) found[2] = 1;
    }
    if (found[0] && found[1] && found[2]) { PASS(); } else { FAIL("missing algorithm"); }

    TEST("QUDO_KEM_list_algorithms(NULL count)");
    algs = QUDO_KEM_list_algorithms(NULL);
    if (algs == NULL) { PASS(); } else { FAIL("should return NULL"); }
}

static void test_is_algorithm_supported(void) {
    TEST("QUDO_KEM_is_algorithm_supported() valid");
    if (QUDO_KEM_is_algorithm_supported("ML-KEM-512") &&
        QUDO_KEM_is_algorithm_supported("ML-KEM-768") &&
        QUDO_KEM_is_algorithm_supported("ML-KEM-1024")) { PASS(); } else { FAIL("should be supported"); }

    TEST("QUDO_KEM_is_algorithm_supported() invalid");
    if (!QUDO_KEM_is_algorithm_supported("invalid") &&
        !QUDO_KEM_is_algorithm_supported(NULL) &&
        !QUDO_KEM_is_algorithm_supported("")) { PASS(); } else { FAIL("should not be supported"); }
}

static void test_get_algorithm_info(void) {
    TEST("QUDO_KEM_get_algorithm_info() valid");
    const QUDO_KEM *info = NULL;
    QUDO_KEM_status_t rc = QUDO_KEM_get_algorithm_info("ML-KEM-768", &info);
    if (rc != QUDO_KEM_SUCCESS || !info) { FAIL("failed"); return; }
    if (info->length_public_key != QUDO_KEM_768_PUBLIC_KEY_BYTES) { FAIL("wrong pk size"); return; }
    PASS();

    TEST("QUDO_KEM_get_algorithm_info(NULL)");
    rc = QUDO_KEM_get_algorithm_info(NULL, &info);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_get_algorithm_info(NULL output)");
    rc = QUDO_KEM_get_algorithm_info("ML-KEM-512", NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_get_algorithm_info(invalid)");
    rc = QUDO_KEM_get_algorithm_info("invalid", &info);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
}

static void test_get_version(void) {
    TEST("QUDO_KEM_get_version()");
    const char *ver = QUDO_KEM_get_version();
    if (ver && strlen(ver) > 0) { PASS(); } else { FAIL("empty version"); }
}

static void test_get_error_string(void) {
    TEST("QUDO_KEM_error_string() all codes");

    const char *s;
    s = QUDO_KEM_error_string(QUDO_KEM_SUCCESS);
    if (!s || strlen(s) == 0) { FAIL("SUCCESS"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR);
    if (!s || strlen(s) == 0) { FAIL("ERROR"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_INVALID_ARG);
    if (!s || strlen(s) == 0) { FAIL("INVALID_ARG"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_NULL_PTR);
    if (!s || strlen(s) == 0) { FAIL("NULL_PTR"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_ALLOC);
    if (!s || strlen(s) == 0) { FAIL("ALLOC"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_RNG);
    if (!s || strlen(s) == 0) { FAIL("RNG"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_NOT_IMPL);
    if (!s || strlen(s) == 0) { FAIL("NOT_IMPL"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_CRYPTO);
    if (!s || strlen(s) == 0) { FAIL("CRYPTO"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_FILE_IO);
    if (!s || strlen(s) == 0) { FAIL("FILE_IO"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_ENCODE);
    if (!s || strlen(s) == 0) { FAIL("ENCODE"); return; }

    s = QUDO_KEM_error_string(QUDO_KEM_ERROR_BUFFER_TOO_SMALL);
    if (!s || strlen(s) == 0) { FAIL("BUFFER_TOO_SMALL"); return; }

    s = QUDO_KEM_error_string(-999);
    if (!s) { FAIL("unknown code returned NULL"); return; }

    PASS();
}

static void test_config_default(void) {
    TEST("QUDO_KEM_config_default()");
    QUDO_KEM_config_t *cfg = QUDO_KEM_config_default();
    if (!cfg) { FAIL("returned NULL"); return; }
    if (!cfg->enable_512 || !cfg->enable_768 || !cfg->enable_1024) { FAIL("levels disabled"); QUDO_KEM_config_free(cfg); return; }
    if (!cfg->use_avx2) { FAIL("avx2 disabled"); QUDO_KEM_config_free(cfg); return; }
    if (!cfg->use_openssl) { FAIL("openssl disabled"); QUDO_KEM_config_free(cfg); return; }
    QUDO_KEM_config_free(cfg);
    PASS();
}

static void test_config_free_null(void) {
    TEST("QUDO_KEM_config_free(NULL)");
    QUDO_KEM_config_free(NULL);
    PASS();
}

static void test_config_validate(void) {
    TEST("QUDO_KEM_config_validate() valid");
    QUDO_KEM_config_t *cfg = QUDO_KEM_config_default();
    if (!cfg) { FAIL("default failed"); return; }
    if (QUDO_KEM_config_validate(cfg) != QUDO_KEM_SUCCESS) { FAIL("should be valid"); }
    else { PASS(); }
    QUDO_KEM_config_free(cfg);

    TEST("QUDO_KEM_config_validate(NULL)");
    if (QUDO_KEM_config_validate(NULL) != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_config_validate() all disabled");
    cfg = QUDO_KEM_config_default();
    if (!cfg) { FAIL("default failed"); return; }
    cfg->enable_512 = 0;
    cfg->enable_768 = 0;
    cfg->enable_1024 = 0;
    if (QUDO_KEM_config_validate(cfg) != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
    QUDO_KEM_config_free(cfg);
}

static void test_config_apply(void) {
    TEST("QUDO_KEM_config_apply() valid");
    QUDO_KEM_config_t *cfg = QUDO_KEM_config_default();
    if (!cfg) { FAIL("default failed"); return; }
    if (QUDO_KEM_config_apply(cfg) != QUDO_KEM_SUCCESS) { FAIL("apply failed"); }
    else { PASS(); }
    QUDO_KEM_config_free(cfg);

    TEST("QUDO_KEM_config_apply(NULL)");
    if (QUDO_KEM_config_apply(NULL) != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_config_apply() invalid config");
    cfg = QUDO_KEM_config_default();
    if (!cfg) { FAIL("default failed"); return; }
    cfg->enable_512 = 0;
    cfg->enable_768 = 0;
    cfg->enable_1024 = 0;
    if (QUDO_KEM_config_apply(cfg) != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
    QUDO_KEM_config_free(cfg);
}

static void test_config_save_load(void) {
    TEST("QUDO_KEM_config_save/load round-trip");
    QUDO_KEM_config_t *cfg = QUDO_KEM_config_default();
    if (!cfg) { FAIL("default failed"); return; }

    const char *tmpdir = getenv("TEMP");
    if (!tmpdir) tmpdir = getenv("TMP");
    if (!tmpdir) tmpdir = "/tmp";
    char tmpfile_buf[512];
    snprintf(tmpfile_buf, sizeof(tmpfile_buf), "%s/test_mlkem_config.ini", tmpdir);
    const char *tmpfile = tmpfile_buf;
    int rc = QUDO_KEM_config_save(cfg, tmpfile);
    if (rc != QUDO_KEM_SUCCESS) { FAIL("save failed"); QUDO_KEM_config_free(cfg); return; }

    QUDO_KEM_config_t *loaded = QUDO_KEM_config_load(tmpfile);
    if (!loaded) { FAIL("load failed"); QUDO_KEM_config_free(cfg); return; }

    if (loaded->enable_512 != cfg->enable_512 ||
        loaded->enable_768 != cfg->enable_768 ||
        loaded->enable_1024 != cfg->enable_1024) {
        FAIL("config mismatch after load");
    } else {
        PASS();
    }

    QUDO_KEM_config_free(cfg);
    QUDO_KEM_config_free(loaded);
    remove(tmpfile);

    TEST("QUDO_KEM_config_save(NULL)");
    rc = QUDO_KEM_config_save(NULL, tmpfile);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_config_save(NULL file)");
    cfg = QUDO_KEM_config_default();
    rc = QUDO_KEM_config_save(cfg, NULL);
    if (rc != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }
    QUDO_KEM_config_free(cfg);

    TEST("QUDO_KEM_config_load(NULL)");
    loaded = QUDO_KEM_config_load(NULL);
    if (loaded) {

        PASS();
        QUDO_KEM_config_free(loaded);
    } else { FAIL("should return default"); }

    TEST("QUDO_KEM_config_load(nonexistent file)");
    loaded = QUDO_KEM_config_load("/tmp/nonexistent_mlkem_config_xyz.ini");
    if (loaded) {

        PASS();
        QUDO_KEM_config_free(loaded);
    } else { FAIL("should return default"); }
}

static void test_rng(void) {
    TEST("QUDO_KEM_randombytes_init()");
    if (QUDO_KEM_randombytes_init() == QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("init failed"); }

    TEST("QUDO_KEM_randombytes_test()");
    if (QUDO_KEM_randombytes_test() == QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("test failed"); }

    TEST("QUDO_KEM_randombytes() valid");
    uint8_t buf[64];
    if (QUDO_KEM_randombytes(buf, sizeof(buf)) == QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("failed"); }

    TEST("QUDO_KEM_randombytes(NULL)");
    if (QUDO_KEM_randombytes(NULL, 32) != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_randombytes(0 len)");
    if (QUDO_KEM_randombytes(buf, 0) != QUDO_KEM_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_KEM_randombytes_cleanup()");
    QUDO_KEM_randombytes_cleanup();
    PASS();
}

int main(void) {
    printf("=== QUDO ML-KEM Object API & Utility Tests ===\n\n");

    printf("[Object API]\n");
    test_new_by_name();
    test_new_invalid();
    test_new_by_level();
    test_free_null();
    test_keypair_all_levels();
    test_keypair_null_args();
    test_encaps_null_args();
    test_decaps_null_args();
    test_keypair_derand();
    test_encaps_derand();

    printf("\n[Direct API]\n");
    test_direct_api();

    printf("\n[Utility Functions]\n");
    test_get_sizes();
    test_algorithm_name();
    test_level_from_name();
    test_list_algorithms();
    test_is_algorithm_supported();
    test_get_algorithm_info();
    test_get_version();
    test_get_error_string();

    printf("\n[Config]\n");
    test_config_default();
    test_config_free_null();
    test_config_validate();
    test_config_apply();
    test_config_save_load();

    printf("\n[RNG]\n");
    test_rng();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
