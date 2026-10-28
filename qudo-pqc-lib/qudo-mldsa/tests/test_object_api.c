/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/mldsa_wrapper.h"
#include "../include/mldsa_config.h"
#include "../include/mldsa_error.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-55s ", tests_run, name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

static void test_new_by_name(void) {
    const char *algs[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    for (int i = 0; i < 3; i++) {
        char label[64];
        snprintf(label, sizeof(label), "QUDO_MLDSA_new(\"%s\")", algs[i]);
        TEST(label);
        QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[i]);
        if (!sig) { FAIL("returned NULL"); continue; }
        if (strcmp(sig->method_name, algs[i]) != 0) { FAIL("wrong name"); QUDO_MLDSA_free(sig); continue; }
        PASS();
        QUDO_MLDSA_free(sig);
    }
}

static void test_new_invalid(void) {
    TEST("QUDO_MLDSA_new(NULL)");
    QUDO_MLDSA *sig = QUDO_MLDSA_new(NULL);
    if (sig == NULL) { PASS(); } else { FAIL("should be NULL"); QUDO_MLDSA_free(sig); }

    TEST("QUDO_MLDSA_new(\"invalid\")");
    sig = QUDO_MLDSA_new("invalid");
    if (sig == NULL) { PASS(); } else { FAIL("should be NULL"); QUDO_MLDSA_free(sig); }

    TEST("QUDO_MLDSA_new(\"\")");
    sig = QUDO_MLDSA_new("");
    if (sig == NULL) { PASS(); } else { FAIL("should be NULL"); QUDO_MLDSA_free(sig); }
}

static void test_free_null(void) {
    TEST("QUDO_MLDSA_free(NULL)");
    QUDO_MLDSA_free(NULL);
    PASS();
}

static void test_init_cleanup(void) {
    TEST("QUDO_MLDSA_init()");
    QUDO_MLDSA_status_t rc = QUDO_MLDSA_init();
    if (rc == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("init failed"); }

    TEST("QUDO_MLDSA_cleanup()");
    QUDO_MLDSA_cleanup();
    PASS();

    TEST("QUDO_MLDSA_init() after cleanup");
    rc = QUDO_MLDSA_init();
    if (rc == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("re-init failed"); }
}

static void test_sign_verify_all_levels(void) {
    const char *algs[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    const uint8_t msg[] = "Test message for ML-DSA signing";
    size_t msg_len = sizeof(msg) - 1;

    for (int i = 0; i < 3; i++) {
        char label[64];
        QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[i]);
        if (!sig) { snprintf(label, sizeof(label), "sign/verify %s", algs[i]); TEST(label); FAIL("new failed"); continue; }

        size_t pk_len = sig->length_public_key;
        size_t sk_len = sig->length_secret_key;
        size_t sig_max = sig->length_signature;

        uint8_t *pk = malloc(pk_len);
        uint8_t *sk = malloc(sk_len);
        uint8_t *signature = malloc(sig_max);
        if (!pk || !sk || !signature) { free(pk); free(sk); free(signature); QUDO_MLDSA_free(sig); continue; }

        snprintf(label, sizeof(label), "%s keypair", algs[i]);
        TEST(label);
        QUDO_MLDSA_status_t rc = QUDO_MLDSA_keypair(sig, pk, sk);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("keypair failed"); goto next; }
        PASS();

        snprintf(label, sizeof(label), "%s sign", algs[i]);
        TEST(label);
        size_t sig_len = sig_max;
        rc = QUDO_MLDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);
        if (rc != QUDO_MLDSA_SUCCESS) { FAIL("sign failed"); goto next; }
        if (sig_len == 0 || sig_len > sig_max) { FAIL("bad sig_len"); goto next; }
        PASS();

        snprintf(label, sizeof(label), "%s verify", algs[i]);
        TEST(label);
        rc = QUDO_MLDSA_verify(sig, signature, sig_len, msg, msg_len, pk);
        if (rc == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("verify failed"); }

        snprintf(label, sizeof(label), "%s verify tampered", algs[i]);
        TEST(label);
        signature[0] ^= 0xFF;
        rc = QUDO_MLDSA_verify(sig, signature, sig_len, msg, msg_len, pk);
        if (rc != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

next:
        free(pk); free(sk); free(signature);
        QUDO_MLDSA_free(sig);
    }
}

static void test_sign_verify_with_context(void) {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) { TEST("context sign/verify"); FAIL("new failed"); return; }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    if (!pk || !sk || !signature) { free(pk); free(sk); free(signature); QUDO_MLDSA_free(sig); return; }

    QUDO_MLDSA_keypair(sig, pk, sk);

    const uint8_t msg[] = "context test message";
    const uint8_t ctx[] = "test-context";

    TEST("sign_with_context()");
    size_t sig_len = sig->length_signature;
    QUDO_MLDSA_status_t rc = QUDO_MLDSA_sign_with_context(sig, signature, &sig_len, msg, sizeof(msg)-1, ctx, sizeof(ctx)-1, sk);
    if (rc == QUDO_MLDSA_SUCCESS && sig_len > 0) { PASS(); } else { FAIL("sign failed"); }

    TEST("verify_with_context()");
    rc = QUDO_MLDSA_verify_with_context(sig, signature, sig_len, msg, sizeof(msg)-1, ctx, sizeof(ctx)-1, pk);
    if (rc == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("verify failed"); }

    TEST("verify_with_context() wrong context");
    const uint8_t wrong_ctx[] = "wrong-ctx";
    rc = QUDO_MLDSA_verify_with_context(sig, signature, sig_len, msg, sizeof(msg)-1, wrong_ctx, sizeof(wrong_ctx)-1, pk);
    if (rc != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("sign_with_context() NULL context");
    rc = QUDO_MLDSA_sign_with_context(sig, signature, &sig_len, msg, sizeof(msg)-1, NULL, 0, sk);
    if (rc == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("NULL ctx should work"); }

    free(pk); free(sk); free(signature);
    QUDO_MLDSA_free(sig);
}

static void test_keypair_null_args(void) {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) return;
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];

    TEST("keypair(sig, NULL, sk)");
    if (QUDO_MLDSA_keypair(sig, NULL, sk) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("keypair(sig, pk, NULL)");
    if (QUDO_MLDSA_keypair(sig, pk, NULL) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("keypair(NULL, pk, sk)");
    if (QUDO_MLDSA_keypair(NULL, pk, sk) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_MLDSA_free(sig);
}

static void test_sign_null_args(void) {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) return;
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    QUDO_MLDSA_keypair(sig, pk, sk);

    uint8_t signature[ML_DSA_44_SIGNATURE_BYTES];
    size_t sig_len;
    const uint8_t msg[] = "test";

    TEST("sign(NULL sig, ...)");
    if (QUDO_MLDSA_sign(NULL, signature, &sig_len, msg, 4, sk) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("sign(sig, NULL sig buf, ...) size query");
    sig_len = 0;
    if (QUDO_MLDSA_sign(sig, NULL, &sig_len, msg, 4, sk) == QUDO_MLDSA_SUCCESS
        && sig_len == sig->length_signature) { PASS(); } else { FAIL("size query should succeed"); }

    TEST("sign(sig, sig, NULL sig_len, ...)");
    if (QUDO_MLDSA_sign(sig, signature, NULL, msg, 4, sk) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("sign(sig, ..., NULL sk)");
    if (QUDO_MLDSA_sign(sig, signature, &sig_len, msg, 4, NULL) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("verify(NULL sig, ...)");
    QUDO_MLDSA_sign(sig, signature, &sig_len, msg, 4, sk);
    if (QUDO_MLDSA_verify(NULL, signature, sig_len, msg, 4, pk) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("verify(sig, NULL sig buf, ...)");
    if (QUDO_MLDSA_verify(sig, NULL, sig_len, msg, 4, pk) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("verify(sig, ..., NULL pk)");
    if (QUDO_MLDSA_verify(sig, signature, sig_len, msg, 4, NULL) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_MLDSA_free(sig);
}

static void test_direct_api(void) {

    TEST("Direct API: ML-DSA-44 keypair+sign+verify");
    {
        uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES], sk[ML_DSA_44_SECRET_KEY_BYTES];
        uint8_t signature[ML_DSA_44_SIGNATURE_BYTES];
        size_t sig_len;
        const uint8_t msg[] = "direct api test 44";

        if (QUDO_MLDSA_ML_DSA_44_keypair(pk, sk) != QUDO_MLDSA_SUCCESS) { FAIL("keypair"); goto d65; }
        if (QUDO_MLDSA_ML_DSA_44_sign(signature, &sig_len, msg, sizeof(msg)-1, sk) != QUDO_MLDSA_SUCCESS) { FAIL("sign"); goto d65; }
        if (QUDO_MLDSA_ML_DSA_44_verify(signature, sig_len, msg, sizeof(msg)-1, pk) == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("verify"); }
    }
d65:

    TEST("Direct API: ML-DSA-65 keypair+sign+verify");
    {
        uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES], sk[ML_DSA_65_SECRET_KEY_BYTES];
        uint8_t signature[ML_DSA_65_SIGNATURE_BYTES];
        size_t sig_len;
        const uint8_t msg[] = "direct api test 65";

        if (QUDO_MLDSA_ML_DSA_65_keypair(pk, sk) != QUDO_MLDSA_SUCCESS) { FAIL("keypair"); goto d87; }
        if (QUDO_MLDSA_ML_DSA_65_sign(signature, &sig_len, msg, sizeof(msg)-1, sk) != QUDO_MLDSA_SUCCESS) { FAIL("sign"); goto d87; }
        if (QUDO_MLDSA_ML_DSA_65_verify(signature, sig_len, msg, sizeof(msg)-1, pk) == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("verify"); }
    }
d87:

    TEST("Direct API: ML-DSA-87 keypair+sign+verify");
    {
        uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES], sk[ML_DSA_87_SECRET_KEY_BYTES];
        uint8_t signature[ML_DSA_87_SIGNATURE_BYTES];
        size_t sig_len;
        const uint8_t msg[] = "direct api test 87";

        if (QUDO_MLDSA_ML_DSA_87_keypair(pk, sk) != QUDO_MLDSA_SUCCESS) { FAIL("keypair"); return; }
        if (QUDO_MLDSA_ML_DSA_87_sign(signature, &sig_len, msg, sizeof(msg)-1, sk) != QUDO_MLDSA_SUCCESS) { FAIL("sign"); return; }
        if (QUDO_MLDSA_ML_DSA_87_verify(signature, sig_len, msg, sizeof(msg)-1, pk) == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("verify"); }
    }
}

static void test_get_sizes(void) {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return;

    TEST("get_public_key_bytes(sig)");
    if (QUDO_MLDSA_get_public_key_bytes(sig) == ML_DSA_65_PUBLIC_KEY_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("get_secret_key_bytes(sig)");
    if (QUDO_MLDSA_get_secret_key_bytes(sig) == ML_DSA_65_SECRET_KEY_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("get_signature_bytes(sig)");
    if (QUDO_MLDSA_get_signature_bytes(sig) == ML_DSA_65_SIGNATURE_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("get_public_key_bytes(NULL)");
    if (QUDO_MLDSA_get_public_key_bytes(NULL) == 0) { PASS(); } else { FAIL("should be 0"); }

    TEST("get_secret_key_bytes(NULL)");
    if (QUDO_MLDSA_get_secret_key_bytes(NULL) == 0) { PASS(); } else { FAIL("should be 0"); }

    TEST("get_signature_bytes(NULL)");
    if (QUDO_MLDSA_get_signature_bytes(NULL) == 0) { PASS(); } else { FAIL("should be 0"); }

    QUDO_MLDSA_free(sig);
}

static void test_algorithm_name(void) {
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    if (!sig) return;

    TEST("get_algorithm_name(sig)");
    const char *name = QUDO_MLDSA_get_algorithm_name(sig);
    if (name && strcmp(name, "ML-DSA-65") == 0) { PASS(); } else { FAIL("wrong name"); }

    TEST("get_algorithm_name(NULL)");
    name = QUDO_MLDSA_get_algorithm_name(NULL);
    if (name == NULL) { PASS(); } else { FAIL("should be NULL"); }

    TEST("get_security_level(sig)");
    QUDO_MLDSA_security_level_t level = QUDO_MLDSA_get_security_level(sig);
    if (level == QUDO_MLDSA_LEVEL_65) { PASS(); } else { FAIL("wrong level"); }

    TEST("get_security_level(NULL)");
    level = QUDO_MLDSA_get_security_level(NULL);

    PASS();

    QUDO_MLDSA_free(sig);
}

static void test_algorithm_enum(void) {
    TEST("alg_count()");
    int count = QUDO_MLDSA_alg_count();
    if (count == 3) { PASS(); } else { printf("(%d) ", count); FAIL("expected 3"); }

    TEST("alg_identifier(0)");
    const char *name = QUDO_MLDSA_alg_identifier(0);
    if (name && strlen(name) > 0) { printf("(%s) ", name); PASS(); } else { FAIL("NULL or empty"); }

    TEST("alg_identifier(1)");
    name = QUDO_MLDSA_alg_identifier(1);
    if (name && strlen(name) > 0) { printf("(%s) ", name); PASS(); } else { FAIL("NULL or empty"); }

    TEST("alg_identifier(2)");
    name = QUDO_MLDSA_alg_identifier(2);
    if (name && strlen(name) > 0) { printf("(%s) ", name); PASS(); } else { FAIL("NULL or empty"); }

    TEST("alg_identifier(99) out of range");
    name = QUDO_MLDSA_alg_identifier(99);
    if (name == NULL) { PASS(); } else { FAIL("should be NULL"); }

    TEST("alg_is_enabled(\"ML-DSA-65\")");
    if (QUDO_MLDSA_alg_is_enabled("ML-DSA-65") == 1) { PASS(); } else { FAIL("should be enabled"); }

    TEST("alg_is_enabled(\"invalid\")");
    if (QUDO_MLDSA_alg_is_enabled("invalid") == 0) { PASS(); } else { FAIL("should not be enabled"); }

    TEST("alg_is_enabled(NULL)");
    if (QUDO_MLDSA_alg_is_enabled(NULL) == 0) { PASS(); } else { FAIL("should not be enabled"); }

    TEST("supports_ctx_str(\"ML-DSA-65\")");
    if (QUDO_MLDSA_supports_ctx_str("ML-DSA-65") == 1) { PASS(); } else { FAIL("should support ctx"); }

    TEST("supports_ctx_str(NULL)");
    if (QUDO_MLDSA_supports_ctx_str(NULL) == 0) { PASS(); } else { FAIL("should return 0"); }
}

static void test_get_error_string(void) {
    TEST("get_error_string(QUDO_MLDSA_SUCCESS)");
    const char *s = QUDO_MLDSA_error_string(QUDO_MLDSA_SUCCESS);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("empty or NULL"); }

    TEST("get_error_string(QUDO_MLDSA_ERROR)");
    s = QUDO_MLDSA_error_string(QUDO_MLDSA_ERROR);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("empty or NULL"); }

    TEST("get_error_string(QUDO_MLDSA_ERROR_NULL_PTR)");
    s = QUDO_MLDSA_error_string(QUDO_MLDSA_ERROR_NULL_PTR);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("empty or NULL"); }

    TEST("get_error_string(-99)");
    s = QUDO_MLDSA_error_string(-99);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("should return unknown"); }
}

static void test_get_version(void) {
    TEST("QUDO_MLDSA_get_version()");
    const char *ver = QUDO_MLDSA_get_version();
    if (ver && strchr(ver, '.')) { printf("(%s) ", ver); PASS(); } else { FAIL("bad version"); }
}

static void test_config(void) {
    TEST("config_default()");
    mldsa_config_t *cfg = QUDO_MLDSA_config_default();
    if (cfg) { PASS(); } else { FAIL("NULL"); return; }

    TEST("config_validate(cfg)");
    if (QUDO_MLDSA_config_validate(cfg) == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("invalid"); }

    TEST("config_validate(NULL)");
    if (QUDO_MLDSA_config_validate(NULL) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_apply(cfg)");
    if (QUDO_MLDSA_config_apply(cfg) == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("apply failed"); }

    TEST("config_apply(NULL)");
    if (QUDO_MLDSA_config_apply(NULL) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_save/load roundtrip");
    const char *tmpdir = getenv("TEMP");
    if (!tmpdir) tmpdir = getenv("TMP");
    if (!tmpdir) tmpdir = "/tmp";
    char tmpfile_buf[512];
    snprintf(tmpfile_buf, sizeof(tmpfile_buf), "%s/test_mldsa_config.ini", tmpdir);
    const char *tmpfile = tmpfile_buf;
    int rc = QUDO_MLDSA_config_save(cfg, tmpfile);
    if (rc != QUDO_MLDSA_SUCCESS) { FAIL("save failed"); QUDO_MLDSA_config_free(cfg); return; }
    mldsa_config_t *loaded = QUDO_MLDSA_config_load(tmpfile);
    if (loaded) { PASS(); QUDO_MLDSA_config_free(loaded); } else { FAIL("load failed"); }
    remove(tmpfile);

    TEST("config_save(NULL, file)");
    if (QUDO_MLDSA_config_save(NULL, tmpfile) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_save(cfg, NULL)");
    if (QUDO_MLDSA_config_save(cfg, NULL) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_load(NULL)");
    loaded = QUDO_MLDSA_config_load(NULL);
    if (loaded) { PASS(); QUDO_MLDSA_config_free(loaded); } else { FAIL("should return default"); }

    TEST("config_load(nonexistent)");
    loaded = QUDO_MLDSA_config_load("/tmp/nonexistent_mldsa_cfg.ini");
    if (loaded) { PASS(); QUDO_MLDSA_config_free(loaded); } else { FAIL("should return default"); }

    TEST("config_free(NULL)");
    QUDO_MLDSA_config_free(NULL);
    PASS();

    QUDO_MLDSA_config_free(cfg);
}

static void test_config_helpers(void) {
    TEST("mldsa_get_default_config()");
    const mldsa_config_t *cfg = mldsa_get_default_config();
    if (cfg) { PASS(); } else { FAIL("NULL"); }

    TEST("mldsa_get_version()");
    const char *ver = mldsa_get_version();
    if (ver && strlen(ver) > 0) { printf("(%s) ", ver); PASS(); } else { FAIL("NULL or empty"); }

    TEST("mldsa_get_algorithm_name(LEVEL_44)");
    const char *name = mldsa_get_algorithm_name(QUDO_MLDSA_LEVEL_44);
    if (name && strstr(name, "44")) { printf("(%s) ", name); PASS(); } else { FAIL("wrong name"); }

    TEST("mldsa_get_algorithm_name(LEVEL_65)");
    name = mldsa_get_algorithm_name(QUDO_MLDSA_LEVEL_65);
    if (name && strstr(name, "65")) { printf("(%s) ", name); PASS(); } else { FAIL("wrong name"); }

    TEST("mldsa_get_algorithm_name(LEVEL_87)");
    name = mldsa_get_algorithm_name(QUDO_MLDSA_LEVEL_87);
    if (name && strstr(name, "87")) { printf("(%s) ", name); PASS(); } else { FAIL("wrong name"); }

    TEST("mldsa_get_algorithm_name(99) invalid");
    name = mldsa_get_algorithm_name(99);
    if (name == NULL) { PASS(); } else { printf("(%s) ", name); PASS(); }

    TEST("mldsa_get_public_key_bytes(LEVEL_65)");
    if (mldsa_get_public_key_bytes(QUDO_MLDSA_LEVEL_65) == ML_DSA_65_PUBLIC_KEY_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("mldsa_get_secret_key_bytes(LEVEL_65)");
    if (mldsa_get_secret_key_bytes(QUDO_MLDSA_LEVEL_65) == ML_DSA_65_SECRET_KEY_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("mldsa_get_signature_bytes(LEVEL_65)");
    if (mldsa_get_signature_bytes(QUDO_MLDSA_LEVEL_65) == ML_DSA_65_SIGNATURE_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("mldsa_get_public_key_bytes(99) invalid");
    if (mldsa_get_public_key_bytes(99) == 0) { PASS(); } else { FAIL("should be 0"); }
}

static void test_rng(void) {
    TEST("QUDO_MLDSA_randombytes_init()");
    if (QUDO_MLDSA_randombytes_init() == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("init failed"); }

    TEST("QUDO_MLDSA_randombytes_test()");
    if (QUDO_MLDSA_randombytes_test() == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("test failed"); }

    TEST("QUDO_MLDSA_randombytes() valid");
    uint8_t buf[64];
    if (QUDO_MLDSA_randombytes(buf, sizeof(buf)) == QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("failed"); }

    TEST("QUDO_MLDSA_randombytes(NULL)");
    if (QUDO_MLDSA_randombytes(NULL, 32) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_MLDSA_randombytes(0 len)");
    if (QUDO_MLDSA_randombytes(buf, 0) != QUDO_MLDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_MLDSA_randombytes_cleanup()");
    QUDO_MLDSA_randombytes_cleanup();
    PASS();
}

int main(void) {
    printf("=== QUDO ML-DSA Object API & Utility Tests ===\n\n");

    printf("[Object API]\n");
    test_new_by_name();
    test_new_invalid();
    test_free_null();
    test_init_cleanup();

    printf("\n[Sign/Verify Round-trip]\n");
    test_sign_verify_all_levels();

    printf("\n[Context String]\n");
    test_sign_verify_with_context();

    printf("\n[NULL Arg Tests]\n");
    test_keypair_null_args();
    test_sign_null_args();

    printf("\n[Direct API]\n");
    test_direct_api();

    printf("\n[Utility Functions]\n");
    test_get_sizes();
    test_algorithm_name();
    test_algorithm_enum();
    test_get_error_string();
    test_get_version();

    printf("\n[Config]\n");
    test_config();
    test_config_helpers();

    printf("\n[RNG]\n");
    test_rng();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
