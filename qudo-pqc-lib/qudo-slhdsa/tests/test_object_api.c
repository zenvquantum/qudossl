/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/slhdsa_wrapper.h"
#include "../include/slhdsa_config.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-55s ", tests_run, name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

static const char *all_algs[] = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
};

static void test_new_all_algorithms(void) {
    for (int i = 0; i < 12; i++) {
        char label[64];
        snprintf(label, sizeof(label), "QUDO_SLHDSA_new(\"%s\")", all_algs[i]);
        TEST(label);
        QUDO_SLHDSA *sig = QUDO_SLHDSA_new(all_algs[i]);
        if (!sig) { FAIL("returned NULL"); continue; }
        if (strcmp(sig->method_name, all_algs[i]) != 0) { FAIL("wrong name"); QUDO_SLHDSA_free(sig); continue; }
        if (sig->length_public_key == 0) { FAIL("zero pk size"); QUDO_SLHDSA_free(sig); continue; }
        PASS();
        QUDO_SLHDSA_free(sig);
    }
}

static void test_new_invalid(void) {
    TEST("QUDO_SLHDSA_new(NULL)");
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(NULL);
    if (sig == NULL) { PASS(); } else { FAIL("should be NULL"); QUDO_SLHDSA_free(sig); }

    TEST("QUDO_SLHDSA_new(\"invalid\")");
    sig = QUDO_SLHDSA_new("invalid");
    if (sig == NULL) { PASS(); } else { FAIL("should be NULL"); QUDO_SLHDSA_free(sig); }

    TEST("QUDO_SLHDSA_new(\"\")");
    sig = QUDO_SLHDSA_new("");
    if (sig == NULL) { PASS(); } else { FAIL("should be NULL"); QUDO_SLHDSA_free(sig); }
}

static void test_free_null(void) {
    TEST("QUDO_SLHDSA_free(NULL)");
    QUDO_SLHDSA_free(NULL);
    PASS();
}

static void test_init_cleanup(void) {
    TEST("QUDO_SLHDSA_init()");
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_init();
    if (rc == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("init failed"); }

    TEST("QUDO_SLHDSA_is_initialized()");
    if (QUDO_SLHDSA_is_initialized() == 1) { PASS(); } else { FAIL("should be initialized"); }

    TEST("QUDO_SLHDSA_cleanup()");
    QUDO_SLHDSA_cleanup();
    PASS();
}

static void test_sign_verify_roundtrip(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    if (!sig) { TEST("sign/verify roundtrip"); FAIL("new failed"); return; }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    if (!pk || !sk || !signature) { free(pk); free(sk); free(signature); QUDO_SLHDSA_free(sig); return; }

    const uint8_t msg[] = "Test message for SLH-DSA signing";
    size_t msg_len = sizeof(msg) - 1;

    TEST("SHA2-128f keypair");
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_keypair(sig, pk, sk);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("keypair failed"); goto done; }
    PASS();

    TEST("SHA2-128f sign");
    size_t sig_len = sig->length_signature;
    rc = QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("sign failed"); goto done; }
    if (sig_len == 0) { FAIL("zero sig_len"); goto done; }
    PASS();

    TEST("SHA2-128f verify");
    rc = QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk);
    if (rc == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("verify failed"); }

    TEST("SHA2-128f verify tampered");
    signature[0] ^= 0xFF;
    rc = QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk);
    if (rc != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

done:
    free(pk); free(sk); free(signature);
    QUDO_SLHDSA_free(sig);
}

static void test_sign_verify_with_context(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    if (!sig) { TEST("context sign/verify"); FAIL("new failed"); return; }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    if (!pk || !sk || !signature) { free(pk); free(sk); free(signature); QUDO_SLHDSA_free(sig); return; }

    QUDO_SLHDSA_keypair(sig, pk, sk);
    const uint8_t msg[] = "context test message";
    const uint8_t ctx[] = "test-context";

    TEST("sign_with_ctx_str()");
    size_t sig_len = sig->length_signature;
    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_sign_with_ctx_str(sig, signature, &sig_len, msg, sizeof(msg)-1, ctx, sizeof(ctx)-1, sk);
    if (rc == QUDO_SLHDSA_SUCCESS && sig_len > 0) { PASS(); } else { FAIL("sign failed"); }

    TEST("verify_with_ctx_str()");
    rc = QUDO_SLHDSA_verify_with_ctx_str(sig, msg, sizeof(msg)-1, signature, sig_len, ctx, sizeof(ctx)-1, pk);
    if (rc == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("verify failed"); }

    TEST("verify_with_ctx_str() wrong context");
    const uint8_t wrong_ctx[] = "wrong-ctx";
    rc = QUDO_SLHDSA_verify_with_ctx_str(sig, msg, sizeof(msg)-1, signature, sig_len, wrong_ctx, sizeof(wrong_ctx)-1, pk);
    if (rc != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    free(pk); free(sk); free(signature);
    QUDO_SLHDSA_free(sig);
}

static void test_keypair_null_args(void) {
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128s");
    if (!sig) return;
    uint8_t pk[SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES];
    uint8_t sk[SLH_DSA_SHA2_128S_SECRET_KEY_BYTES];

    TEST("keypair(sig, NULL, sk)");
    if (QUDO_SLHDSA_keypair(sig, NULL, sk) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("keypair(sig, pk, NULL)");
    if (QUDO_SLHDSA_keypair(sig, pk, NULL) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("keypair(NULL, pk, sk)");
    if (QUDO_SLHDSA_keypair(NULL, pk, sk) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    QUDO_SLHDSA_free(sig);
}

static void test_direct_api(void) {
    TEST("Direct API: SHA2-128s keypair+sign+verify");
    {
        uint8_t pk[SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES], sk[SLH_DSA_SHA2_128S_SECRET_KEY_BYTES];
        uint8_t *signature = malloc(SLH_DSA_SHA2_128S_SIGNATURE_BYTES);
        if (!signature) { FAIL("alloc"); return; }
        size_t sig_len;
        const uint8_t msg[] = "direct api test";

        if (QUDO_SLHDSA_SHA2_128s_keypair(pk, sk) != QUDO_SLHDSA_SUCCESS) { FAIL("keypair"); free(signature); return; }
        if (QUDO_SLHDSA_SHA2_128s_sign(signature, &sig_len, msg, sizeof(msg)-1, sk) != QUDO_SLHDSA_SUCCESS) { FAIL("sign"); free(signature); return; }
        if (QUDO_SLHDSA_SHA2_128s_verify(msg, sizeof(msg)-1, signature, sig_len, pk) == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("verify"); }
        free(signature);
    }
}

static void test_get_version(void) {
    TEST("QUDO_SLHDSA_get_version()");
    const char *ver = QUDO_SLHDSA_get_version();
    if (ver && strchr(ver, '.')) { printf("(%s) ", ver); PASS(); } else { FAIL("bad version"); }
}

static void test_get_error_string(void) {
    TEST("get_error_string(SUCCESS)");
    const char *s = QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_SUCCESS);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("empty or NULL"); }

    TEST("get_error_string(ERROR)");
    s = QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_ERROR);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("empty or NULL"); }

    TEST("get_error_string(NULL_PTR)");
    s = QUDO_SLHDSA_get_error_string(QUDO_SLHDSA_ERROR_NULL_PTR);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("empty or NULL"); }

    TEST("get_error_string(-99)");
    s = QUDO_SLHDSA_get_error_string(-99);
    if (s && strlen(s) > 0) { PASS(); } else { FAIL("should return unknown"); }
}

static void test_get_security_level(void) {
    QUDO_SLHDSA_parameter_set_t params[] = {
        QUDO_SLHDSA_SHA2_128s, QUDO_SLHDSA_SHA2_192s, QUDO_SLHDSA_SHA2_256s
    };
    int expected[] = { 1, 3, 5 };

    for (int i = 0; i < 3; i++) {
        char label[64];
        snprintf(label, sizeof(label), "get_security_level(param=%d)", params[i]);
        TEST(label);
        int level = QUDO_SLHDSA_get_security_level(params[i]);
        if (level == expected[i]) { PASS(); } else { printf("(%d vs %d) ", level, expected[i]); FAIL("wrong level"); }
    }

    TEST("get_security_level(invalid=99)");
    if (QUDO_SLHDSA_get_security_level(99) == 0) { PASS(); } else { FAIL("should be 0"); }
}

static void test_algorithm_enum(void) {
    TEST("alg_count()");
    int count = QUDO_SLHDSA_alg_count();
    if (count == 12) { PASS(); } else { printf("(%d) ", count); FAIL("expected 12"); }

    for (int i = 0; i < 12; i++) {
        char label[64];
        snprintf(label, sizeof(label), "alg_identifier(%d)", i);
        TEST(label);
        const char *name = QUDO_SLHDSA_alg_identifier(i);
        if (name && strlen(name) > 0) { printf("(%s) ", name); PASS(); } else { FAIL("NULL or empty"); }
    }

    TEST("alg_identifier(99) out of range");
    if (QUDO_SLHDSA_alg_identifier(99) == NULL) { PASS(); } else { FAIL("should be NULL"); }

    TEST("alg_is_enabled(\"SLH-DSA-SHA2-128s\")");
    if (QUDO_SLHDSA_alg_is_enabled("SLH-DSA-SHA2-128s") == 1) { PASS(); } else { FAIL("should be enabled"); }

    TEST("alg_is_enabled(\"invalid\")");
    if (QUDO_SLHDSA_alg_is_enabled("invalid") == 0) { PASS(); } else { FAIL("should not be enabled"); }

    TEST("alg_is_enabled(NULL)");
    if (QUDO_SLHDSA_alg_is_enabled(NULL) == 0) { PASS(); } else { FAIL("should return 0"); }
}

static void test_config_helpers(void) {
    TEST("slhdsa_get_algorithm_name(SHA2_128s)");
    const char *name = slhdsa_get_algorithm_name(QUDO_SLHDSA_SHA2_128s);
    if (name && strstr(name, "128s")) { printf("(%s) ", name); PASS(); } else { FAIL("wrong name"); }

    TEST("slhdsa_get_algorithm_name(invalid=99)");
    if (slhdsa_get_algorithm_name(99) == NULL) { PASS(); } else { FAIL("should be NULL"); }

    TEST("slhdsa_get_public_key_bytes(SHA2_128s)");
    if (slhdsa_get_public_key_bytes(QUDO_SLHDSA_SHA2_128s) == SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("slhdsa_get_secret_key_bytes(SHA2_128s)");
    if (slhdsa_get_secret_key_bytes(QUDO_SLHDSA_SHA2_128s) == SLH_DSA_SHA2_128S_SECRET_KEY_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("slhdsa_get_signature_bytes(SHA2_128s)");
    if (slhdsa_get_signature_bytes(QUDO_SLHDSA_SHA2_128s) == SLH_DSA_SHA2_128S_SIGNATURE_BYTES) { PASS(); } else { FAIL("wrong size"); }

    TEST("slhdsa_get_nist_level(SHA2_128s)");
    if (slhdsa_get_nist_level(QUDO_SLHDSA_SHA2_128s) == 1) { PASS(); } else { FAIL("wrong level"); }

    TEST("slhdsa_get_nist_level(SHA2_256s)");
    if (slhdsa_get_nist_level(QUDO_SLHDSA_SHA2_256s) == 5) { PASS(); } else { FAIL("wrong level"); }

    TEST("slhdsa_get_parameter_set(\"SLH-DSA-SHA2-128s\")");
    if (slhdsa_get_parameter_set("SLH-DSA-SHA2-128s") == QUDO_SLHDSA_SHA2_128s) { PASS(); } else { FAIL("wrong param set"); }

    TEST("slhdsa_get_parameter_set(\"invalid\")");
    if (slhdsa_get_parameter_set("invalid") == 0) { PASS(); } else { FAIL("should be 0"); }

    TEST("slhdsa_get_parameter_set(NULL)");
    if (slhdsa_get_parameter_set(NULL) == 0) { PASS(); } else { FAIL("should be 0"); }

    TEST("slhdsa_get_public_key_bytes(invalid=99)");
    if (slhdsa_get_public_key_bytes(99) == 0) { PASS(); } else { FAIL("should be 0"); }
}

static void test_config(void) {
    TEST("config_default()");
    slhdsa_config_t *cfg = QUDO_SLHDSA_config_default();
    if (cfg) { PASS(); } else { FAIL("NULL"); return; }

    TEST("config_validate(cfg)");
    if (QUDO_SLHDSA_config_validate(cfg) == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("invalid"); }

    TEST("config_validate(NULL)");
    if (QUDO_SLHDSA_config_validate(NULL) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_apply(cfg)");
    if (QUDO_SLHDSA_config_apply(cfg) == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("apply failed"); }

    TEST("config_apply(NULL)");
    if (QUDO_SLHDSA_config_apply(NULL) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_save/load roundtrip");
    const char *tmpdir = getenv("TEMP");
    if (!tmpdir) tmpdir = getenv("TMP");
    if (!tmpdir) tmpdir = "/tmp";
    char tmpfile_buf[512];
    snprintf(tmpfile_buf, sizeof(tmpfile_buf), "%s/test_slhdsa_config.ini", tmpdir);
    const char *tmpfile = tmpfile_buf;
    int rc = QUDO_SLHDSA_config_save(cfg, tmpfile);
    if (rc != QUDO_SLHDSA_SUCCESS) { FAIL("save failed"); QUDO_SLHDSA_config_free(cfg); return; }
    slhdsa_config_t *loaded = QUDO_SLHDSA_config_load(tmpfile);
    if (loaded) { PASS(); QUDO_SLHDSA_config_free(loaded); } else { FAIL("load failed"); }
    remove(tmpfile);

    TEST("config_save(NULL, file)");
    if (QUDO_SLHDSA_config_save(NULL, tmpfile) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_save(cfg, NULL)");
    if (QUDO_SLHDSA_config_save(cfg, NULL) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("config_load(NULL)");
    loaded = QUDO_SLHDSA_config_load(NULL);
    if (loaded) { PASS(); QUDO_SLHDSA_config_free(loaded); } else { FAIL("should return default"); }

    TEST("config_load(nonexistent)");
    loaded = QUDO_SLHDSA_config_load("/tmp/nonexistent_slhdsa_cfg.ini");
    if (loaded) { PASS(); QUDO_SLHDSA_config_free(loaded); } else { FAIL("should return default"); }

    TEST("config_free(NULL)");
    QUDO_SLHDSA_config_free(NULL);
    PASS();

    QUDO_SLHDSA_config_free(cfg);
}

static void test_rng(void) {
    TEST("QUDO_SLHDSA_randombytes_init()");
    if (QUDO_SLHDSA_randombytes_init() == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("init failed"); }

    TEST("QUDO_SLHDSA_randombytes_test()");
    if (QUDO_SLHDSA_randombytes_test() == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("test failed"); }

    TEST("QUDO_SLHDSA_randombytes() valid");
    uint8_t buf[64];
    if (QUDO_SLHDSA_randombytes(buf, sizeof(buf)) == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("failed"); }

    TEST("QUDO_SLHDSA_randombytes(NULL)");
    if (QUDO_SLHDSA_randombytes(NULL, 32) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_SLHDSA_randombytes(0 len)");
    if (QUDO_SLHDSA_randombytes(buf, 0) != QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("should fail"); }

    TEST("QUDO_SLHDSA_randombytes_cleanup()");
    QUDO_SLHDSA_randombytes_cleanup();
    PASS();
}

typedef struct {
    const char *name;
    size_t pk_size;
    size_t sk_size;
    size_t sig_size;
    size_t n;
    QUDO_SLHDSA_status_t (*keypair)(uint8_t *pk, uint8_t *sk);
    QUDO_SLHDSA_status_t (*sign)(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
    QUDO_SLHDSA_status_t (*verify)(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk);
} slhdsa_variant_t;

static const slhdsa_variant_t all_variants[] = {
    { "SHA2_128s",  32,  64,  SLH_DSA_SHA2_128S_SIGNATURE_BYTES,  16, QUDO_SLHDSA_SHA2_128s_keypair,  QUDO_SLHDSA_SHA2_128s_sign,  QUDO_SLHDSA_SHA2_128s_verify  },
    { "SHA2_128f",  32,  64,  SLH_DSA_SHA2_128F_SIGNATURE_BYTES,  16, QUDO_SLHDSA_SHA2_128f_keypair,  QUDO_SLHDSA_SHA2_128f_sign,  QUDO_SLHDSA_SHA2_128f_verify  },
    { "SHA2_192s",  48,  96,  SLH_DSA_SHA2_192S_SIGNATURE_BYTES,  24, QUDO_SLHDSA_SHA2_192s_keypair,  QUDO_SLHDSA_SHA2_192s_sign,  QUDO_SLHDSA_SHA2_192s_verify  },
    { "SHA2_192f",  48,  96,  SLH_DSA_SHA2_192F_SIGNATURE_BYTES,  24, QUDO_SLHDSA_SHA2_192f_keypair,  QUDO_SLHDSA_SHA2_192f_sign,  QUDO_SLHDSA_SHA2_192f_verify  },
    { "SHA2_256s",  64, 128,  SLH_DSA_SHA2_256S_SIGNATURE_BYTES,  32, QUDO_SLHDSA_SHA2_256s_keypair,  QUDO_SLHDSA_SHA2_256s_sign,  QUDO_SLHDSA_SHA2_256s_verify  },
    { "SHA2_256f",  64, 128,  SLH_DSA_SHA2_256F_SIGNATURE_BYTES,  32, QUDO_SLHDSA_SHA2_256f_keypair,  QUDO_SLHDSA_SHA2_256f_sign,  QUDO_SLHDSA_SHA2_256f_verify  },
    { "SHAKE_128s", 32,  64,  SLH_DSA_SHAKE_128S_SIGNATURE_BYTES, 16, QUDO_SLHDSA_SHAKE_128s_keypair, QUDO_SLHDSA_SHAKE_128s_sign, QUDO_SLHDSA_SHAKE_128s_verify },
    { "SHAKE_128f", 32,  64,  SLH_DSA_SHAKE_128F_SIGNATURE_BYTES, 16, QUDO_SLHDSA_SHAKE_128f_keypair, QUDO_SLHDSA_SHAKE_128f_sign, QUDO_SLHDSA_SHAKE_128f_verify },
    { "SHAKE_192s", 48,  96,  SLH_DSA_SHAKE_192S_SIGNATURE_BYTES, 24, QUDO_SLHDSA_SHAKE_192s_keypair, QUDO_SLHDSA_SHAKE_192s_sign, QUDO_SLHDSA_SHAKE_192s_verify },
    { "SHAKE_192f", 48,  96,  SLH_DSA_SHAKE_192F_SIGNATURE_BYTES, 24, QUDO_SLHDSA_SHAKE_192f_keypair, QUDO_SLHDSA_SHAKE_192f_sign, QUDO_SLHDSA_SHAKE_192f_verify },
    { "SHAKE_256s", 64, 128,  SLH_DSA_SHAKE_256S_SIGNATURE_BYTES, 32, QUDO_SLHDSA_SHAKE_256s_keypair, QUDO_SLHDSA_SHAKE_256s_sign, QUDO_SLHDSA_SHAKE_256s_verify },
    { "SHAKE_256f", 64, 128,  SLH_DSA_SHAKE_256F_SIGNATURE_BYTES, 32, QUDO_SLHDSA_SHAKE_256f_keypair, QUDO_SLHDSA_SHAKE_256f_sign, QUDO_SLHDSA_SHAKE_256f_verify },
};
#define NUM_VARIANTS 12

static void test_all_direct_api(void) {
    const uint8_t msg[] = "direct api coverage test";
    const size_t msg_len = sizeof(msg) - 1;

    for (int i = 0; i < NUM_VARIANTS; i++) {
        const slhdsa_variant_t *v = &all_variants[i];

        uint8_t *pk  = malloc(v->pk_size);
        uint8_t *sk  = malloc(v->sk_size);
        uint8_t *sig = malloc(v->sig_size);
        if (!pk || !sk || !sig) { free(pk); free(sk); free(sig); continue; }

        char label[80];

        snprintf(label, sizeof(label), "Direct %s keypair", v->name);
        TEST(label);
        if (v->keypair(pk, sk) == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("keypair failed"); free(pk); free(sk); free(sig); continue; }

        snprintf(label, sizeof(label), "Direct %s sign", v->name);
        TEST(label);
        size_t sig_len = v->sig_size;
        if (v->sign(sig, &sig_len, msg, msg_len, sk) == QUDO_SLHDSA_SUCCESS && sig_len > 0) { PASS(); } else { FAIL("sign failed"); free(pk); free(sk); free(sig); continue; }

        snprintf(label, sizeof(label), "Direct %s verify", v->name);
        TEST(label);
        if (v->verify(msg, msg_len, sig, sig_len, pk) == QUDO_SLHDSA_SUCCESS) { PASS(); } else { FAIL("verify failed"); }

        free(pk); free(sk); free(sig);
    }

    TEST("keypair_internal (SHA2_128f, deterministic)");
    QUDO_SLHDSA *sig_obj = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    if (!sig_obj) { FAIL("new failed"); return; }
    uint8_t pk1[SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES], sk1[SLH_DSA_SHA2_128F_SECRET_KEY_BYTES];
    uint8_t pk2[SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES], sk2[SLH_DSA_SHA2_128F_SECRET_KEY_BYTES];
    uint8_t sk_seed[16], sk_prf[16], pk_seed[16];
    memset(sk_seed, 0xAA, 16); memset(sk_prf, 0xBB, 16); memset(pk_seed, 0xCC, 16);
    QUDO_SLHDSA_status_t r1 = QUDO_SLHDSA_keypair_internal(sig_obj, pk1, sk1, sk_seed, sk_prf, pk_seed);
    QUDO_SLHDSA_status_t r2 = QUDO_SLHDSA_keypair_internal(sig_obj, pk2, sk2, sk_seed, sk_prf, pk_seed);
    if (r1 == QUDO_SLHDSA_SUCCESS && r2 == QUDO_SLHDSA_SUCCESS &&
        memcmp(pk1, pk2, SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES) == 0) { PASS(); } else { FAIL("keypair_internal mismatch"); }
    QUDO_SLHDSA_free(sig_obj);
}

int main(void) {
    printf("=== QUDO SLH-DSA Object API & Utility Tests ===\n\n");

    printf("[Object API - All 12 Algorithms]\n");
    test_new_all_algorithms();
    test_new_invalid();
    test_free_null();

    printf("\n[Init/Cleanup]\n");
    test_init_cleanup();

    printf("\n[Sign/Verify Round-trip]\n");
    test_sign_verify_roundtrip();

    printf("\n[Context String]\n");
    test_sign_verify_with_context();

    printf("\n[NULL Arg Tests]\n");
    test_keypair_null_args();

    printf("\n[Direct API]\n");
    test_direct_api();

    printf("\n[Direct API - All 12 Parameter Sets + keypair_internal]\n");
    test_all_direct_api();

    printf("\n[Utility Functions]\n");
    test_get_version();
    test_get_error_string();
    test_get_security_level();

    printf("\n[Algorithm Enumeration]\n");
    test_algorithm_enum();

    printf("\n[Config Helpers]\n");
    test_config_helpers();

    printf("\n[Config]\n");
    test_config();

    printf("\n[RNG]\n");
    test_rng();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
