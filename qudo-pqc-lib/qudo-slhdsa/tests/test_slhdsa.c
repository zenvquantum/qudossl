/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "slhdsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name, cond) do { \
    tests_run++; \
    if (cond) { tests_passed++; } \
    else { fprintf(stderr, "  FAIL: %s\n", name); } \
} while(0)

static int test_variant(const char *alg_name) {
    int ok = 1;

    fprintf(stderr, "Testing %s...\n", alg_name);

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg_name);
    if (!sig) {
        fprintf(stderr, "  FAIL: QUDO_SLHDSA_new returned NULL for %s\n", alg_name);
        tests_run++;
        return 0;
    }

    TEST("new", sig != NULL);
    TEST("method_name", strcmp(sig->method_name, alg_name) == 0);
    TEST("alg_version", strcmp(sig->alg_version, "FIPS 205") == 0);
    TEST("pk_size > 0", sig->length_public_key > 0);
    TEST("sk_size > 0", sig->length_secret_key > 0);
    TEST("sig_size > 0", sig->length_signature > 0);

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);

    if (!pk || !sk || !signature) {
        fprintf(stderr, "  FAIL: malloc failed\n");
        free(pk); free(sk); free(signature);
        QUDO_SLHDSA_free(sig);
        return 0;
    }

    QUDO_SLHDSA_status_t rc = QUDO_SLHDSA_keypair(sig, pk, sk);
    TEST("keypair", rc == QUDO_SLHDSA_SUCCESS);

    if (rc != QUDO_SLHDSA_SUCCESS) {
        fprintf(stderr, "  Keygen failed, skipping sign/verify tests\n");
        free(pk); free(sk); free(signature);
        QUDO_SLHDSA_free(sig);
        return 0;
    }

    const uint8_t msg[] = "QUDO SLH-DSA test message";
    size_t msg_len = sizeof(msg) - 1;
    size_t sig_len = sig->length_signature;

    rc = QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, msg_len, sk);
    TEST("sign", rc == QUDO_SLHDSA_SUCCESS);
    TEST("sig_len == expected", sig_len == sig->length_signature);

    rc = QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk);
    TEST("verify_ok", rc == QUDO_SLHDSA_SUCCESS);

    const uint8_t bad_msg[] = "WRONG message";
    rc = QUDO_SLHDSA_verify(sig, bad_msg, sizeof(bad_msg) - 1, signature, sig_len, pk);
    TEST("verify_bad_msg", rc != QUDO_SLHDSA_SUCCESS);

    signature[0] ^= 0xFF;
    rc = QUDO_SLHDSA_verify(sig, msg, msg_len, signature, sig_len, pk);
    TEST("verify_bad_sig", rc != QUDO_SLHDSA_SUCCESS);
    signature[0] ^= 0xFF;

    const uint8_t ctx[] = "test-context";
    size_t ctx_len = sizeof(ctx) - 1;
    sig_len = sig->length_signature;

    rc = QUDO_SLHDSA_sign_with_ctx_str(sig, signature, &sig_len, msg, msg_len,
                                         ctx, ctx_len, sk);
    TEST("sign_with_ctx", rc == QUDO_SLHDSA_SUCCESS);

    rc = QUDO_SLHDSA_verify_with_ctx_str(sig, msg, msg_len, signature, sig_len,
                                           ctx, ctx_len, pk);
    TEST("verify_with_ctx", rc == QUDO_SLHDSA_SUCCESS);

    const uint8_t bad_ctx[] = "wrong-ctx";
    rc = QUDO_SLHDSA_verify_with_ctx_str(sig, msg, msg_len, signature, sig_len,
                                           bad_ctx, sizeof(bad_ctx) - 1, pk);
    TEST("verify_bad_ctx", rc != QUDO_SLHDSA_SUCCESS);

    fprintf(stderr, "  %s: OK\n", alg_name);

    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return ok;
}

int main(void) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    fprintf(stderr, "\n=== QUDO SLH-DSA Test Suite ===\n\n");

    const char *algorithms[] = {
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-256f",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHA2-256s",
        "SLH-DSA-SHAKE-256s",
    };

    for (int i = 0; i < 12; i++) {
        test_variant(algorithms[i]);
    }

    fprintf(stderr, "\n=== Results: %d/%d tests passed ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
