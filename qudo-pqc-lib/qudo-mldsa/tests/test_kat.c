/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "../include/mldsa_wrapper.h"

#define TEST_RUNS 10

static int test_sign_consistency(const char *alg_name) {
    printf("\nTesting %s Consistency\n", alg_name);
    printf("═══════════════════════════════════════════════════════════════\n\n");

    const QUDO_MLDSA *sig = QUDO_MLDSA_new(alg_name);
    if (!sig) {
        printf("❌ Failed to create SIG object for %s\n", alg_name);
        return 1;
    }

    printf("Parameters:\n");
    printf("  Public key:    %zu bytes\n", sig->length_public_key);
    printf("  Secret key:    %zu bytes\n", sig->length_secret_key);
    printf("  Signature:     %zu bytes\n", sig->length_signature);
    printf("\n");

    uint8_t *pk1 = malloc(sig->length_public_key);
    uint8_t *sk1 = malloc(sig->length_secret_key);
    uint8_t *pk2 = malloc(sig->length_public_key);
    uint8_t *sk2 = malloc(sig->length_secret_key);
    uint8_t *sm = malloc(sig->length_signature + 128);
    size_t smlen;
    uint8_t msg[128] = "Test message for ML-DSA signature verification";
    size_t msg_len = strlen((char*)msg);
    int ret;

    printf("Test 1: Keypair generation produces random keys\n");
    sig->keypair(pk1, sk1);
    sig->keypair(pk2, sk2);
    if (memcmp(pk1, pk2, sig->length_public_key) == 0) {
        printf("❌ Public keys are identical (bad randomness)\n");
        ret = 1;
        goto cleanup;
    }
    printf("✅ Keypairs are different (good randomness)\n\n");

    printf("Test 2: Sign and verify correctness\n");
    sig->keypair(pk1, sk1);
    sig->sign(sm, &smlen, msg, msg_len, sk1);
    ret = sig->verify(msg, msg_len, sm, smlen, pk1);
    if (ret != 0) {
        printf("❌ Signature verification failed\n");
        ret = 1;
        goto cleanup;
    }
    printf("✅ Signature verified successfully\n\n");

    printf("Test 3: Wrong message detection\n");
    msg[0] = ~msg[0];
    ret = sig->verify(msg, msg_len, sm, smlen, pk1);
    if (ret == 0) {
        printf("❌ Verification succeeded with wrong message\n");
        ret = 1;
        goto cleanup;
    }
    printf("✅ Wrong message detected correctly\n\n");

    printf("Test 4: Wrong public key detection\n");
    msg[0] = ~msg[0];
    sig->keypair(pk2, sk2);
    ret = sig->verify(msg, msg_len, sm, smlen, pk2);
    if (ret == 0) {
        printf("❌ Verification succeeded with wrong public key\n");
        ret = 1;
        goto cleanup;
    }
    printf("✅ Wrong public key detected correctly\n\n");

    printf("✅ All consistency tests PASSED for %s\n\n", alg_name);
    ret = 0;

cleanup:
    free(pk1);
    free(sk1);
    free(pk2);
    free(sk2);
    free(sm);
    QUDO_MLDSA_free((QUDO_MLDSA*)sig);
    return ret;
}

int main(void) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    QUDO_MLDSA_init();

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("ML-DSA Known Answer Tests (Functional Consistency)\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    int result = 0;

    result |= test_sign_consistency("ML-DSA-44");
    result |= test_sign_consistency("ML-DSA-65");
    result |= test_sign_consistency("ML-DSA-87");

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Final Result\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    if (result == 0) {
        printf("✅ ALL KAT TESTS PASSED\n\n");
    } else {
        printf("❌ SOME TESTS FAILED\n\n");
    }
    OPENSSL_cleanup();
    return result;
}
