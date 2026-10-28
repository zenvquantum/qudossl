/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/slhdsa_wrapper.h"

#define TEST_RUNS 3

static int test_sign_consistency(const char *alg_name) {
    printf("\nTesting %s Consistency\n", alg_name);
    printf("-----------------------------------------------------------\n\n");

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg_name);
    if (!sig) {
        printf("FAIL: Failed to create SLHDSA object for %s\n", alg_name);
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
    uint8_t *sm = malloc(sig->length_signature);
    size_t smlen;
    uint8_t msg[128] = "Test message for SLH-DSA signature verification";
    size_t msg_len = strlen((char *)msg);
    int ret;

    printf("Test 1: Keypair generation produces random keys\n");
    QUDO_SLHDSA_keypair(sig, pk1, sk1);
    QUDO_SLHDSA_keypair(sig, pk2, sk2);
    if (memcmp(pk1, pk2, sig->length_public_key) == 0) {
        printf("FAIL: Public keys are identical (bad randomness)\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS: Keypairs are different (good randomness)\n\n");

    printf("Test 2: Sign and verify correctness\n");
    QUDO_SLHDSA_keypair(sig, pk1, sk1);
    smlen = sig->length_signature;
    ret = QUDO_SLHDSA_sign(sig, sm, &smlen, msg, msg_len, sk1);
    if (ret != QUDO_SLHDSA_SUCCESS) {
        printf("FAIL: Signing failed with error %d\n", ret);
        ret = 1;
        goto cleanup;
    }
    ret = QUDO_SLHDSA_verify(sig, msg, msg_len, sm, smlen, pk1);
    if (ret != QUDO_SLHDSA_SUCCESS) {
        printf("FAIL: Signature verification failed\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS: Signature verified successfully\n\n");

    printf("Test 3: Wrong message detection\n");
    msg[0] = ~msg[0];
    ret = QUDO_SLHDSA_verify(sig, msg, msg_len, sm, smlen, pk1);
    if (ret == QUDO_SLHDSA_SUCCESS) {
        printf("FAIL: Verification succeeded with wrong message\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS: Wrong message detected correctly\n\n");

    printf("Test 4: Wrong public key detection\n");
    msg[0] = ~msg[0];
    QUDO_SLHDSA_keypair(sig, pk2, sk2);
    ret = QUDO_SLHDSA_verify(sig, msg, msg_len, sm, smlen, pk2);
    if (ret == QUDO_SLHDSA_SUCCESS) {
        printf("FAIL: Verification succeeded with wrong public key\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS: Wrong public key detected correctly\n\n");

    printf("Test 5: Multiple sign/verify rounds (%d)\n", TEST_RUNS);
    for (int i = 0; i < TEST_RUNS; i++) {
        char test_msg[64];
        snprintf(test_msg, sizeof(test_msg), "Test message round %d", i);
        size_t tlen = strlen(test_msg);

        smlen = sig->length_signature;
        ret = QUDO_SLHDSA_sign(sig, sm, &smlen, (uint8_t *)test_msg, tlen, sk1);
        if (ret != QUDO_SLHDSA_SUCCESS) {
            printf("FAIL: Signing failed on round %d\n", i);
            ret = 1;
            goto cleanup;
        }
        ret = QUDO_SLHDSA_verify(sig, (uint8_t *)test_msg, tlen, sm, smlen, pk1);
        if (ret != QUDO_SLHDSA_SUCCESS) {
            printf("FAIL: Verification failed on round %d\n", i);
            ret = 1;
            goto cleanup;
        }
    }
    printf("PASS: All %d rounds succeeded\n\n", TEST_RUNS);

    ret = 0;

cleanup:
    free(pk1);
    free(sk1);
    free(pk2);
    free(sk2);
    free(sm);
    QUDO_SLHDSA_free(sig);
    return ret;
}

int main(void) {
    int failures = 0;

    printf("=== SLH-DSA Sign/Verify Consistency Tests ===\n");

    const char *test_algs[] = {
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256f",
    };

    for (size_t i = 0; i < sizeof(test_algs) / sizeof(test_algs[0]); i++) {
        if (test_sign_consistency(test_algs[i]) != 0) {
            failures++;
        }
    }

    printf("\n=== Results: %zu/%zu consistency tests passed ===\n",
           sizeof(test_algs) / sizeof(test_algs[0]) - failures,
           sizeof(test_algs) / sizeof(test_algs[0]));

    return failures ? 1 : 0;
}
