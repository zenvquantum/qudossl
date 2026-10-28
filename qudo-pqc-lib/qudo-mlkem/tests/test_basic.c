/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include "../include/mlkem_wrapper.h"

int main(void) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    int ret = 0;
    QUDO_KEM *kem = NULL;
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *ct = NULL;
    uint8_t *ss_enc = NULL;
    uint8_t *ss_dec = NULL;

    if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
        printf("FAIL: QUDO_KEM_init()\n");
        return 1;
    }

    printf("QUDO KEM Basic Test\n");
    printf("Version: %s\n", QUDO_KEM_get_version());
    printf("Platform: %s\n", QUDO_KEM_get_platform());
    printf("Architecture: %s\n", QUDO_KEM_get_architecture());
    printf("\n");

    printf("Creating ML-KEM-768 object... ");
    kem = QUDO_KEM_new("ML-KEM-768");
    if (!kem) {
        printf("FAIL\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS\n");

    pk = (uint8_t *)malloc(kem->length_public_key);
    sk = (uint8_t *)malloc(kem->length_secret_key);
    ct = (uint8_t *)malloc(kem->length_ciphertext);
    ss_enc = (uint8_t *)malloc(kem->length_shared_secret);
    ss_dec = (uint8_t *)malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
        printf("FAIL: Memory allocation failed\n");
        ret = 1;
        goto cleanup;
    }

    printf("Test 1: Keypair generation... ");
    if (QUDO_KEM_keypair(kem, pk, sk) != QUDO_KEM_SUCCESS) {
        printf("FAIL\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS\n");

    printf("Test 2: Encapsulation... ");
    if (QUDO_KEM_encaps(kem, ct, ss_enc, pk) != QUDO_KEM_SUCCESS) {
        printf("FAIL\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS\n");

    printf("Test 3: Decapsulation... ");
    if (QUDO_KEM_decaps(kem, ss_dec, ct, sk) != QUDO_KEM_SUCCESS) {
        printf("FAIL\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS\n");

    printf("Test 4: Shared secret match... ");
    if (memcmp(ss_enc, ss_dec, kem->length_shared_secret) != 0) {
        printf("FAIL (shared secrets don't match)\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS\n");

    printf("Test 5: Tamper detection... ");
    ct[0] ^= 1;
    if (QUDO_KEM_decaps(kem, ss_dec, ct, sk) != QUDO_KEM_SUCCESS) {
        printf("FAIL (decaps should succeed with implicit rejection)\n");
        ret = 1;
        goto cleanup;
    }

    if (memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0) {
        printf("FAIL (implicit rejection not working)\n");
        ret = 1;
        goto cleanup;
    }
    printf("PASS\n");

    printf("\n✓ All basic tests passed\n");

cleanup:

    free(pk);
    free(sk);
    free(ct);
    free(ss_enc);
    free(ss_dec);
    QUDO_KEM_free(kem);
    QUDO_KEM_cleanup();
    OPENSSL_cleanup();

    return ret;
}
