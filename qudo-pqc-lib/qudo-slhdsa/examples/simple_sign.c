/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "slhdsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *alg = "SLH-DSA-SHA2-128f";

    printf("=== QUDO SLH-DSA Simple Example ===\n\n");
    printf("Algorithm: %s\n", alg);

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg);
    if (!sig) {
        fprintf(stderr, "Failed to create SLH-DSA instance\n");
        return 1;
    }

    printf("Public key size:  %zu bytes\n", sig->length_public_key);
    printf("Secret key size:  %zu bytes\n", sig->length_secret_key);
    printf("Signature size:   %zu bytes\n\n", sig->length_signature);

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    printf("Generating keypair...\n");
    if (QUDO_SLHDSA_keypair(sig, pk, sk) != QUDO_SLHDSA_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        goto cleanup;
    }
    printf("Keypair generated successfully.\n\n");

    const char *message = "Hello, Post-Quantum World!";
    size_t msg_len = strlen(message);
    size_t sig_len = sig->length_signature;

    printf("Signing message: \"%s\"\n", message);
    if (QUDO_SLHDSA_sign(sig, signature, &sig_len,
                          (const uint8_t *)message, msg_len, sk) != QUDO_SLHDSA_SUCCESS) {
        fprintf(stderr, "Signing failed\n");
        goto cleanup;
    }
    printf("Signature generated: %zu bytes\n\n", sig_len);

    printf("Verifying signature...\n");
    if (QUDO_SLHDSA_verify(sig, (const uint8_t *)message, msg_len,
                            signature, sig_len, pk) == QUDO_SLHDSA_SUCCESS) {
        printf("Verification: SUCCESS\n\n");
    } else {
        printf("Verification: FAILED\n\n");
    }

cleanup:
    free(pk);
    free(sk);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return 0;
}
