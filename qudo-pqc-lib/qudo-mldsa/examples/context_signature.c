/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "mldsa_wrapper.h"
#include <stdio.h>
#include <string.h>

int main()
{
    QUDO_MLDSA_init();

    printf("=== QUDO ML-DSA Context String Example ===\n\n");

    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-44");
    if (!sig) {
        fprintf(stderr, "ERROR: Failed to create ML-DSA instance\n");
        return 1;
    }

    printf("Algorithm: %s\n\n", QUDO_MLDSA_get_algorithm_name(sig));

    uint8_t public_key[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t secret_key[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t signature[ML_DSA_44_SIGNATURE_BYTES];
    size_t sig_len = sizeof(signature);

    printf("[1] Generating keypair...\n");
    QUDO_MLDSA_status_t status
        = QUDO_MLDSA_keypair(sig, public_key, secret_key);
    if (status != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "ERROR: Keypair generation failed\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }
    printf("    ✓ Keypair generated\n\n");

    const char *message = "Important transaction: Transfer $1000";
    const char *context_banking = "banking-app-v1";
    const char *context_wrong = "email-client-v1";

    printf("Message: \"%s\"\n", message);
    printf("Correct context: \"%s\"\n", context_banking);
    printf("Wrong context: \"%s\"\n\n", context_wrong);

    printf("[2] Signing with context \"%s\"...\n", context_banking);
    status = QUDO_MLDSA_sign_with_context(
        sig, signature, &sig_len, (const uint8_t *)message, strlen(message),
        (const uint8_t *)context_banking, strlen(context_banking), secret_key);
    if (status != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "ERROR: Signing failed\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }
    printf("    ✓ Signature generated (length: %zu bytes)\n\n", sig_len);

    printf("[3] Verifying with CORRECT context...\n");
    status = QUDO_MLDSA_verify_with_context(
        sig, signature, sig_len, (const uint8_t *)message, strlen(message),
        (const uint8_t *)context_banking, strlen(context_banking), public_key);
    if (status == QUDO_MLDSA_SUCCESS) {
        printf("    ✓ Signature is VALID (correct context)\n\n");
    } else {
        fprintf(stderr, "    ✗ ERROR: Signature should be valid!\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }

    printf("[4] Verifying with WRONG context...\n");
    status = QUDO_MLDSA_verify_with_context(
        sig, signature, sig_len, (const uint8_t *)message, strlen(message),
        (const uint8_t *)context_wrong, strlen(context_wrong), public_key);
    if (status == QUDO_MLDSA_ERROR_VERIFY) {
        printf("    ✓ Correctly rejected (wrong context)\n\n");
    } else {
        fprintf(stderr, "    ✗ ERROR: Should have rejected wrong context!\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }

    printf("[5] Verifying without context...\n");
    status = QUDO_MLDSA_verify_with_context(
        sig, signature, sig_len, (const uint8_t *)message, strlen(message),
        NULL, 0, public_key);
    if (status == QUDO_MLDSA_ERROR_VERIFY) {
        printf("    ✓ Correctly rejected (missing context)\n");
    } else {
        fprintf(stderr, "    ✗ ERROR: Should have rejected missing context!\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }

    QUDO_MLDSA_free(sig);

    printf("\n=== All context tests PASSED ===\n");
    printf("\nContext strings provide domain separation and prevent\n");
    printf("signature reuse across different applications/protocols.\n");
    return 0;
}
