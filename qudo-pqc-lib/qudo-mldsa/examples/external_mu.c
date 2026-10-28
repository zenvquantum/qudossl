/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <string.h>
#include "mldsa_wrapper.h"

static void compute_mu_demo(uint8_t mu[MLDSA_CRHBYTES],
                            const uint8_t *msg, size_t msglen) {
    memset(mu, 0, MLDSA_CRHBYTES);
    for (size_t i = 0; i < msglen; i++) {
        mu[i % MLDSA_CRHBYTES] ^= msg[i];
    }
    for (size_t i = 0; i < MLDSA_CRHBYTES; i++) {
        mu[i] = (mu[i] + i) ^ 0x55;
    }
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < (len > 32 ? 32 : len); i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("... (%zu bytes total)", len);
    printf("\n");
}

int main(void) {
    printf("=== External Mu Signing Example ===\n\n");

    const char *variant = "ML-DSA-65";
    const char *message = "Message to be hashed externally";
    size_t msglen = strlen(message);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(variant);
    if (!sig) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    size_t sig_len = QUDO_MLDSA_get_signature_bytes(sig);

    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];

    printf("--- Keypair Generation ---\n");
    QUDO_MLDSA_status_t ret = QUDO_MLDSA_keypair(sig, pk, sk);
    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }
    printf("✓ Keypair generated\n\n");

    printf("--- External Hash Computation ---\n");
    uint8_t mu[MLDSA_CRHBYTES];
    compute_mu_demo(mu, (const uint8_t *)message, msglen);

    print_hex("Original message", (const uint8_t *)message, msglen);
    print_hex("Computed mu (hash)", mu, MLDSA_CRHBYTES);
    printf("\n");

    printf("--- Signing with External Mu ---\n");
    uint8_t signature[ML_DSA_87_SIGNATURE_BYTES];
    size_t signature_len = sig_len;

    ret = QUDO_MLDSA_sign_extmu(sig, signature, &signature_len, mu, sk);
    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "External mu signing failed: %s\n",
                QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }

    print_hex("Signature", signature, signature_len);
    printf("Signature length: %zu bytes\n", signature_len);
    printf("✓ Signature created from external mu\n\n");

    printf("--- Verification with External Mu ---\n");
    ret = QUDO_MLDSA_verify_extmu(sig, signature, signature_len, mu, pk);
    if (ret == QUDO_MLDSA_SUCCESS) {
        printf("✓ Signature VALID (using external mu)\n");
    } else {
        printf("✗ Signature INVALID: %s\n", QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }

    printf("\n--- Negative Test: Wrong Mu ---\n");
    uint8_t wrong_mu[MLDSA_CRHBYTES];
    memset(wrong_mu, 0xFF, MLDSA_CRHBYTES);

    ret = QUDO_MLDSA_verify_extmu(sig, signature, signature_len, wrong_mu, pk);
    if (ret != QUDO_MLDSA_SUCCESS) {
        printf("✓ Signature correctly rejected with wrong mu\n");
    } else {
        printf("✗ WARNING: Signature accepted with wrong mu!\n");
    }

    printf("\n=== Direct API (ML-DSA-65) ===\n");
    uint8_t sig_direct[ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_direct_len = ML_DSA_65_SIGNATURE_BYTES;

    ret = QUDO_MLDSA_ML_DSA_65_sign_extmu(sig_direct, &sig_direct_len, mu, sk);
    if (ret == QUDO_MLDSA_SUCCESS) {
        print_hex("Direct API signature", sig_direct, sig_direct_len);

        ret = QUDO_MLDSA_ML_DSA_65_verify_extmu(sig_direct, sig_direct_len, mu, pk);
        printf("Direct API verification: %s\n",
               (ret == QUDO_MLDSA_SUCCESS) ? "✓ VALID" : "✗ INVALID");
    }

    QUDO_MLDSA_free(sig);

    printf("\n=== Use Cases ===\n");
    printf("External mu signing is useful for:\n");
    printf("  - Custom hash tree constructions\n");
    printf("  - Merkle tree signatures\n");
    printf("  - Hash-then-sign protocols\n");
    printf("  - Integration with external hash computation\n");
    printf("  - Advanced cryptographic protocols\n");

    return 0;
}
