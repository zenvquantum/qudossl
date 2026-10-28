/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <string.h>
#include "mldsa_wrapper.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < (len > 32 ? 32 : len); i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("... (%zu bytes total)", len);
    printf("\n");
}

int main(void) {
    printf("=== Deterministic Signature Generation Example ===\n\n");

    const char *variant = "ML-DSA-65";

    uint8_t seed[MLDSA_SEEDBYTES] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };

    uint8_t rnd[MLDSA_RNDBYTES] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
    };

    const char *message = "Deterministic signing test message";
    size_t msglen = strlen(message);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(variant);
    if (!sig) {
        fprintf(stderr, "Failed to create %s context\n", variant);
        return 1;
    }

    size_t pk_len = QUDO_MLDSA_get_public_key_bytes(sig);
    size_t sig_len = QUDO_MLDSA_get_signature_bytes(sig);

    uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];

    printf("--- Deterministic Keypair Generation ---\n");
    QUDO_MLDSA_status_t ret = QUDO_MLDSA_keypair_internal(sig, pk, sk, seed);
    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "Keypair generation failed: %s\n",
                QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }
    print_hex("Seed", seed, MLDSA_SEEDBYTES);
    print_hex("Public Key", pk, pk_len);
    printf("\n");

    printf("--- Deterministic Signature Generation ---\n");
    uint8_t sig1[ML_DSA_87_SIGNATURE_BYTES];
    uint8_t sig2[ML_DSA_87_SIGNATURE_BYTES];
    size_t sig1_len = sig_len;
    size_t sig2_len = sig_len;

    print_hex("Message", (const uint8_t *)message, msglen);
    print_hex("Randomness", rnd, MLDSA_RNDBYTES);

    ret = QUDO_MLDSA_sign_internal(sig, sig1, &sig1_len,
                                  (const uint8_t *)message, msglen,
                                  NULL, 0, rnd, sk, 0);
    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "Signature 1 failed: %s\n",
                QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }

    ret = QUDO_MLDSA_sign_internal(sig, sig2, &sig2_len,
                                  (const uint8_t *)message, msglen,
                                  NULL, 0, rnd, sk, 0);
    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "Signature 2 failed: %s\n",
                QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }

    print_hex("Signature 1", sig1, sig1_len);
    print_hex("Signature 2", sig2, sig2_len);

    int sig_match = (sig1_len == sig2_len) && (memcmp(sig1, sig2, sig1_len) == 0);

    printf("\nDeterminism check:\n");
    printf("  Signature 1 length: %zu bytes\n", sig1_len);
    printf("  Signature 2 length: %zu bytes\n", sig2_len);
    printf("  Signatures match: %s\n", sig_match ? "✓ YES" : "✗ NO");

    if (sig_match) {
        printf("✓ Deterministic signing verified!\n");
    } else {
        printf("✗ Signatures don't match - NOT deterministic!\n");
        QUDO_MLDSA_free(sig);
        return 1;
    }

    printf("\n--- Signature Verification ---\n");
    ret = QUDO_MLDSA_verify(sig, sig1, sig1_len, (const uint8_t *)message, msglen, pk);
    printf("Signature 1 verification: %s\n",
           (ret == QUDO_MLDSA_SUCCESS) ? "✓ VALID" : "✗ INVALID");

    ret = QUDO_MLDSA_verify(sig, sig2, sig2_len, (const uint8_t *)message, msglen, pk);
    printf("Signature 2 verification: %s\n",
           (ret == QUDO_MLDSA_SUCCESS) ? "✓ VALID" : "✗ INVALID");

    printf("\n--- Non-Deterministic Comparison ---\n");
    uint8_t rnd_different[MLDSA_RNDBYTES] = {0};
    uint8_t sig3[ML_DSA_87_SIGNATURE_BYTES];
    size_t sig3_len = sig_len;

    ret = QUDO_MLDSA_sign_internal(sig, sig3, &sig3_len,
                                  (const uint8_t *)message, msglen,
                                  NULL, 0, rnd_different, sk, 0);
    if (ret == QUDO_MLDSA_SUCCESS) {
        int sig_different = (memcmp(sig1, sig3, sig1_len) != 0);
        print_hex("Different randomness", rnd_different, MLDSA_RNDBYTES);
        print_hex("Signature 3", sig3, sig3_len);
        printf("Signature 3 != Signature 1: %s (as expected)\n",
               sig_different ? "✓ YES" : "✗ NO");

        ret = QUDO_MLDSA_verify(sig, sig3, sig3_len, (const uint8_t *)message, msglen, pk);
        printf("Signature 3 verification: %s\n",
               (ret == QUDO_MLDSA_SUCCESS) ? "✓ VALID" : "✗ INVALID");
    }

    QUDO_MLDSA_free(sig);
    return 0;
}
