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
    printf("=== Deterministic Keypair Generation Example ===\n\n");

    uint8_t seed[MLDSA_SEEDBYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };

    const char *variants[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    for (int i = 0; i < 3; i++) {
        printf("--- %s ---\n", variants[i]);

        QUDO_MLDSA *sig = QUDO_MLDSA_new(variants[i]);
        if (!sig) {
            fprintf(stderr, "Failed to create %s context\n", variants[i]);
            continue;
        }

        size_t pk_len = QUDO_MLDSA_get_public_key_bytes(sig);
        size_t sk_len = QUDO_MLDSA_get_secret_key_bytes(sig);

        uint8_t pk1[ML_DSA_87_PUBLIC_KEY_BYTES];
        uint8_t sk1[ML_DSA_87_SECRET_KEY_BYTES];
        uint8_t pk2[ML_DSA_87_PUBLIC_KEY_BYTES];
        uint8_t sk2[ML_DSA_87_SECRET_KEY_BYTES];

        QUDO_MLDSA_status_t ret = QUDO_MLDSA_keypair_internal(sig, pk1, sk1, seed);
        if (ret != QUDO_MLDSA_SUCCESS) {
            fprintf(stderr, "Failed to generate keypair 1: %s\n",
                    QUDO_MLDSA_error_string(ret));
            QUDO_MLDSA_free(sig);
            continue;
        }

        ret = QUDO_MLDSA_keypair_internal(sig, pk2, sk2, seed);
        if (ret != QUDO_MLDSA_SUCCESS) {
            fprintf(stderr, "Failed to generate keypair 2: %s\n",
                    QUDO_MLDSA_error_string(ret));
            QUDO_MLDSA_free(sig);
            continue;
        }

        int pk_match = (memcmp(pk1, pk2, pk_len) == 0);
        int sk_match = (memcmp(sk1, sk2, sk_len) == 0);

        printf("Public key size: %zu bytes\n", pk_len);
        printf("Secret key size: %zu bytes\n", sk_len);
        print_hex("Seed", seed, MLDSA_SEEDBYTES);
        print_hex("Public Key", pk1, pk_len);
        print_hex("Secret Key", sk1, sk_len);

        printf("Determinism check:\n");
        printf("  Public keys match: %s\n", pk_match ? "✓ YES" : "✗ NO");
        printf("  Secret keys match: %s\n", sk_match ? "✓ YES" : "✗ NO");

        if (pk_match && sk_match) {
            printf("✓ Deterministic key generation verified!\n");
        } else {
            printf("✗ Keys don't match - NOT deterministic!\n");
        }

        QUDO_MLDSA_free(sig);
        printf("\n");
    }

    printf("=== Direct API Example ===\n");

    uint8_t pk_direct[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk_direct[ML_DSA_65_SECRET_KEY_BYTES];

    QUDO_MLDSA_status_t ret = QUDO_MLDSA_ML_DSA_65_keypair_internal(
        pk_direct, sk_direct, seed
    );

    if (ret == QUDO_MLDSA_SUCCESS) {
        printf("ML-DSA-65 direct API keypair generation:\n");
        print_hex("Public Key", pk_direct, ML_DSA_65_PUBLIC_KEY_BYTES);
        print_hex("Secret Key", sk_direct, ML_DSA_65_SECRET_KEY_BYTES);
        printf("✓ Direct API works!\n");
    } else {
        printf("✗ Direct API failed: %s\n", QUDO_MLDSA_error_string(ret));
    }

    return 0;
}
