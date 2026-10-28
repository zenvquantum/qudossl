/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <string.h>
#include "mlkem_wrapper.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < (len < 16 ? len : 16); i++) {
        printf("%02x", data[i]);
    }
    if (len > 16) printf("... (%zu bytes)", len);
    printf("\n");
}

int main() {
    int i;
    QUDO_KEM_security_level_t levels[] = {QUDO_KEM_512, QUDO_KEM_768, QUDO_KEM_1024};
    const char *level_names[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};

    if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "Failed to initialize QUDO KEM\n");
        return 1;
    }

    printf("===========================================\n");
    printf("QUDO KEM - ML-KEM Example\n");
    printf("===========================================\n");
    printf("Library version: %s\n\n", QUDO_KEM_get_version());

    for (i = 0; i < 3; i++) {
        QUDO_KEM_security_level_t level = levels[i];
        printf("-------------------------------------------\n");
        printf("Testing %s (NIST Level %d)\n", level_names[i], (i+1)*2-1);
        printf("-------------------------------------------\n");

        size_t pk_len = QUDO_KEM_get_public_key_size(level);
        size_t sk_len = QUDO_KEM_get_secret_key_size(level);
        size_t ct_len = QUDO_KEM_get_ciphertext_size(level);

        if (pk_len == 0 || sk_len == 0 || ct_len == 0) {
            fprintf(stderr, "Invalid security level\n");
            continue;
        }

        uint8_t public_key[2048];
        uint8_t secret_key[4096];

        printf("Generating keypair...\n");
        if (QUDO_KEM_keypair_generate(level, public_key, secret_key) != QUDO_KEM_SUCCESS) {
            fprintf(stderr, "Failed to generate keypair\n");
            continue;
        }

        printf("  Public key:  %zu bytes\n", pk_len);
        printf("  Secret key:  %zu bytes\n", sk_len);
        print_hex("  Public key", public_key, pk_len);

        printf("\nEncapsulating (sender side)...\n");
        uint8_t ciphertext[2048];
        uint8_t shared_secret_sender[32];

        if (QUDO_KEM_encapsulate(level, ciphertext, shared_secret_sender, public_key) != QUDO_KEM_SUCCESS) {
            fprintf(stderr, "Failed to encapsulate\n");
            continue;
        }

        printf("  Ciphertext: %zu bytes\n", ct_len);
        print_hex("  Shared secret (sender)", shared_secret_sender, 32);

        printf("\nDecapsulating (receiver side)...\n");
        uint8_t shared_secret_receiver[32];

        if (QUDO_KEM_decapsulate(level, shared_secret_receiver, ciphertext, secret_key) != QUDO_KEM_SUCCESS) {
            fprintf(stderr, "Failed to decapsulate\n");
            continue;
        }

        print_hex("  Shared secret (receiver)", shared_secret_receiver, 32);

        if (memcmp(shared_secret_sender, shared_secret_receiver, 32) == 0) {
            printf("\nSUCCESS: Both sides have the same shared secret!\n");
        } else {
            printf("\nFAIL: Shared secrets don't match!\n");
        }

        printf("\n");
    }

    QUDO_KEM_cleanup();

    printf("===========================================\n");
    printf("All tests completed\n");
    printf("===========================================\n");

    return 0;
}
