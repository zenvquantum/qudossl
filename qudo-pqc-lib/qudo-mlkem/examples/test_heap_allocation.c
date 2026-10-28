/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <string.h>
#include "mlkem_wrapper.h"

int main() {
    printf("===========================================\n");
    printf("QUDO KEM - Heap Allocation Test\n");
    printf("===========================================\n\n");

    if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "Failed to initialize QUDO KEM\n");
        return 1;
    }

    printf("Test 1: Multiple instances are independent\n");
    printf("-------------------------------------------\n");

    QUDO_KEM *kem1 = QUDO_KEM_new("ML-KEM-768");
    QUDO_KEM *kem2 = QUDO_KEM_new("ML-KEM-768");
    QUDO_KEM *kem3 = QUDO_KEM_new_by_level(QUDO_KEM_768);

    if (!kem1 || !kem2 || !kem3) {
        fprintf(stderr, "Failed to create KEM instances\n");
        return 1;
    }

    printf("kem1 address: %p\n", (void*)kem1);
    printf("kem2 address: %p\n", (void*)kem2);
    printf("kem3 address: %p\n", (void*)kem3);

    if (kem1 == kem2 || kem1 == kem3 || kem2 == kem3) {
        printf("FAIL: Instances share the same memory address!\n");
        QUDO_KEM_free(kem1);
        QUDO_KEM_free(kem2);
        QUDO_KEM_free(kem3);
        return 1;
    }

    printf("SUCCESS: All instances have different addresses!\n");
    printf("\n");

    printf("Test 2: Free and re-allocate\n");
    printf("-------------------------------------------\n");

    void *old_addr = (void*)kem2;
    QUDO_KEM_free(kem2);
    printf("Freed kem2 at address: %p\n", old_addr);

    kem2 = QUDO_KEM_new("ML-KEM-512");
    if (!kem2) {
        fprintf(stderr, "Failed to re-allocate KEM instance\n");
        QUDO_KEM_free(kem1);
        QUDO_KEM_free(kem3);
        return 1;
    }

    printf("New kem2 address: %p\n", (void*)kem2);
    printf("SUCCESS: Free and re-allocate works!\n\n");

    printf("Test 3: Functional test with heap-allocated objects\n");
    printf("-------------------------------------------\n");

    size_t pk_len = QUDO_KEM_get_public_key_size(QUDO_KEM_768);
    size_t sk_len = QUDO_KEM_get_secret_key_size(QUDO_KEM_768);
    size_t ct_len = QUDO_KEM_get_ciphertext_size(QUDO_KEM_768);

    uint8_t pk[2048], sk[4096], ct[2048];
    uint8_t ss1[32], ss2[32];

    if (QUDO_KEM_keypair(kem1, pk, sk) != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        goto cleanup;
    }
    printf("Generated keypair with kem1\n");

    if (QUDO_KEM_encaps(kem3, ct, ss1, pk) != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "Encapsulation failed\n");
        goto cleanup;
    }
    printf("Encapsulated with kem3\n");

    if (QUDO_KEM_decaps(kem1, ss2, ct, sk) != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "Decapsulation failed\n");
        goto cleanup;
    }
    printf("Decapsulated with kem1\n");

    if (memcmp(ss1, ss2, 32) == 0) {
        printf("SUCCESS: Shared secrets match!\n");
        printf("Heap-allocated objects work correctly.\n\n");
    } else {
        printf("FAIL: Shared secrets don't match!\n");
        goto cleanup;
    }

    printf("Test 4: Memory cleanup\n");
    printf("-------------------------------------------\n");

cleanup:
    QUDO_KEM_free(kem1);
    QUDO_KEM_free(kem2);
    QUDO_KEM_free(kem3);
    printf("All instances freed\n");

    QUDO_KEM_cleanup();

    printf("\n===========================================\n");
    printf("All heap allocation tests completed!\n");
    printf("===========================================\n");
    printf("\nTo check for memory leaks, run:\n");
    printf("  valgrind --leak-check=full ./test_heap_allocation\n\n");

    return 0;
}
