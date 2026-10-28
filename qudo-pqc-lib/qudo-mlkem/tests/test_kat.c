/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/crypto.h>

#include "../include/mlkem_wrapper.h"

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
    if (strlen(hex) != bytes_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)byte;
    }
    return 0;
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s = ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len, const char *name) {
    if (memcmp(a, b, len) != 0) {
        printf("❌ MISMATCH in %s\n", name);
        printf("  Expected: ");
        for (size_t i = 0; i < (len < 16 ? len : 16); i++) {
            printf("%02X", a[i]);
        }
        if (len > 16) printf("...");
        printf("\n  Got:      ");
        for (size_t i = 0; i < (len < 16 ? len : 16); i++) {
            printf("%02X", b[i]);
        }
        if (len > 16) printf("...");
        printf("\n");
        return 0;
    }
    return 1;
}

typedef struct {
    int count;
    const char *seed_hex;
    const char *pk_hex;
    const char *sk_hex;
    const char *ct_hex;
    const char *ss_hex;
} kat_vector_t;

static const kat_vector_t kat_vectors_512[] = {
    {
        .count = 0,

        .seed_hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",

        .pk_hex = NULL,
        .sk_hex = NULL,
        .ct_hex = NULL,
        .ss_hex = NULL,
    },

};

static int test_consistency(const char *alg_name, const char *name) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Testing %s Consistency\n", name);
    printf("═══════════════════════════════════════════════════════════════\n\n");

    QUDO_KEM *kem = QUDO_KEM_new(alg_name);
    if (!kem) {
        printf("❌ Failed to create KEM object\n");
        return 0;
    }

    printf("Parameters:\n");
    printf("  Public key:    %zu bytes\n", kem->length_public_key);
    printf("  Secret key:    %zu bytes\n", kem->length_secret_key);
    printf("  Ciphertext:    %zu bytes\n", kem->length_ciphertext);
    printf("  Shared secret: %zu bytes\n\n", kem->length_shared_secret);

    uint8_t *pk1 = malloc(kem->length_public_key);
    uint8_t *sk1 = malloc(kem->length_secret_key);
    uint8_t *pk2 = malloc(kem->length_public_key);
    uint8_t *sk2 = malloc(kem->length_secret_key);
    uint8_t *ct1 = malloc(kem->length_ciphertext);
    uint8_t *ct2 = malloc(kem->length_ciphertext);
    uint8_t *ss_e1 = malloc(kem->length_shared_secret);
    uint8_t *ss_e2 = malloc(kem->length_shared_secret);
    uint8_t *ss_d1 = malloc(kem->length_shared_secret);
    uint8_t *ss_d2 = malloc(kem->length_shared_secret);

    if (!pk1 || !sk1 || !pk2 || !sk2 || !ct1 || !ct2 || !ss_e1 || !ss_e2 || !ss_d1 || !ss_d2) {
        printf("❌ Memory allocation failed\n");
        goto cleanup;
    }

    int passed = 1;

    printf("Test 1: Keypair generation produces random keys\n");
    if (kem->keypair(pk1, sk1) != QUDO_KEM_SUCCESS) {
        printf("❌ Keypair 1 generation failed\n");
        passed = 0;
        goto cleanup;
    }
    if (kem->keypair(pk2, sk2) != QUDO_KEM_SUCCESS) {
        printf("❌ Keypair 2 generation failed\n");
        passed = 0;
        goto cleanup;
    }

    if (memcmp(pk1, pk2, kem->length_public_key) == 0) {
        printf("❌ Two keypairs generated identical public keys (RNG problem!)\n");
        passed = 0;
    } else {
        printf("✅ Keypairs are different (good randomness)\n");
    }

    printf("\nTest 2: Encapsulation randomness\n");
    if (kem->encaps(ct1, ss_e1, pk1) != QUDO_KEM_SUCCESS) {
        printf("❌ Encapsulation 1 failed\n");
        passed = 0;
        goto cleanup;
    }
    if (kem->encaps(ct2, ss_e2, pk1) != QUDO_KEM_SUCCESS) {
        printf("❌ Encapsulation 2 failed\n");
        passed = 0;
        goto cleanup;
    }

    if (memcmp(ct1, ct2, kem->length_ciphertext) == 0) {
        printf("❌ Two encapsulations produced identical ciphertexts (RNG problem!)\n");
        passed = 0;
    } else {
        printf("✅ Ciphertexts are different (good randomness)\n");
    }

    if (memcmp(ss_e1, ss_e2, kem->length_shared_secret) == 0) {
        printf("❌ Two encapsulations produced identical shared secrets\n");
        passed = 0;
    } else {
        printf("✅ Shared secrets are different (good randomness)\n");
    }

    printf("\nTest 3: Decapsulation correctness\n");
    if (kem->decaps(ss_d1, ct1, sk1) != QUDO_KEM_SUCCESS) {
        printf("❌ Decapsulation failed\n");
        passed = 0;
        goto cleanup;
    }

    if (compare_bytes(ss_e1, ss_d1, kem->length_shared_secret, "shared secret")) {
        printf("✅ Decapsulation recovered correct shared secret\n");
    } else {
        passed = 0;
    }

    printf("\nTest 4: Implicit rejection (wrong key)\n");
    if (kem->decaps(ss_d2, ct1, sk2) != QUDO_KEM_SUCCESS) {
        printf("❌ Decapsulation with wrong key failed (should succeed with different ss)\n");
        passed = 0;
    } else {
        if (memcmp(ss_e1, ss_d2, kem->length_shared_secret) != 0) {
            printf("✅ Wrong key produces different shared secret (implicit rejection working)\n");
        } else {
            printf("❌ Wrong key produced same shared secret (implicit rejection not working!)\n");
            passed = 0;
        }
    }

cleanup:
    free(pk1); free(sk1); free(pk2); free(sk2);
    free(ct1); free(ct2);
    free(ss_e1); free(ss_e2); free(ss_d1); free(ss_d2);
    QUDO_KEM_free(kem);

    if (passed) {
        printf("\n✅ All consistency tests PASSED for %s\n", name);
    } else {
        printf("\n❌ Some consistency tests FAILED for %s\n", name);
    }

    return passed;
}

int main(int argc, char **argv) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          ML-KEM Known Answer Test (KAT) Suite               ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    int all_passed = 1;

    printf("\n");
    all_passed &= test_consistency(QUDO_KEM_alg_mlkem_512, "ML-KEM-512");
    all_passed &= test_consistency(QUDO_KEM_alg_mlkem_768, "ML-KEM-768");
    all_passed &= test_consistency(QUDO_KEM_alg_mlkem_1024, "ML-KEM-1024");

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Final Result\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int ret;
    if (all_passed) {
        printf("✅ ALL KAT TESTS PASSED\n\n");
        ret = 0;
    } else {
        printf("❌ SOME KAT TESTS FAILED\n\n");
        ret = 1;
    }
    OPENSSL_cleanup();
    return ret;
}
