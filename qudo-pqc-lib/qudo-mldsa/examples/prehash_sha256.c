/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <string.h>
#include "mldsa_wrapper.h"

static void simple_sha256_demo(uint8_t hash[32], const uint8_t *data, size_t len) {
    memset(hash, 0, 32);
    for (size_t i = 0; i < len; i++) {
        hash[i % 32] ^= data[i];
        hash[(i + 1) % 32] += data[i];
    }
    for (int i = 0; i < 32; i++) {
        hash[i] = (hash[i] + hash[(i + 7) % 32]) ^ (i * 17);
    }
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    printf("=== HashML-DSA Pre-Hash Signing Example ===\n\n");

    const char *variant = "ML-DSA-65";

    const char *large_file_chunk1 = "This is chunk 1 of a very large file... ";
    const char *large_file_chunk2 = "This is chunk 2 of a very large file... ";
    const char *large_file_chunk3 = "This is chunk 3 of a very large file... ";

    printf("Scenario: Signing a large file by hashing it first\n");
    printf("File chunks:\n");
    printf("  Chunk 1: \"%s\"\n", large_file_chunk1);
    printf("  Chunk 2: \"%s\"\n", large_file_chunk2);
    printf("  Chunk 3: \"%s\"\n", large_file_chunk3);
    printf("\n");

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

    printf("--- Pre-Hash Computation (SHA2-256) ---\n");
    uint8_t file_hash[32];

    simple_sha256_demo(file_hash, (const uint8_t *)large_file_chunk1, strlen(large_file_chunk1));

    print_hex("File SHA2-256 hash", file_hash, 32);
    printf("Hash length: 32 bytes (SHA2-256)\n");
    printf("\n");

    printf("--- HashML-DSA Signing ---\n");
    const char *context = "document-signature-v2";
    size_t ctxlen = strlen(context);
    uint8_t rnd[MLDSA_RNDBYTES];
    memset(rnd, 0xAB, MLDSA_RNDBYTES);

    uint8_t signature[ML_DSA_87_SIGNATURE_BYTES];
    size_t signature_len = sig_len;

    printf("Context: \"%s\"\n", context);
    printf("Hash algorithm: SHA2-256 (QUDO_PREHASH_SHA2_256)\n");

    ret = QUDO_MLDSA_sign_pre_hash_internal(
        sig, signature, &signature_len,
        file_hash, 32,
        (const uint8_t *)context, ctxlen,
        rnd, sk,
        QUDO_PREHASH_SHA2_256
    );

    if (ret != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "Pre-hash signing failed: %s\n",
                QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }

    print_hex("Signature (first 64 bytes)", signature, 64);
    printf("Signature length: %zu bytes\n", signature_len);
    printf("✓ Pre-hash signature created\n\n");

    printf("--- HashML-DSA Verification ---\n");
    ret = QUDO_MLDSA_verify_pre_hash_internal(
        sig, signature, signature_len,
        file_hash, 32,
        (const uint8_t *)context, ctxlen,
        pk,
        QUDO_PREHASH_SHA2_256
    );

    if (ret == QUDO_MLDSA_SUCCESS) {
        printf("✓ Pre-hash signature VALID\n");
    } else {
        printf("✗ Pre-hash signature INVALID: %s\n",
               QUDO_MLDSA_error_string(ret));
        QUDO_MLDSA_free(sig);
        return 1;
    }

    printf("\n--- Negative Test: Wrong Hash ---\n");
    uint8_t wrong_hash[32];
    memset(wrong_hash, 0xFF, 32);

    ret = QUDO_MLDSA_verify_pre_hash_internal(
        sig, signature, signature_len,
        wrong_hash, 32,
        (const uint8_t *)context, ctxlen,
        pk,
        QUDO_PREHASH_SHA2_256
    );

    if (ret != QUDO_MLDSA_SUCCESS) {
        printf("✓ Wrong hash correctly rejected\n");
    } else {
        printf("✗ WARNING: Wrong hash was accepted!\n");
    }

    printf("\n--- Negative Test: Wrong Hash Algorithm ---\n");
    ret = QUDO_MLDSA_verify_pre_hash_internal(
        sig, signature, signature_len,
        file_hash, 32,
        (const uint8_t *)context, ctxlen,
        pk,
        QUDO_PREHASH_SHA2_512
    );

    if (ret != QUDO_MLDSA_SUCCESS) {
        printf("✓ Wrong hash algorithm correctly rejected\n");
    } else {
        printf("✗ WARNING: Wrong hash algorithm was accepted!\n");
    }

    printf("\n=== Other Supported Hash Algorithms ===\n");
    const char *hash_algs[] = {
        "SHA2-256", "SHA2-512", "SHA3-256", "SHA3-512",
        "SHAKE-128", "SHAKE-256"
    };
    int hash_ids[] = {
        QUDO_PREHASH_SHA2_256, QUDO_PREHASH_SHA2_512,
        QUDO_PREHASH_SHA3_256, QUDO_PREHASH_SHA3_512,
        QUDO_PREHASH_SHAKE_128, QUDO_PREHASH_SHAKE_256
    };

    for (int i = 0; i < 6; i++) {
        printf("  %d: %s\n", hash_ids[i], hash_algs[i]);
    }

    printf("\n=== Direct API (ML-DSA-65) ===\n");
    uint8_t sig_direct[ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_direct_len = ML_DSA_65_SIGNATURE_BYTES;

    ret = QUDO_MLDSA_ML_DSA_65_sign_pre_hash(
        sig_direct, &sig_direct_len,
        file_hash, 32,
        (const uint8_t *)context, ctxlen,
        rnd, sk,
        QUDO_PREHASH_SHA2_256
    );

    if (ret == QUDO_MLDSA_SUCCESS) {
        printf("Direct API signature length: %zu bytes\n", sig_direct_len);

        ret = QUDO_MLDSA_ML_DSA_65_verify_pre_hash(
            sig_direct, sig_direct_len,
            file_hash, 32,
            (const uint8_t *)context, ctxlen,
            pk,
            QUDO_PREHASH_SHA2_256
        );
        printf("Direct API verification: %s\n",
               (ret == QUDO_MLDSA_SUCCESS) ? "✓ VALID" : "✗ INVALID");
    }

    QUDO_MLDSA_free(sig);

    printf("\n=== Use Cases ===\n");
    printf("HashML-DSA (pre-hash signing) is useful for:\n");
    printf("  - Large file signing (GBs of data)\n");
    printf("  - Streaming data signatures\n");
    printf("  - Integration with existing hash workflows\n");
    printf("  - Reduced memory requirements\n");
    printf("  - Sign-what-you-hash protocols\n");

    return 0;
}
