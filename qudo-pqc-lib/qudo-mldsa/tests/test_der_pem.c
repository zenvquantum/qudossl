/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mldsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_PASSED 0
#define TEST_FAILED 1

static int test_public_key_der_pem(const char *variant) {
    printf("\n=== Testing %s Public Key DER/PEM ===\n", variant);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(variant);
    if (!sig) {
        printf("ERROR: Failed to create signature instance\n");
        return TEST_FAILED;
    }

    size_t pk_len = QUDO_MLDSA_get_public_key_bytes(sig);
    size_t sk_len = QUDO_MLDSA_get_secret_key_bytes(sig);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);

    if (!pk || !sk) {
        printf("ERROR: Memory allocation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }

    printf("1. Generating keypair...\n");
    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Keypair generation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   Public key size: %zu bytes\n", pk_len);

    printf("2. Exporting public key to DER...\n");
    uint8_t der_buffer[4096];
    size_t der_len = sizeof(der_buffer);

    if (QUDO_MLDSA_export_public_key_der(pk, pk_len, der_buffer, &der_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: DER export failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   DER size: %zu bytes\n", der_len);

    printf("3. Importing public key from DER...\n");
    uint8_t pk_imported[4096];
    size_t pk_imported_len = sizeof(pk_imported);

    if (QUDO_MLDSA_import_public_key_der(der_buffer, der_len, pk_imported, &pk_imported_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: DER import failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   Imported key size: %zu bytes\n", pk_imported_len);

    if (pk_imported_len != pk_len || memcmp(pk, pk_imported, pk_len) != 0) {
        printf("ERROR: DER round-trip failed - keys don't match!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   ✓ DER round-trip successful\n");

    printf("4. Exporting public key to PEM...\n");
    char pem_buffer[8192];
    size_t pem_len = sizeof(pem_buffer);

    if (QUDO_MLDSA_export_public_key_pem(pk, pk_len, pem_buffer, &pem_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: PEM export failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   PEM size: %zu bytes\n", pem_len);
    printf("   PEM preview:\n%.*s\n", (int)(pem_len < 200 ? pem_len : 200), pem_buffer);

    printf("5. Importing public key from PEM...\n");
    uint8_t pk_from_pem[4096];
    size_t pk_from_pem_len = sizeof(pk_from_pem);

    if (QUDO_MLDSA_import_public_key_pem(pem_buffer, pk_from_pem, &pk_from_pem_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: PEM import failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }

    if (pk_from_pem_len != pk_len || memcmp(pk, pk_from_pem, pk_len) != 0) {
        printf("ERROR: PEM round-trip failed - keys don't match!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   ✓ PEM round-trip successful\n");

    printf("6. Testing signature with imported public key...\n");
    const char *message = "Test message for DER/PEM verification";
    uint8_t signature[8192];
    size_t sig_len = sizeof(signature);

    if (QUDO_MLDSA_sign(sig, signature, &sig_len, (const uint8_t *)message, strlen(message), sk) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Signature generation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }

    if (QUDO_MLDSA_verify(sig, signature, sig_len, (const uint8_t *)message, strlen(message), pk_imported) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Signature verification failed with imported key!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   ✓ Signature verified with imported public key\n");

    QUDO_MLDSA_free(sig);
    free(pk);
    free(sk);
    return TEST_PASSED;
}

static int test_private_key_der_pem(const char *variant) {
    printf("\n=== Testing %s Private Key DER/PEM (PKCS#8) ===\n", variant);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(variant);
    if (!sig) {
        printf("ERROR: Failed to create signature instance\n");
        return TEST_FAILED;
    }

    size_t pk_len = QUDO_MLDSA_get_public_key_bytes(sig);
    size_t sk_len = QUDO_MLDSA_get_secret_key_bytes(sig);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);

    if (!pk || !sk) {
        printf("ERROR: Memory allocation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }

    printf("1. Generating keypair...\n");
    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Keypair generation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   Private key size: %zu bytes\n", sk_len);

    printf("2. Exporting private key to DER (PKCS#8)...\n");
    uint8_t der_buffer[16384];
    size_t der_len = sizeof(der_buffer);

    if (QUDO_MLDSA_export_private_key_der(sk, sk_len, der_buffer, &der_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Private key DER export failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   DER size: %zu bytes\n", der_len);

    printf("3. Importing private key from DER...\n");
    uint8_t sk_imported[8192];
    size_t sk_imported_len = sizeof(sk_imported);

    if (QUDO_MLDSA_import_private_key_der(der_buffer, der_len, sk_imported, &sk_imported_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Private key DER import failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   Imported key size: %zu bytes\n", sk_imported_len);

    if (sk_imported_len != sk_len || memcmp(sk, sk_imported, sk_len) != 0) {
        printf("ERROR: Private key DER round-trip failed - keys don't match!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   ✓ Private key DER round-trip successful\n");

    printf("4. Exporting private key to PEM...\n");
    char pem_buffer[32768];
    size_t pem_len = sizeof(pem_buffer);

    if (QUDO_MLDSA_export_private_key_pem(sk, sk_len, pem_buffer, &pem_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Private key PEM export failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   PEM size: %zu bytes\n", pem_len);
    printf("   PEM preview:\n%.*s\n", (int)(pem_len < 200 ? pem_len : 200), pem_buffer);

    printf("5. Importing private key from PEM...\n");
    uint8_t sk_from_pem[8192];
    size_t sk_from_pem_len = sizeof(sk_from_pem);

    if (QUDO_MLDSA_import_private_key_pem(pem_buffer, sk_from_pem, &sk_from_pem_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Private key PEM import failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }

    if (sk_from_pem_len != sk_len || memcmp(sk, sk_from_pem, sk_len) != 0) {
        printf("ERROR: Private key PEM round-trip failed - keys don't match!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   ✓ Private key PEM round-trip successful\n");

    printf("6. Testing signature with imported private key...\n");
    const char *message = "Test message for private key DER/PEM verification";
    uint8_t signature[8192];
    size_t sig_len = sizeof(signature);

    if (QUDO_MLDSA_sign(sig, signature, &sig_len, (const uint8_t *)message, strlen(message), sk_imported) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Signature generation failed with imported private key!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }

    if (QUDO_MLDSA_verify(sig, signature, sig_len, (const uint8_t *)message, strlen(message), pk) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Signature verification failed!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   ✓ Signature verified with imported private key\n");

    QUDO_MLDSA_free(sig);
    free(pk);
    free(sk);
    return TEST_PASSED;
}

static int test_seed_priv_der(const char *variant) {
    printf("\n=== Testing %s SEED_PRIV DER Round-Trip ===\n", variant);

    QUDO_MLDSA *sig = QUDO_MLDSA_new(variant);
    if (!sig) {
        printf("ERROR: Failed to create signature instance\n");
        return TEST_FAILED;
    }

    size_t pk_len = QUDO_MLDSA_get_public_key_bytes(sig);
    size_t sk_len = QUDO_MLDSA_get_secret_key_bytes(sig);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t seed[MLDSA_SEEDBYTES];

    if (!pk || !sk) {
        printf("ERROR: Memory allocation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }

    memset(seed, 0x42, MLDSA_SEEDBYTES);

    printf("1. Generating keypair from seed...\n");
    if (QUDO_MLDSA_keypair_internal(sig, pk, sk, seed) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Deterministic keypair generation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    printf("   pk=%zu bytes, sk=%zu bytes, seed=%d bytes\n", pk_len, sk_len, MLDSA_SEEDBYTES);

    printf("2. Exporting as SEED_PRIV DER (seed||sk)...\n");
    size_t input_len = MLDSA_SEEDBYTES + sk_len;
    uint8_t *seed_sk = malloc(input_len);
    if (!seed_sk) {
        printf("ERROR: Memory allocation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        return TEST_FAILED;
    }
    memcpy(seed_sk, seed, MLDSA_SEEDBYTES);
    memcpy(seed_sk + MLDSA_SEEDBYTES, sk, sk_len);

    uint8_t der_buffer[16384];
    size_t der_len = sizeof(der_buffer);
    if (QUDO_MLDSA_export_private_key_der_format(seed_sk, input_len, der_buffer, &der_len,
                                                 QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: SEED_PRIV DER export failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   SEED_PRIV DER size: %zu bytes\n", der_len);

    printf("3. Importing via basic import (should extract sk)...\n");
    uint8_t sk_imported[8192];
    size_t sk_imported_len = sizeof(sk_imported);
    if (QUDO_MLDSA_import_private_key_der(der_buffer, der_len, sk_imported, &sk_imported_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Basic DER import failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   Imported sk size: %zu bytes (expected %zu)\n", sk_imported_len, sk_len);

    if (sk_imported_len != sk_len || memcmp(sk, sk_imported, sk_len) != 0) {
        printf("ERROR: Imported sk does not match original!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   OK: sk matches\n");

    printf("4. Importing via format-aware import (should regenerate pk)...\n");
    uint8_t sk_fmt[8192], pk_regen[4096];
    size_t sk_fmt_len = sizeof(sk_fmt);
    size_t pk_regen_len = sizeof(pk_regen);
    if (QUDO_MLDSA_import_private_key_der_format(der_buffer, der_len, sk_fmt, &sk_fmt_len,
                                                 pk_regen, &pk_regen_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Format-aware DER import failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   Imported sk: %zu bytes, regenerated pk: %zu bytes\n", sk_fmt_len, pk_regen_len);

    if (sk_fmt_len != sk_len || memcmp(sk, sk_fmt, sk_len) != 0) {
        printf("ERROR: Format-imported sk does not match!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   OK: sk matches\n");

    if (pk_regen_len != pk_len || memcmp(pk, pk_regen, pk_len) != 0) {
        printf("ERROR: Regenerated pk does not match original!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   OK: pk regenerated correctly from seed\n");

    printf("5. Sign with imported sk, verify with regenerated pk...\n");
    const char *message = "SEED_PRIV round-trip verification test";
    uint8_t signature[8192];
    size_t sig_len = sizeof(signature);

    if (QUDO_MLDSA_sign(sig, signature, &sig_len, (const uint8_t *)message, strlen(message), sk_imported) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Signature generation failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }

    if (QUDO_MLDSA_verify(sig, signature, sig_len, (const uint8_t *)message, strlen(message), pk_regen) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Signature verification failed with regenerated pk!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   OK: sign/verify successful\n");

    printf("6. Testing PEM round-trip...\n");
    char pem_buffer[32768];
    size_t pem_len = sizeof(pem_buffer);
    if (QUDO_MLDSA_export_private_key_pem_format(seed_sk, input_len, pem_buffer, &pem_len,
                                                 QUDO_MLDSA_PKCS8_FORMAT_SEED_PRIV) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: SEED_PRIV PEM export failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }

    uint8_t sk_pem[8192], pk_pem[4096];
    size_t sk_pem_len = sizeof(sk_pem);
    size_t pk_pem_len = sizeof(pk_pem);
    if (QUDO_MLDSA_import_private_key_pem_format(pem_buffer, sk_pem, &sk_pem_len,
                                                 pk_pem, &pk_pem_len) != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: SEED_PRIV PEM import failed\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }

    if (sk_pem_len != sk_len || memcmp(sk, sk_pem, sk_len) != 0 ||
        pk_pem_len != pk_len || memcmp(pk, pk_pem, pk_len) != 0) {
        printf("ERROR: PEM round-trip key mismatch!\n");
        QUDO_MLDSA_free(sig);
        free(pk);
        free(sk);
        free(seed_sk);
        return TEST_FAILED;
    }
    printf("   OK: PEM round-trip successful\n");

    QUDO_MLDSA_free(sig);
    free(pk);
    free(sk);
    free(seed_sk);
    return TEST_PASSED;
}

int main(void) {
    int failed = 0;

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  ML-DSA DER/PEM Serialization Test Suite                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    if (QUDO_MLDSA_init() != QUDO_MLDSA_SUCCESS) {
        printf("ERROR: Failed to initialize library\n");
        return 1;
    }

    const char *variants[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    for (int i = 0; i < 3; i++) {
        printf("\n");
        printf("═══════════════════════════════════════════════════════════\n");
        printf("  Testing %s\n", variants[i]);
        printf("═══════════════════════════════════════════════════════════\n");

        if (test_public_key_der_pem(variants[i]) != TEST_PASSED) {
            printf("\n❌ %s public key test FAILED\n", variants[i]);
            failed++;
        } else {
            printf("\n✓ %s public key test PASSED\n", variants[i]);
        }

        if (test_private_key_der_pem(variants[i]) != TEST_PASSED) {
            printf("\n❌ %s private key test FAILED\n", variants[i]);
            failed++;
        } else {
            printf("\n✓ %s private key test PASSED\n", variants[i]);
        }

        if (test_seed_priv_der(variants[i]) != TEST_PASSED) {
            printf("\n❌ %s SEED_PRIV test FAILED\n", variants[i]);
            failed++;
        } else {
            printf("\n✓ %s SEED_PRIV test PASSED\n", variants[i]);
        }
    }

    QUDO_MLDSA_cleanup();

    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    if (failed == 0) {
        printf("  ✅ All tests PASSED!\n");
        printf("═══════════════════════════════════════════════════════════\n");
        return 0;
    } else {
        printf("  ❌ %d test(s) FAILED\n", failed);
        printf("═══════════════════════════════════════════════════════════\n");
        return 1;
    }
}
