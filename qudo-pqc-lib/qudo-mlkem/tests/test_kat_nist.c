/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/crypto.h>

#include "../include/mlkem_wrapper.h"
#include "nist_drbg.h"

void randombytes(uint8_t *out, size_t outlen) {
    nist_drbg_generate(out, outlen);
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s = ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static int run_kat(const char *alg_name, int num_tests) {
    QUDO_KEM *kem = QUDO_KEM_new(alg_name);
    if (!kem) {
        fprintf(stderr, "ERROR: Failed to create KEM for %s\n", alg_name);
        return -1;
    }

    printf("# %s\n\n", alg_name);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_encaps = malloc(kem->length_shared_secret);
    uint8_t *ss_decaps = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss_encaps || !ss_decaps) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        goto cleanup;
    }

    for (int count = 0; count < num_tests; count++) {

        uint8_t entropy[48];
        for (int i = 0; i < 48; i++) {
            entropy[i] = i;
        }

        if (count > 0) {
            nist_drbg_generate(entropy, 48);
        }

        printf("count = %d\n", count);
        print_hex("seed", entropy, 48);

        nist_drbg_init(entropy, NULL);

        if (kem->keypair(pk, sk) != QUDO_KEM_SUCCESS) {
            fprintf(stderr, "ERROR: Keypair generation failed\n");
            goto cleanup;
        }

        print_hex("pk", pk, kem->length_public_key);
        print_hex("sk", sk, kem->length_secret_key);

        if (kem->encaps(ct, ss_encaps, pk) != QUDO_KEM_SUCCESS) {
            fprintf(stderr, "ERROR: Encapsulation failed\n");
            goto cleanup;
        }

        print_hex("ct", ct, kem->length_ciphertext);
        print_hex("ss", ss_encaps, kem->length_shared_secret);

        if (kem->decaps(ss_decaps, ct, sk) != QUDO_KEM_SUCCESS) {
            fprintf(stderr, "ERROR: Decapsulation failed\n");
            goto cleanup;
        }

        if (memcmp(ss_encaps, ss_decaps, kem->length_shared_secret) != 0) {
            fprintf(stderr, "ERROR: Shared secrets don't match!\n");
            goto cleanup;
        }

        if (count < num_tests - 1) {
            printf("\n");
        }
    }

    printf("\n");

    free(pk);
    free(sk);
    free(ct);
    free(ss_encaps);
    free(ss_decaps);
    QUDO_KEM_free(kem);

    return 0;

cleanup:
    free(pk);
    free(sk);
    free(ct);
    free(ss_encaps);
    free(ss_decaps);
    QUDO_KEM_free(kem);
    return -1;
}

int main(int argc, char **argv) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <algorithm> [num_tests]\n", argv[0]);
        fprintf(stderr, "  algorithm: ML-KEM-512, ML-KEM-768, ML-KEM-1024\n");
        fprintf(stderr, "  num_tests: number of test vectors to generate (default: 1)\n");
        return 1;
    }

    const char *alg_name = argv[1];
    int num_tests = (argc > 2) ? atoi(argv[2]) : 1;

    if (num_tests < 1 || num_tests > 100) {
        fprintf(stderr, "ERROR: num_tests must be between 1 and 100\n");
        return 1;
    }

    if (strcmp(alg_name, QUDO_KEM_alg_mlkem_512) != 0 &&
        strcmp(alg_name, QUDO_KEM_alg_mlkem_768) != 0 &&
        strcmp(alg_name, QUDO_KEM_alg_mlkem_1024) != 0) {
        fprintf(stderr, "ERROR: Unknown algorithm: %s\n", alg_name);
        fprintf(stderr, "Valid options: ML-KEM-512, ML-KEM-768, ML-KEM-1024\n");
        return 1;
    }

    uint8_t initial_entropy[48];
    for (int i = 0; i < 48; i++) {
        initial_entropy[i] = i;
    }
    nist_drbg_init(initial_entropy, NULL);

    int ret = run_kat(alg_name, num_tests);
    OPENSSL_cleanup();
    return ret;
}
