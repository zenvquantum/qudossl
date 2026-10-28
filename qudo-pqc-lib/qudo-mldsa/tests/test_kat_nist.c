/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "../include/mldsa_wrapper.h"
#include "nist_drbg.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s = ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static unsigned char rnd_seed[48];
extern void randombytes(unsigned char *buf, unsigned long long len) {
    nist_drbg_generate(buf, len);
}

static int run_kat(const char *alg_name, int num_tests) {
    const QUDO_MLDSA *sig = QUDO_MLDSA_new(alg_name);
    if (!sig) {
        fprintf(stderr, "Failed to create SIG for %s\n", alg_name);
        return 1;
    }

    printf("# %s\n\n", alg_name);

    for (int i = 0; i < num_tests; i++) {

        for (int j = 0; j < 48; j++) rnd_seed[j] = i + j;
        nist_drbg_init(rnd_seed, NULL);

        uint8_t *pk = malloc(sig->length_public_key);
        uint8_t *sk = malloc(sig->length_secret_key);
        uint8_t *sm = malloc(sig->length_signature + 128);
        size_t smlen;
        uint8_t msg[33] = {0};
        for (int j = 0; j < 33; j++) msg[j] = i + j;

        printf("count = %d\n", i);
        print_hex("seed", rnd_seed, 48);

        sig->keypair(pk, sk);
        print_hex("pk", pk, sig->length_public_key);
        print_hex("sk", sk, sig->length_secret_key);

        sig->sign(sm, &smlen, msg, 33, sk);
        print_hex("msg", msg, 33);
        print_hex("sm", sm, smlen);
        printf("\n");

        free(pk);
        free(sk);
        free(sm);
    }

    QUDO_MLDSA_free((QUDO_MLDSA*)sig);
    return 0;
}

int main(int argc, char **argv) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <algorithm> <num_tests>\n", argv[0]);
        fprintf(stderr, "  algorithm: ML-DSA-44, ML-DSA-65, ML-DSA-87\n");
        return 1;
    }

    int ret = run_kat(argv[1], atoi(argv[2]));
    OPENSSL_cleanup();
    return ret;
}
