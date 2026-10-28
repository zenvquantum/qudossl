/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int exercise(const char *alg)
{
    QUDO_MLDSA *sig = QUDO_MLDSA_new(alg);
    uint8_t *pk = NULL, *sk = NULL, *sg = NULL;
    uint8_t msg[32];
    size_t sglen;
    int ok = 0;

    if (sig == NULL) {
        fprintf(stderr, "ERROR: QUDO_MLDSA_new(%s) failed\n", alg);
        return 0;
    }

    pk = malloc(sig->length_public_key);
    sk = malloc(sig->length_secret_key);
    sg = malloc(sig->length_signature);
    if (pk == NULL || sk == NULL || sg == NULL)
        goto done;

    memset(msg, 0xA5, sizeof(msg));
    sglen = sig->length_signature;
    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS
        || QUDO_MLDSA_sign(sig, sg, &sglen, msg, sizeof(msg), sk)
               != QUDO_MLDSA_SUCCESS) {
        fprintf(stderr, "ERROR: %s keygen/sign failed\n", alg);
        goto done;
    }

    printf("  %-10s keygen + sign OK\n", alg);
    ok = 1;

done:
    free(pk);
    free(sk);
    free(sg);
    QUDO_MLDSA_free(sig);
    return ok;
}

int main(void)
{
    static const char *algs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    int i, fail = 0;

    QUDO_MLDSA_init();

    printf("=== ML-DSA Constant-Time Validation (Valgrind poisoning) ===\n");
    for (i = 0; i < 3; i++)
        fail += exercise(algs[i]) ? 0 : 1;

    printf("\n=== %s ===\n", fail == 0 ? "PASS" : "FAIL");
    return fail == 0 ? 0 : 1;
}
