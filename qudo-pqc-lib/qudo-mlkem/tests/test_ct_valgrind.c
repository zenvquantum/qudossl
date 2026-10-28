/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mlkem_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int exercise(const char *alg)
{
    QUDO_KEM *kem = QUDO_KEM_new(alg);
    uint8_t *pk = NULL, *sk = NULL, *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    int ok = 0;

    if (kem == NULL) {
        fprintf(stderr, "ERROR: QUDO_KEM_new(%s) failed\n", alg);
        return 0;
    }

    pk = malloc(kem->length_public_key);
    sk = malloc(kem->length_secret_key);
    ct = malloc(kem->length_ciphertext);
    ss1 = malloc(kem->length_shared_secret);
    ss2 = malloc(kem->length_shared_secret);
    if (pk == NULL || sk == NULL || ct == NULL || ss1 == NULL || ss2 == NULL)
        goto done;

    if (QUDO_KEM_keypair(kem, pk, sk) != QUDO_KEM_SUCCESS
        || QUDO_KEM_encaps(kem, ct, ss1, pk) != QUDO_KEM_SUCCESS
        || QUDO_KEM_decaps(kem, ss2, ct, sk) != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "ERROR: %s operate cycle failed\n", alg);
        goto done;
    }

    ct[0] ^= 0x01;
    if (QUDO_KEM_decaps(kem, ss2, ct, sk) != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "ERROR: %s implicit-rejection decaps failed\n", alg);
        goto done;
    }

    printf("  %-12s keygen + encaps + decaps + implicit-rejection OK\n", alg);
    ok = 1;

done:
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);
    QUDO_KEM_free(kem);
    return ok;
}

int main(void)
{
    static const char *algs[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    int i, fail = 0;

    QUDO_KEM_init();

    printf("=== ML-KEM Constant-Time Validation (Valgrind poisoning) ===\n");
    for (i = 0; i < 3; i++)
        fail += exercise(algs[i]) ? 0 : 1;

    printf("\n=== %s ===\n", fail == 0 ? "PASS" : "FAIL");
    return fail == 0 ? 0 : 1;
}
