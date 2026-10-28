/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "slhdsa_wrapper.h"
#include "test_fips_init.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENDURANCE_DEFAULT_REPEATS 100000
#define CHAIN_BYTES               64
#define MSG_BYTES                 32
#define SLHDSA_SEED_BYTES         16
#define SKIP_EXIT_CODE            77

static int g_verbose = 0;
static long g_repeats = ENDURANCE_DEFAULT_REPEATS;

static void secure_clear(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

static void chain_init(uint8_t chain[CHAIN_BYTES])
{
    int i;
    for (i = 0; i < CHAIN_BYTES; i++)
        chain[i] = (uint8_t)(i * 7 + 1);
}

static void chain_fold(uint8_t chain[CHAIN_BYTES], const uint8_t *data,
                       size_t len)
{
    size_t i;
    uint8_t c = chain[CHAIN_BYTES - 1];

    for (i = 0; i < len; i++) {
        size_t j = i & (CHAIN_BYTES - 1);
        c = (uint8_t)((c + data[i] + (uint8_t)i) * 131u + 0x9eu);
        chain[j] = (uint8_t)(chain[j] ^ c);
        c = (uint8_t)((c << 3) | (c >> 5));
    }
}

static void chain_print(const char *tag, const uint8_t chain[CHAIN_BYTES])
{
    int i;
    printf("  %-12s final-digest ", tag);
    for (i = 0; i < CHAIN_BYTES; i++)
        printf("%02x", chain[i]);
    printf("\n");
}

static void progress(const char *tag, long i)
{
    if (g_verbose && g_repeats >= 10 && (i % (g_repeats / 10)) == 0)
        printf("    %s %ld/%ld\n", tag, i, g_repeats);
}

static int run_mlkem(void)
{
    QUDO_KEM *kem = QUDO_KEM_new("ML-KEM-768");
    uint8_t *pk = NULL, *sk = NULL, *ct = NULL, *ss_e = NULL, *ss_d = NULL;
    uint8_t chain[CHAIN_BYTES];
    long i;
    int ok = 0;

    if (kem == NULL)
        return 0;

    pk = malloc(kem->length_public_key);
    sk = malloc(kem->length_secret_key);
    ct = malloc(kem->length_ciphertext);
    ss_e = malloc(kem->length_shared_secret);
    ss_d = malloc(kem->length_shared_secret);
    if (pk == NULL || sk == NULL || ct == NULL || ss_e == NULL || ss_d == NULL)
        goto done;

    chain_init(chain);
    for (i = 0; i < g_repeats; i++) {
        if (QUDO_KEM_keypair_from_seed(kem, pk, sk, chain) != QUDO_KEM_SUCCESS)
            goto done;
        if (QUDO_KEM_encaps_derand(kem, ct, ss_e, pk, chain)
            != QUDO_KEM_SUCCESS)
            goto done;
        if (QUDO_KEM_decaps(kem, ss_d, ct, sk) != QUDO_KEM_SUCCESS)
            goto done;
        if (memcmp(ss_e, ss_d, kem->length_shared_secret) != 0) {
            printf("  ML-KEM-768   shared-secret mismatch at iter %ld\n", i);
            goto done;
        }
        chain_fold(chain, ss_d, kem->length_shared_secret);
        chain_fold(chain, ct, kem->length_ciphertext);
        progress("ML-KEM-768", i);
    }
    chain_print("ML-KEM-768", chain);
    ok = 1;

done:
    if (sk != NULL)
        secure_clear(sk, kem->length_secret_key);
    free(pk);
    free(sk);
    free(ct);
    free(ss_e);
    free(ss_d);
    QUDO_KEM_free(kem);
    return ok;
}

static int run_mldsa(void)
{
    QUDO_MLDSA *sig = QUDO_MLDSA_new("ML-DSA-65");
    uint8_t *pk = NULL, *sk = NULL, *sg = NULL;
    uint8_t chain[CHAIN_BYTES];
    uint8_t msg[MSG_BYTES], rnd[MLDSA_RNDBYTES], saved;
    size_t sglen;
    long i;
    int ok = 0;

    if (sig == NULL)
        return 0;

    pk = malloc(sig->length_public_key);
    sk = malloc(sig->length_secret_key);
    sg = malloc(sig->length_signature);
    if (pk == NULL || sk == NULL || sg == NULL)
        goto done;

    chain_init(chain);
    for (i = 0; i < g_repeats; i++) {
        if (QUDO_MLDSA_keypair_internal(sig, pk, sk, chain)
            != QUDO_MLDSA_SUCCESS)
            goto done;
        memcpy(msg, chain, MSG_BYTES);
        memcpy(rnd, chain + MSG_BYTES, MLDSA_RNDBYTES);
        sglen = sig->length_signature;
        if (QUDO_MLDSA_sign_internal(sig, sg, &sglen, msg, MSG_BYTES, NULL, 0,
                                     rnd, sk, 0)
            != QUDO_MLDSA_SUCCESS)
            goto done;
        if (QUDO_MLDSA_verify_internal(sig, sg, sglen, msg, MSG_BYTES, NULL, 0,
                                       pk, 0)
            != QUDO_MLDSA_SUCCESS) {
            printf("  ML-DSA-65    verify failed at iter %ld\n", i);
            goto done;
        }
        saved = sg[0];
        sg[0] ^= 0x01;
        if (QUDO_MLDSA_verify_internal(sig, sg, sglen, msg, MSG_BYTES, NULL, 0,
                                       pk, 0)
            == QUDO_MLDSA_SUCCESS) {
            printf("  ML-DSA-65    tampered signature accepted at iter %ld\n",
                   i);
            goto done;
        }
        sg[0] = saved;
        chain_fold(chain, pk, sig->length_public_key);
        chain_fold(chain, sg, sglen);
        progress("ML-DSA-65", i);
    }
    chain_print("ML-DSA-65", chain);
    ok = 1;

done:
    if (sk != NULL)
        secure_clear(sk, sig->length_secret_key);
    free(pk);
    free(sk);
    free(sg);
    QUDO_MLDSA_free(sig);
    return ok;
}

static int run_slhdsa(void)
{
    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128f");
    uint8_t *pk = NULL, *sk = NULL, *sg = NULL;
    uint8_t chain[CHAIN_BYTES];
    uint8_t msg[MSG_BYTES], saved;
    size_t sglen;
    long i;
    int ok = 0;

    if (sig == NULL)
        return 0;

    pk = malloc(sig->length_public_key);
    sk = malloc(sig->length_secret_key);
    sg = malloc(sig->length_signature);
    if (pk == NULL || sk == NULL || sg == NULL)
        goto done;

    chain_init(chain);
    for (i = 0; i < g_repeats; i++) {
        if (QUDO_SLHDSA_keypair_internal(sig, pk, sk, chain,
                                         chain + SLHDSA_SEED_BYTES,
                                         chain + 2 * SLHDSA_SEED_BYTES)
            != QUDO_SLHDSA_SUCCESS)
            goto done;
        memcpy(msg, chain, MSG_BYTES);
        sglen = sig->length_signature;
        if (QUDO_SLHDSA_sign_ex(sig, sg, &sglen, msg, MSG_BYTES, NULL, 0,
                                chain + MSG_BYTES, sk)
            != QUDO_SLHDSA_SUCCESS)
            goto done;
        if (QUDO_SLHDSA_verify(sig, msg, MSG_BYTES, sg, sglen, pk)
            != QUDO_SLHDSA_SUCCESS) {
            printf("  SLH-DSA-128f verify failed at iter %ld\n", i);
            goto done;
        }
        saved = sg[0];
        sg[0] ^= 0x01;
        if (QUDO_SLHDSA_verify(sig, msg, MSG_BYTES, sg, sglen, pk)
            == QUDO_SLHDSA_SUCCESS) {
            printf("  SLH-DSA-128f tampered signature accepted at iter %ld\n",
                   i);
            goto done;
        }
        sg[0] = saved;
        chain_fold(chain, pk, sig->length_public_key);
        chain_fold(chain, sg, sglen);
        progress("SLH-DSA-128f", i);
    }
    chain_print("SLH-DSA-128f", chain);
    ok = 1;

done:
    if (sk != NULL)
        secure_clear(sk, sig->length_secret_key);
    free(pk);
    free(sk);
    free(sg);
    QUDO_SLHDSA_free(sig);
    return ok;
}

int main(int argc, char *argv[])
{
    const char *section = NULL;
    int run_all, fail = 0;
    int i;

    test_fips_init_set_args(&argc, argv);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "--num") == 0 && i + 1 < argc) {
            g_repeats = strtol(argv[++i], NULL, 10);
        } else if (strncmp(argv[i], "--num=", 6) == 0) {
            g_repeats = strtol(argv[i] + 6, NULL, 10);
        } else if (strncmp(argv[i], "--", 2) == 0) {
            section = argv[i] + 2;
        }
    }
    if (g_repeats <= 0)
        g_repeats = ENDURANCE_DEFAULT_REPEATS;

    if (getenv("QUDO_ENDURANCE") == NULL) {
        printf("SKIP: endurance test is opt-in; set QUDO_ENDURANCE=1 to run "
               "(e.g. QUDO_ENDURANCE=1 ctest -R pqc_endurance)\n");
        return SKIP_EXIT_CODE;
    }

    printf("=== QUDO PQC Endurance Tests (%ld iterations/family) ===\n",
           g_repeats);

    if (test_fips_init() == 0) {
        fprintf(stderr, "FAIL: qudo_pqc_init returned error\n");
        return 1;
    }

    run_all = (section == NULL);
    if (run_all || strcmp(section, "mlkem") == 0)
        fail += run_mlkem() ? 0 : 1;
    if (run_all || strcmp(section, "mldsa") == 0)
        fail += run_mldsa() ? 0 : 1;
    if (run_all || strcmp(section, "slhdsa") == 0)
        fail += run_slhdsa() ? 0 : 1;

    printf("\n=== Endurance: %s ===\n", fail == 0 ? "PASS" : "FAIL");
    return fail == 0 ? 0 : 1;
}
