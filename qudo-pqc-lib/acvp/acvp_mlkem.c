/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "acvp_common.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MLKEM_D_BYTES 32
#define MLKEM_Z_BYTES 32
#define MLKEM_M_BYTES 32

static const char *level_to_alg(int level)
{
    switch (level) {
    case 512:  return QUDO_KEM_alg_mlkem_512;
    case 768:  return QUDO_KEM_alg_mlkem_768;
    case 1024: return QUDO_KEM_alg_mlkem_1024;
    default:   return NULL;
    }
}

static void do_keygen(int argc, char **argv)
{
    int level = 0;
    uint8_t d[MLKEM_D_BYTES];
    uint8_t z[MLKEM_Z_BYTES];
    uint8_t seed[QUDO_KEM_SEED_BYTES];
    int have_d = 0, have_z = 0;
    int i;
    QUDO_KEM *kem;
    uint8_t *pk = NULL, *sk = NULL;
    QUDO_KEM_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg(argv[i], "d", d, MLKEM_D_BYTES) == 0) {
            have_d = 1;
            continue;
        }
        if (acvp_parse_hex_arg(argv[i], "z", z, MLKEM_Z_BYTES) == 0) {
            have_z = 1;
            continue;
        }
    }

    if (level == 0 || !have_d || !have_z)
        acvp_fatal("keyGen: requires level=INT d=HEX z=HEX");

    kem = QUDO_KEM_new(level_to_alg(level));
    if (kem == NULL)
        acvp_fatal("keyGen: unsupported level %d", level);

    memcpy(seed, d, MLKEM_D_BYTES);
    memcpy(seed + MLKEM_D_BYTES, z, MLKEM_Z_BYTES);

    pk = (uint8_t *)malloc(kem->length_public_key);
    sk = (uint8_t *)malloc(kem->length_secret_key);
    if (pk == NULL || sk == NULL)
        acvp_fatal("keyGen: allocation failed");

    rc = QUDO_KEM_keypair_from_seed(kem, pk, sk, seed);
    if (rc != QUDO_KEM_SUCCESS)
        acvp_fatal("keyGen: QUDO_KEM_keypair_from_seed failed (%d)", rc);

    acvp_print_hex("ek", pk, kem->length_public_key);
    acvp_print_hex("dk", sk, kem->length_secret_key);

    free(pk);
    free(sk);
    QUDO_KEM_free(kem);
}

static void do_encapsulation(int argc, char **argv)
{
    int level = 0;
    uint8_t m[MLKEM_M_BYTES];
    uint8_t *ek = NULL;
    size_t ek_len = 0;
    int have_m = 0;
    int i;
    QUDO_KEM *kem;
    uint8_t *ct = NULL, *ss = NULL;
    QUDO_KEM_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg(argv[i], "m", m, MLKEM_M_BYTES) == 0) {
            have_m = 1;
            continue;
        }
        if (acvp_parse_hex_arg_alloc(argv[i], "ek", &ek, &ek_len) == 0)
            continue;
    }

    if (level == 0 || !have_m || ek == NULL)
        acvp_fatal("encapsulation: requires level=INT ek=HEX m=HEX");

    kem = QUDO_KEM_new(level_to_alg(level));
    if (kem == NULL)
        acvp_fatal("encapsulation: unsupported level %d", level);

    if (ek_len != kem->length_public_key)
        acvp_fatal("encapsulation: ek length %zu != expected %zu",
                   ek_len, kem->length_public_key);

    ct = (uint8_t *)malloc(kem->length_ciphertext);
    ss = (uint8_t *)malloc(kem->length_shared_secret);
    if (ct == NULL || ss == NULL)
        acvp_fatal("encapsulation: allocation failed");

    rc = QUDO_KEM_encaps_derand(kem, ct, ss, ek, m);
    if (rc != QUDO_KEM_SUCCESS)
        acvp_fatal("encapsulation: QUDO_KEM_encaps_derand failed (%d)", rc);

    acvp_print_hex("c", ct, kem->length_ciphertext);
    acvp_print_hex("k", ss, kem->length_shared_secret);

    free(ek);
    free(ct);
    free(ss);
    QUDO_KEM_free(kem);
}

static void do_decapsulation(int argc, char **argv)
{
    int level = 0;
    uint8_t *dk = NULL, *c = NULL;
    size_t dk_len = 0, c_len = 0;
    int i;
    QUDO_KEM *kem;
    uint8_t *ss = NULL;
    QUDO_KEM_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "dk", &dk, &dk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "c", &c, &c_len) == 0)
            continue;
    }

    if (level == 0 || dk == NULL || c == NULL)
        acvp_fatal("decapsulation: requires level=INT dk=HEX c=HEX");

    kem = QUDO_KEM_new(level_to_alg(level));
    if (kem == NULL)
        acvp_fatal("decapsulation: unsupported level %d", level);

    if (dk_len != kem->length_secret_key)
        acvp_fatal("decapsulation: dk length %zu != expected %zu",
                   dk_len, kem->length_secret_key);
    if (c_len != kem->length_ciphertext)
        acvp_fatal("decapsulation: c length %zu != expected %zu",
                   c_len, kem->length_ciphertext);

    ss = (uint8_t *)malloc(kem->length_shared_secret);
    if (ss == NULL)
        acvp_fatal("decapsulation: allocation failed");

    rc = QUDO_KEM_decaps(kem, ss, c, dk);
    if (rc != QUDO_KEM_SUCCESS)
        acvp_fatal("decapsulation: QUDO_KEM_decaps failed (%d)", rc);

    acvp_print_hex("k", ss, kem->length_shared_secret);

    free(dk);
    free(c);
    free(ss);
    QUDO_KEM_free(kem);
}

static void do_encapsulation_key_check(int argc, char **argv)
{
    int level = 0;
    uint8_t *ek = NULL;
    size_t ek_len = 0;
    int i;
    QUDO_KEM *kem;
    QUDO_KEM_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "ek", &ek, &ek_len) == 0)
            continue;
    }

    if (level == 0 || ek == NULL)
        acvp_fatal("encapsulationKeyCheck: requires level=INT ek=HEX");

    kem = QUDO_KEM_new(level_to_alg(level));
    if (kem == NULL)
        acvp_fatal("encapsulationKeyCheck: unsupported level %d", level);

    rc = QUDO_KEM_check_pk(kem, ek, ek_len);
    acvp_print_bool("testPassed", rc == QUDO_KEM_SUCCESS);

    free(ek);
    QUDO_KEM_free(kem);
}

static void do_decapsulation_key_check(int argc, char **argv)
{
    int level = 0;
    uint8_t *dk = NULL;
    size_t dk_len = 0;
    int i;
    QUDO_KEM *kem;
    QUDO_KEM_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "dk", &dk, &dk_len) == 0)
            continue;
    }

    if (level == 0 || dk == NULL)
        acvp_fatal("decapsulationKeyCheck: requires level=INT dk=HEX");

    kem = QUDO_KEM_new(level_to_alg(level));
    if (kem == NULL)
        acvp_fatal("decapsulationKeyCheck: unsupported level %d", level);

    rc = QUDO_KEM_check_sk(kem, dk, dk_len);
    acvp_print_bool("testPassed", rc == QUDO_KEM_SUCCESS);

    free(dk);
    QUDO_KEM_free(kem);
}

static void usage(void)
{
    fprintf(stderr,
        "Usage: qudo_acvp_mlkem <mode> [options...]\n"
        "\n"
        "Modes:\n"
        "  keyGen AFT level=INT d=HEX z=HEX\n"
        "    Generate keypair from seed (d||z)\n"
        "    Output: ek=HEX dk=HEX\n"
        "\n"
        "  encapDecap AFT encapsulation level=INT ek=HEX m=HEX\n"
        "    Deterministic encapsulation\n"
        "    Output: c=HEX k=HEX\n"
        "\n"
        "  encapDecap VAL decapsulation level=INT dk=HEX c=HEX\n"
        "    Decapsulation\n"
        "    Output: k=HEX\n"
    );
    exit(1);
}

static void run_one_op(int argc, char **argv)
{
    if (argc < 2)
        acvp_fatal("incomplete operation");

    if (strcmp(argv[0], "keyGen") == 0) {
        if (strcmp(argv[1], "AFT") != 0)
            acvp_fatal("keyGen: only AFT test type supported");
        do_keygen(argc - 2, argv + 2);
    }
    else if (strcmp(argv[0], "encapDecap") == 0) {
        if (argc < 3)
            acvp_fatal("encapDecap: incomplete operation");

        if (strcmp(argv[1], "AFT") == 0) {
            if (strcmp(argv[2], "encapsulation") == 0) {
                do_encapsulation(argc - 3, argv + 3);
            } else {
                acvp_fatal("encapDecap AFT: unknown function '%s'", argv[2]);
            }
        }
        else if (strcmp(argv[1], "VAL") == 0) {
            if (strcmp(argv[2], "decapsulation") == 0) {
                do_decapsulation(argc - 3, argv + 3);
            } else if (strcmp(argv[2], "encapsulationKeyCheck") == 0) {
                do_encapsulation_key_check(argc - 3, argv + 3);
            } else if (strcmp(argv[2], "decapsulationKeyCheck") == 0) {
                do_decapsulation_key_check(argc - 3, argv + 3);
            } else {
                acvp_fatal("encapDecap VAL: unknown function '%s'", argv[2]);
            }
        }
        else {
            acvp_fatal("encapDecap: unknown test type '%s'", argv[1]);
        }
    }
    else {
        acvp_fatal("Unknown mode '%s'", argv[0]);
    }
}

static void run_batch(void)
{
    char *argv[32];
    char *line;

    acvp_batch_active = 1;
    while ((line = acvp_read_line()) != NULL) {
        int argc = acvp_tokenize(line, argv, 32);
        if (argc > 0) {
            if (setjmp(acvp_batch_jmp) == 0)
                run_one_op(argc, argv);
        }
        printf("=END=\n");
        fflush(stdout);
        free(line);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        usage();

    if (!qudo_pqc_init(NULL))
        acvp_fatal("qudo_pqc_init failed");

    if (strcmp(argv[1], "--batch") == 0) {
        run_batch();
        return 0;
    }

    run_one_op(argc - 1, argv + 1);
    return 0;
}
