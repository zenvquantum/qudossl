/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "acvp_common.h"
#include "slhdsa_wrapper.h"
#include "qudo_pqc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 32

typedef struct {
    const char *key;
    const char *value;
} arg_pair_t;

static arg_pair_t g_args[MAX_ARGS];
static int g_nargs = 0;
static const char *g_command = NULL;

static const char *find_arg(const char *key)
{
    int i;
    for (i = 0; i < g_nargs; i++) {
        if (strcmp(g_args[i].key, key) == 0)
            return g_args[i].value;
    }
    return NULL;
}

static void parse_flags(int argc, char **argv)
{
    int i;
    g_nargs = 0;
    g_command = NULL;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && i + 1 < argc) {
            if (g_nargs >= MAX_ARGS)
                acvp_fatal("Too many arguments (max %d)", MAX_ARGS);
            g_args[g_nargs].key = argv[i] + 1;
            g_args[g_nargs].value = argv[i + 1];
            g_nargs++;
            i++;
        } else {
            g_command = argv[i];
        }
    }
}

static size_t get_n(const QUDO_SLHDSA *sig)
{
    return sig->length_public_key / 2;
}

static uint8_t *get_hex_arg(const char *key, size_t *out_len)
{
    const char *val = find_arg(key);
    uint8_t *buf = NULL;
    size_t len = 0;

    if (val == NULL) {
        *out_len = 0;
        return NULL;
    }

    if (acvp_hex_decode_alloc(val, &buf, &len) != 0) {
        acvp_fatal("Invalid hex for -%s", key);
    }

    *out_len = len;
    return buf;
}

static uint8_t *get_hex_arg_exact(const char *key, size_t expected_len)
{
    size_t len;
    uint8_t *buf = get_hex_arg(key, &len);

    if (buf == NULL)
        acvp_fatal("Missing required argument -%s", key);
    if (len != expected_len)
        acvp_fatal("-%s: expected %zu bytes, got %zu", key, expected_len, len);

    return buf;
}

static void do_keygen(const QUDO_SLHDSA *sig)
{
    size_t n = get_n(sig);
    uint8_t *sk_seed, *sk_prf, *pk_seed;
    uint8_t *pk = NULL, *sk = NULL;
    QUDO_SLHDSA_status_t rc;

    sk_seed = get_hex_arg_exact("skSeed", n);
    sk_prf  = get_hex_arg_exact("skPrf", n);
    pk_seed = get_hex_arg_exact("pkSeed", n);

    pk = (uint8_t *)malloc(sig->length_public_key);
    sk = (uint8_t *)malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL)
        acvp_fatal("keyGen: allocation failed");

    rc = QUDO_SLHDSA_keypair_internal(sig, pk, sk, sk_seed, sk_prf, pk_seed);
    if (rc != QUDO_SLHDSA_SUCCESS)
        acvp_fatal("keyGen: QUDO_SLHDSA_keypair_internal failed (%d)", rc);

    acvp_print_hex("pk", pk, sig->length_public_key);
    acvp_print_hex("sk", sk, sig->length_secret_key);

    free(sk_seed);
    free(sk_prf);
    free(pk_seed);
    free(pk);
    free(sk);
}

static void do_siggen(const QUDO_SLHDSA *sig)
{
    size_t n = get_n(sig);
    uint8_t *msg = NULL, *sk = NULL, *ctx = NULL, *addrnd = NULL;
    size_t msg_len = 0, sk_len = 0, ctx_len = 0, addrnd_len = 0;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    const char *det_str;
    const char *hash_alg;
    int deterministic = 0;
    QUDO_SLHDSA_status_t rc;

    msg = get_hex_arg("message", &msg_len);
    if (msg == NULL)
        acvp_fatal("sigGen: missing -message");

    sk = get_hex_arg("sk", &sk_len);
    if (sk == NULL)
        acvp_fatal("sigGen: missing -sk");
    if (sk_len != sig->length_secret_key)
        acvp_fatal("sigGen: sk length %zu != expected %zu",
                   sk_len, sig->length_secret_key);

    ctx = get_hex_arg("context", &ctx_len);
    addrnd = get_hex_arg("additionalRandomness", &addrnd_len);

    det_str = find_arg("deterministic");
    if (det_str != NULL && strcmp(det_str, "1") == 0)
        deterministic = 1;

    if (deterministic && addrnd != NULL) {
        free(addrnd);
        addrnd = NULL;
    }

    if (addrnd != NULL && addrnd_len != n)
        acvp_fatal("sigGen: additionalRandomness must be %zu bytes, got %zu",
                   n, addrnd_len);

    signature = (uint8_t *)malloc(sig->length_signature);
    if (signature == NULL)
        acvp_fatal("sigGen: allocation failed");
    signature_len = sig->length_signature;

    hash_alg = find_arg("hashAlg");
    if (hash_alg != NULL) {
        rc = QUDO_SLHDSA_sign_pre_hash(sig, signature, &signature_len,
                                        msg, msg_len, ctx, ctx_len,
                                        hash_alg, addrnd, sk);
    } else if (find_arg("signatureInterface") != NULL &&
               strcmp(find_arg("signatureInterface"), "internal") == 0) {
        rc = QUDO_SLHDSA_sign_internal(sig, signature, &signature_len,
                                        msg, msg_len, addrnd, sk);
    } else {
        rc = QUDO_SLHDSA_sign_ex(sig, signature, &signature_len,
                                  msg, msg_len, ctx, ctx_len,
                                  addrnd, sk);
    }

    if (rc != QUDO_SLHDSA_SUCCESS)
        acvp_fatal("sigGen: sign failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(msg);
    free(sk);
    free(ctx);
    free(addrnd);
    free(signature);
}

static void do_sigver(const QUDO_SLHDSA *sig)
{
    uint8_t *msg = NULL, *pk = NULL, *ctx = NULL, *sigbuf = NULL;
    size_t msg_len = 0, pk_len = 0, ctx_len = 0, sig_len = 0;
    const char *hash_alg;
    QUDO_SLHDSA_status_t rc;

    msg = get_hex_arg("message", &msg_len);
    if (msg == NULL)
        acvp_fatal("sigVer: missing -message");

    pk = get_hex_arg("pk", &pk_len);
    if (pk == NULL)
        acvp_fatal("sigVer: missing -pk");
    if (pk_len != sig->length_public_key)
        acvp_fatal("sigVer: pk length %zu != expected %zu",
                   pk_len, sig->length_public_key);

    sigbuf = get_hex_arg("signature", &sig_len);
    if (sigbuf == NULL)
        acvp_fatal("sigVer: missing -signature");

    ctx = get_hex_arg("context", &ctx_len);

    hash_alg = find_arg("hashAlg");
    if (hash_alg != NULL) {
        rc = QUDO_SLHDSA_verify_pre_hash(sig, msg, msg_len,
                                          sigbuf, sig_len,
                                          ctx, ctx_len, hash_alg, pk);
    } else if (find_arg("signatureInterface") != NULL &&
               strcmp(find_arg("signatureInterface"), "internal") == 0) {
        rc = QUDO_SLHDSA_verify_internal(sig, msg, msg_len,
                                          sigbuf, sig_len, pk);
    } else if (ctx != NULL && ctx_len > 0) {
        rc = QUDO_SLHDSA_verify_with_ctx_str(sig, msg, msg_len,
                                              sigbuf, sig_len,
                                              ctx, ctx_len, pk);
    } else {
        rc = QUDO_SLHDSA_verify(sig, msg, msg_len, sigbuf, sig_len, pk);
    }

    acvp_print_bool("testPassed", rc == QUDO_SLHDSA_SUCCESS);

    free(msg);
    free(pk);
    free(ctx);
    free(sigbuf);
}

static void usage(void)
{
    fprintf(stderr,
        "Usage: qudo_acvp_slhdsa -parameterSet NAME [options...] <command>\n"
        "\n"
        "Commands:\n"
        "  keyGen   -skSeed HEX -skPrf HEX -pkSeed HEX\n"
        "  sigGen   -message HEX -sk HEX [-context HEX] [-deterministic 1] [-additionalRandomness HEX]\n"
        "  sigVer   -message HEX -signature HEX -pk HEX [-context HEX]\n"
        "\n"
        "Parameter sets: SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f, ..., SLH-DSA-SHAKE-256f\n"
    );
    exit(1);
}

static void run_one_op(int argc, char **argv)
{
    const char *param_set;
    QUDO_SLHDSA *sig;

    parse_flags(argc, argv);

    if (g_command == NULL)
        acvp_fatal("No command specified (keyGen, sigGen, sigVer)");

    param_set = find_arg("parameterSet");
    if (param_set == NULL)
        acvp_fatal("Missing -parameterSet argument");

    sig = QUDO_SLHDSA_new(param_set);
    if (sig == NULL)
        acvp_fatal("Unsupported parameter set: %s", param_set);

    if (strcmp(g_command, "keyGen") == 0)
        do_keygen(sig);
    else if (strcmp(g_command, "sigGen") == 0)
        do_siggen(sig);
    else if (strcmp(g_command, "sigVer") == 0)
        do_sigver(sig);
    else
        acvp_fatal("Unknown command '%s'", g_command);

    QUDO_SLHDSA_free(sig);
}

static void run_batch(void)
{
    char *toks[31];
    char *argv[32];
    char *line;

    acvp_batch_active = 1;
    while ((line = acvp_read_line()) != NULL) {
        int ntok = acvp_tokenize(line, toks, 31);
        if (ntok > 0) {
            int i;
            argv[0] = (char *)"acvp";
            for (i = 0; i < ntok; i++)
                argv[i + 1] = toks[i];
            if (setjmp(acvp_batch_jmp) == 0)
                run_one_op(ntok + 1, argv);
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

    run_one_op(argc, argv);
    return 0;
}
