/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "acvp_common.h"
#include "mldsa_wrapper.h"
#include "qudo_pqc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MSG_LENGTH  65536
#define MAX_CTX_LENGTH  255
#define MAX_SIG_LENGTH  4627

static const char *level_to_alg(int level)
{
    switch (level) {
    case 44: return QUDO_MLDSA_alg_ml_dsa_44;
    case 65: return QUDO_MLDSA_alg_ml_dsa_65;
    case 87: return QUDO_MLDSA_alg_ml_dsa_87;
    default: return NULL;
    }
}

static int parse_hash_alg(const char *name)
{
    if (name == NULL)
        return -1;
    if (strcmp(name, "SHA2-224") == 0)     return QUDO_PREHASH_SHA2_224;
    if (strcmp(name, "SHA2-256") == 0)     return QUDO_PREHASH_SHA2_256;
    if (strcmp(name, "SHA2-384") == 0)     return QUDO_PREHASH_SHA2_384;
    if (strcmp(name, "SHA2-512") == 0)     return QUDO_PREHASH_SHA2_512;
    if (strcmp(name, "SHA2-512/224") == 0) return QUDO_PREHASH_SHA2_512_224;
    if (strcmp(name, "SHA2-512/256") == 0) return QUDO_PREHASH_SHA2_512_256;
    if (strcmp(name, "SHA3-224") == 0)     return QUDO_PREHASH_SHA3_224;
    if (strcmp(name, "SHA3-256") == 0)     return QUDO_PREHASH_SHA3_256;
    if (strcmp(name, "SHA3-384") == 0)     return QUDO_PREHASH_SHA3_384;
    if (strcmp(name, "SHA3-512") == 0)     return QUDO_PREHASH_SHA3_512;
    if (strcmp(name, "SHAKE-128") == 0)    return QUDO_PREHASH_SHAKE_128;
    if (strcmp(name, "SHAKE-256") == 0)    return QUDO_PREHASH_SHAKE_256;
    return -1;
}

static size_t build_pure_prefix(const uint8_t *ctx, size_t ctx_len,
                                uint8_t *prefix)
{
    prefix[0] = 0x00;
    prefix[1] = (uint8_t)ctx_len;
    if (ctx_len > 0 && ctx != NULL)
        memcpy(prefix + 2, ctx, ctx_len);
    return 2 + ctx_len;
}

static void do_keygen(int argc, char **argv)
{
    int level = 0;
    uint8_t seed[MLDSA_SEEDBYTES];
    int have_seed = 0;
    int i;
    QUDO_MLDSA *sig;
    uint8_t *pk = NULL, *sk = NULL;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg(argv[i], "seed", seed, MLDSA_SEEDBYTES) == 0) {
            have_seed = 1;
            continue;
        }
    }

    if (level == 0 || !have_seed)
        acvp_fatal("keyGen: requires level=INT seed=HEX");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("keyGen: unsupported level %d", level);

    pk = (uint8_t *)malloc(sig->length_public_key);
    sk = (uint8_t *)malloc(sig->length_secret_key);
    if (pk == NULL || sk == NULL)
        acvp_fatal("keyGen: allocation failed");

    rc = QUDO_MLDSA_keypair_internal(sig, pk, sk, seed);
    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("keyGen: QUDO_MLDSA_keypair_internal failed (%d)", rc);

    acvp_print_hex("pk", pk, sig->length_public_key);
    acvp_print_hex("sk", sk, sig->length_secret_key);

    free(pk);
    free(sk);
    QUDO_MLDSA_free(sig);
}

static void do_siggen(int argc, char **argv)
{
    int level = 0;
    uint8_t *msg = NULL, *sk = NULL, *ctx = NULL;
    size_t msg_len = 0, sk_len = 0, ctx_len = 0;
    uint8_t rnd[MLDSA_RNDBYTES];
    int have_rnd = 0;
    int i;
    QUDO_MLDSA *sig;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint8_t prefix[2 + MAX_CTX_LENGTH];
    size_t prefix_len;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "sk", &sk, &sk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
        if (acvp_parse_hex_arg(argv[i], "rnd", rnd, MLDSA_RNDBYTES) == 0) {
            have_rnd = 1;
            continue;
        }
    }

    if (level == 0 || msg == NULL || sk == NULL || !have_rnd)
        acvp_fatal("sigGen: requires level=INT message=HEX sk=HEX rnd=HEX [context=HEX]");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigGen: unsupported level %d", level);

    prefix_len = build_pure_prefix(ctx, ctx_len, prefix);

    signature = (uint8_t *)malloc(sig->length_signature);
    if (signature == NULL)
        acvp_fatal("sigGen: allocation failed");

    rc = QUDO_MLDSA_sign_internal(sig, signature, &signature_len,
                                   msg, msg_len, prefix, prefix_len,
                                   rnd, sk, 0);
    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("sigGen: QUDO_MLDSA_sign_internal failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(msg);
    free(sk);
    free(ctx);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void do_siggen_deterministic(int argc, char **argv)
{
    int level = 0;
    uint8_t *msg = NULL, *sk = NULL, *ctx = NULL;
    size_t msg_len = 0, sk_len = 0, ctx_len = 0;
    uint8_t rnd_zero[MLDSA_RNDBYTES];
    int i;
    QUDO_MLDSA *sig;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint8_t prefix[2 + MAX_CTX_LENGTH];
    size_t prefix_len;
    QUDO_MLDSA_status_t rc;

    memset(rnd_zero, 0, sizeof(rnd_zero));

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "sk", &sk, &sk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
    }

    if (level == 0 || msg == NULL || sk == NULL)
        acvp_fatal("sigGenDeterministic: requires level=INT message=HEX sk=HEX [context=HEX]");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigGenDeterministic: unsupported level %d", level);

    prefix_len = build_pure_prefix(ctx, ctx_len, prefix);

    signature = (uint8_t *)malloc(sig->length_signature);
    if (signature == NULL)
        acvp_fatal("sigGenDeterministic: allocation failed");

    rc = QUDO_MLDSA_sign_internal(sig, signature, &signature_len,
                                   msg, msg_len, prefix, prefix_len,
                                   rnd_zero, sk, 0);
    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("sigGenDeterministic: QUDO_MLDSA_sign_internal failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(msg);
    free(sk);
    free(ctx);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void do_siggen_internal(int argc, char **argv)
{
    int level = 0, external_mu = 0;
    uint8_t *msg = NULL, *sk = NULL;
    size_t msg_len = 0, sk_len = 0;
    uint8_t rnd[MLDSA_RNDBYTES];
    int have_rnd = 0;
    int i;
    QUDO_MLDSA *sig;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "sk", &sk, &sk_len) == 0)
            continue;
        if (acvp_parse_int_arg(argv[i], "externalMu", &external_mu) == 0)
            continue;
        if (acvp_parse_hex_arg(argv[i], "rnd", rnd, MLDSA_RNDBYTES) == 0) {
            have_rnd = 1;
            continue;
        }
    }

    if (level == 0 || msg == NULL || sk == NULL || !have_rnd)
        acvp_fatal("sigGenInternal: requires level=INT message=HEX sk=HEX externalMu=0|1 rnd=HEX");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigGenInternal: unsupported level %d", level);

    signature = (uint8_t *)malloc(sig->length_signature);
    if (signature == NULL)
        acvp_fatal("sigGenInternal: allocation failed");

    if (external_mu) {
        rc = QUDO_MLDSA_sign_internal(sig, signature, &signature_len,
                                       msg, msg_len, NULL, 0,
                                       rnd, sk, 1);
    } else {
        rc = QUDO_MLDSA_sign_internal(sig, signature, &signature_len,
                                       msg, msg_len, NULL, 0,
                                       rnd, sk, 0);
    }

    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("sigGenInternal: QUDO_MLDSA_sign_internal failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(msg);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void do_siggen_internal_deterministic(int argc, char **argv)
{
    int level = 0, external_mu = 0;
    uint8_t *msg = NULL, *sk = NULL;
    size_t msg_len = 0, sk_len = 0;
    uint8_t rnd_zero[MLDSA_RNDBYTES];
    int i;
    QUDO_MLDSA *sig;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    QUDO_MLDSA_status_t rc;

    memset(rnd_zero, 0, sizeof(rnd_zero));

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "sk", &sk, &sk_len) == 0)
            continue;
        if (acvp_parse_int_arg(argv[i], "externalMu", &external_mu) == 0)
            continue;
    }

    if (level == 0 || msg == NULL || sk == NULL)
        acvp_fatal("sigGenInternalDeterministic: requires level=INT message=HEX sk=HEX externalMu=0|1");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigGenInternalDeterministic: unsupported level %d", level);

    signature = (uint8_t *)malloc(sig->length_signature);
    if (signature == NULL)
        acvp_fatal("sigGenInternalDeterministic: allocation failed");

    rc = QUDO_MLDSA_sign_internal(sig, signature, &signature_len,
                                   msg, msg_len, NULL, 0,
                                   rnd_zero, sk, external_mu);
    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("sigGenInternalDeterministic: failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(msg);
    free(sk);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void do_siggen_prehash(int argc, char **argv)
{
    int level = 0;
    uint8_t *ph = NULL, *sk = NULL, *ctx = NULL;
    size_t ph_len = 0, sk_len = 0, ctx_len = 0;
    uint8_t rnd[MLDSA_RNDBYTES];
    int have_rnd = 0;
    const char *hash_alg_str = NULL;
    int hash_alg;
    int i;
    QUDO_MLDSA *sig;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "ph", &ph, &ph_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "sk", &sk, &sk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
        if (acvp_parse_hex_arg(argv[i], "rnd", rnd, MLDSA_RNDBYTES) == 0) {
            have_rnd = 1;
            continue;
        }
        if (hash_alg_str == NULL)
            hash_alg_str = acvp_parse_str_arg(argv[i], "hashAlg");
    }

    if (level == 0 || ph == NULL || sk == NULL || !have_rnd || hash_alg_str == NULL)
        acvp_fatal("sigGenPreHash: requires level=INT ph=HEX sk=HEX rnd=HEX hashAlg=STRING [context=HEX]");

    hash_alg = parse_hash_alg(hash_alg_str);
    if (hash_alg < 0)
        acvp_fatal("sigGenPreHash: unknown hashAlg '%s'", hash_alg_str);

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigGenPreHash: unsupported level %d", level);

    signature = (uint8_t *)malloc(sig->length_signature);
    if (signature == NULL)
        acvp_fatal("sigGenPreHash: allocation failed");

    rc = QUDO_MLDSA_sign_pre_hash(sig, signature, &signature_len,
                                   ph, ph_len, ctx, ctx_len,
                                   rnd, sk, hash_alg);
    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("sigGenPreHash: failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(ph);
    free(sk);
    free(ctx);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void do_siggen_prehash_deterministic(int argc, char **argv)
{
    int level = 0;
    uint8_t *ph = NULL, *sk = NULL, *ctx = NULL;
    size_t ph_len = 0, sk_len = 0, ctx_len = 0;
    uint8_t rnd_zero[MLDSA_RNDBYTES];
    const char *hash_alg_str = NULL;
    int hash_alg;
    int i;
    QUDO_MLDSA *sig;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    QUDO_MLDSA_status_t rc;

    memset(rnd_zero, 0, sizeof(rnd_zero));

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "ph", &ph, &ph_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "sk", &sk, &sk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
        if (hash_alg_str == NULL)
            hash_alg_str = acvp_parse_str_arg(argv[i], "hashAlg");
    }

    if (level == 0 || ph == NULL || sk == NULL || hash_alg_str == NULL)
        acvp_fatal("sigGenPreHashDeterministic: requires level=INT ph=HEX sk=HEX hashAlg=STRING [context=HEX]");

    hash_alg = parse_hash_alg(hash_alg_str);
    if (hash_alg < 0)
        acvp_fatal("sigGenPreHashDeterministic: unknown hashAlg '%s'", hash_alg_str);

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigGenPreHashDeterministic: unsupported level %d", level);

    signature = (uint8_t *)malloc(sig->length_signature);
    if (signature == NULL)
        acvp_fatal("sigGenPreHashDeterministic: allocation failed");

    rc = QUDO_MLDSA_sign_pre_hash(sig, signature, &signature_len,
                                   ph, ph_len, ctx, ctx_len,
                                   rnd_zero, sk, hash_alg);
    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("sigGenPreHashDeterministic: failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(ph);
    free(sk);
    free(ctx);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void do_siggen_prehash_shake256(int argc, char **argv, int deterministic)
{
    int level = 0;
    uint8_t *msg = NULL, *sk = NULL, *ctx = NULL;
    size_t msg_len = 0, sk_len = 0, ctx_len = 0;
    uint8_t rnd[MLDSA_RNDBYTES];
    uint8_t rnd_zero[MLDSA_RNDBYTES];
    int have_rnd = 0;
    int i;
    QUDO_MLDSA *sig;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    QUDO_MLDSA_status_t rc;

    memset(rnd_zero, 0, sizeof(rnd_zero));

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "sk", &sk, &sk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
        if (!deterministic && acvp_parse_hex_arg(argv[i], "rnd", rnd, MLDSA_RNDBYTES) == 0) {
            have_rnd = 1;
            continue;
        }
    }

    if (level == 0 || msg == NULL || sk == NULL)
        acvp_fatal("sigGenPreHashShake256: requires level=INT message=HEX sk=HEX [context=HEX] [rnd=HEX]");
    if (!deterministic && !have_rnd)
        acvp_fatal("sigGenPreHashShake256: randomized mode requires rnd=HEX");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigGenPreHashShake256: unsupported level %d", level);

    {
        uint8_t ph[64];
        rc = QUDO_MLDSA_shake256(ph, sizeof(ph), msg, msg_len);
        if (rc != QUDO_MLDSA_SUCCESS)
            acvp_fatal("sigGenPreHashShake256: SHAKE-256 hash failed (%d)", rc);

        signature = (uint8_t *)malloc(sig->length_signature);
        if (signature == NULL)
            acvp_fatal("sigGenPreHashShake256: allocation failed");

        rc = QUDO_MLDSA_sign_pre_hash_internal(sig, signature, &signature_len,
                                                ph, sizeof(ph), ctx, ctx_len,
                                                deterministic ? rnd_zero : rnd,
                                                sk, QUDO_PREHASH_SHAKE_256);
    }

    if (rc != QUDO_MLDSA_SUCCESS)
        acvp_fatal("sigGenPreHashShake256: sign failed (%d)", rc);

    acvp_print_hex("signature", signature, signature_len);

    free(msg);
    free(sk);
    free(ctx);
    free(signature);
    QUDO_MLDSA_free(sig);
}

static void do_sigver(int argc, char **argv)
{
    int level = 0;
    uint8_t *msg = NULL, *pk = NULL, *ctx = NULL, *sigbuf = NULL;
    size_t msg_len = 0, pk_len = 0, ctx_len = 0, sig_len = 0;
    int i;
    QUDO_MLDSA *sig;
    uint8_t prefix[2 + MAX_CTX_LENGTH];
    size_t prefix_len;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "pk", &pk, &pk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "signature", &sigbuf, &sig_len) == 0)
            continue;
    }

    if (level == 0 || msg == NULL || pk == NULL || sigbuf == NULL)
        acvp_fatal("sigVer: requires level=INT message=HEX pk=HEX signature=HEX [context=HEX]");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigVer: unsupported level %d", level);

    prefix_len = build_pure_prefix(ctx, ctx_len, prefix);

    rc = QUDO_MLDSA_verify_internal(sig, sigbuf, sig_len,
                                     msg, msg_len, prefix, prefix_len,
                                     pk, 0);

    acvp_print_bool("testPassed", rc == QUDO_MLDSA_SUCCESS);

    free(msg);
    free(pk);
    free(ctx);
    free(sigbuf);
    QUDO_MLDSA_free(sig);
}

static void do_sigver_internal(int argc, char **argv)
{
    int level = 0, external_mu = 0;
    uint8_t *msg = NULL, *pk = NULL, *sigbuf = NULL;
    size_t msg_len = 0, pk_len = 0, sig_len = 0;
    int i;
    QUDO_MLDSA *sig;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "pk", &pk, &pk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "signature", &sigbuf, &sig_len) == 0)
            continue;
        if (acvp_parse_int_arg(argv[i], "externalMu", &external_mu) == 0)
            continue;
    }

    if (level == 0 || msg == NULL || pk == NULL || sigbuf == NULL)
        acvp_fatal("sigVerInternal: requires level=INT message=HEX pk=HEX signature=HEX externalMu=0|1");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigVerInternal: unsupported level %d", level);

    rc = QUDO_MLDSA_verify_internal(sig, sigbuf, sig_len,
                                     msg, msg_len, NULL, 0,
                                     pk, external_mu);

    acvp_print_bool("testPassed", rc == QUDO_MLDSA_SUCCESS);

    free(msg);
    free(pk);
    free(sigbuf);
    QUDO_MLDSA_free(sig);
}

static void do_sigver_prehash(int argc, char **argv)
{
    int level = 0;
    uint8_t *ph = NULL, *pk = NULL, *ctx = NULL, *sigbuf = NULL;
    size_t ph_len = 0, pk_len = 0, ctx_len = 0, sig_len = 0;
    const char *hash_alg_str = NULL;
    int hash_alg;
    int i;
    QUDO_MLDSA *sig;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "ph", &ph, &ph_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "pk", &pk, &pk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "signature", &sigbuf, &sig_len) == 0)
            continue;
        if (hash_alg_str == NULL)
            hash_alg_str = acvp_parse_str_arg(argv[i], "hashAlg");
    }

    if (level == 0 || ph == NULL || pk == NULL || sigbuf == NULL || hash_alg_str == NULL)
        acvp_fatal("sigVerPreHash: requires level=INT ph=HEX pk=HEX signature=HEX hashAlg=STRING [context=HEX]");

    hash_alg = parse_hash_alg(hash_alg_str);
    if (hash_alg < 0)
        acvp_fatal("sigVerPreHash: unknown hashAlg '%s'", hash_alg_str);

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigVerPreHash: unsupported level %d", level);

    rc = QUDO_MLDSA_verify_pre_hash(sig, sigbuf, sig_len,
                                     ph, ph_len, ctx, ctx_len,
                                     pk, hash_alg);

    acvp_print_bool("testPassed", rc == QUDO_MLDSA_SUCCESS);

    free(ph);
    free(pk);
    free(ctx);
    free(sigbuf);
    QUDO_MLDSA_free(sig);
}

static void do_sigver_prehash_shake256(int argc, char **argv)
{
    int level = 0;
    uint8_t *msg = NULL, *pk = NULL, *ctx = NULL, *sigbuf = NULL;
    size_t msg_len = 0, pk_len = 0, ctx_len = 0, sig_len = 0;
    int i;
    QUDO_MLDSA *sig;
    QUDO_MLDSA_status_t rc;

    for (i = 0; i < argc; i++) {
        if (acvp_parse_int_arg(argv[i], "level", &level) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "message", &msg, &msg_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "pk", &pk, &pk_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "context", &ctx, &ctx_len) == 0)
            continue;
        if (acvp_parse_hex_arg_alloc(argv[i], "signature", &sigbuf, &sig_len) == 0)
            continue;
    }

    if (level == 0 || msg == NULL || pk == NULL || sigbuf == NULL)
        acvp_fatal("sigVerPreHashShake256: requires level=INT message=HEX pk=HEX signature=HEX [context=HEX]");

    sig = QUDO_MLDSA_new(level_to_alg(level));
    if (sig == NULL)
        acvp_fatal("sigVerPreHashShake256: unsupported level %d", level);

    {
        uint8_t ph[64];
        rc = QUDO_MLDSA_shake256(ph, sizeof(ph), msg, msg_len);
        if (rc != QUDO_MLDSA_SUCCESS)
            acvp_fatal("sigVerPreHashShake256: SHAKE-256 hash failed (%d)", rc);

        rc = QUDO_MLDSA_verify_pre_hash_internal(sig, sigbuf, sig_len,
                                                   ph, sizeof(ph), ctx, ctx_len,
                                                   pk, QUDO_PREHASH_SHAKE_256);
    }

    acvp_print_bool("testPassed", rc == QUDO_MLDSA_SUCCESS);

    free(msg);
    free(pk);
    free(ctx);
    free(sigbuf);
    QUDO_MLDSA_free(sig);
}

static void usage(void)
{
    fprintf(stderr,
        "Usage: qudo_acvp_mldsa <mode> [options...]\n"
        "\n"
        "Modes:\n"
        "  keyGen                              level=INT seed=HEX\n"
        "  sigGen                              level=INT message=HEX sk=HEX context=HEX rnd=HEX\n"
        "  sigGenDeterministic                 level=INT message=HEX sk=HEX context=HEX\n"
        "  sigGenInternal                      level=INT message=HEX sk=HEX externalMu=0|1 rnd=HEX\n"
        "  sigGenInternalDeterministic         level=INT message=HEX sk=HEX externalMu=0|1\n"
        "  sigGenPreHash                       level=INT ph=HEX sk=HEX rnd=HEX hashAlg=STRING [context=HEX]\n"
        "  sigGenPreHashDeterministic          level=INT ph=HEX sk=HEX hashAlg=STRING [context=HEX]\n"
        "  sigGenPreHashShake256               level=INT message=HEX sk=HEX [context=HEX] rnd=HEX\n"
        "  sigGenPreHashShake256Deterministic  level=INT message=HEX sk=HEX [context=HEX]\n"
        "  sigVer                              level=INT message=HEX pk=HEX signature=HEX [context=HEX]\n"
        "  sigVerInternal                      level=INT message=HEX pk=HEX signature=HEX externalMu=0|1\n"
        "  sigVerPreHash                       level=INT ph=HEX pk=HEX signature=HEX hashAlg=STRING [context=HEX]\n"
        "  sigVerPreHashShake256               level=INT message=HEX pk=HEX signature=HEX [context=HEX]\n"
    );
    exit(1);
}

static void run_one_op(int argc, char **argv)
{
    const char *mode;

    if (argc < 1)
        acvp_fatal("empty operation");

    mode = argv[0];
    if (strcmp(mode, "keyGen") == 0)
        do_keygen(argc - 1, argv + 1);
    else if (strcmp(mode, "sigGen") == 0)
        do_siggen(argc - 1, argv + 1);
    else if (strcmp(mode, "sigGenDeterministic") == 0)
        do_siggen_deterministic(argc - 1, argv + 1);
    else if (strcmp(mode, "sigGenInternal") == 0)
        do_siggen_internal(argc - 1, argv + 1);
    else if (strcmp(mode, "sigGenInternalDeterministic") == 0)
        do_siggen_internal_deterministic(argc - 1, argv + 1);
    else if (strcmp(mode, "sigGenPreHash") == 0)
        do_siggen_prehash(argc - 1, argv + 1);
    else if (strcmp(mode, "sigGenPreHashDeterministic") == 0)
        do_siggen_prehash_deterministic(argc - 1, argv + 1);
    else if (strcmp(mode, "sigGenPreHashShake256") == 0)
        do_siggen_prehash_shake256(argc - 1, argv + 1, 0);
    else if (strcmp(mode, "sigGenPreHashShake256Deterministic") == 0)
        do_siggen_prehash_shake256(argc - 1, argv + 1, 1);
    else if (strcmp(mode, "sigVer") == 0)
        do_sigver(argc - 1, argv + 1);
    else if (strcmp(mode, "sigVerInternal") == 0)
        do_sigver_internal(argc - 1, argv + 1);
    else if (strcmp(mode, "sigVerPreHash") == 0)
        do_sigver_prehash(argc - 1, argv + 1);
    else if (strcmp(mode, "sigVerPreHashShake256") == 0)
        do_sigver_prehash_shake256(argc - 1, argv + 1);
    else
        acvp_fatal("Unknown mode '%s'", mode);
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
