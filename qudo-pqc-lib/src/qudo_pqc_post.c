/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "fips/qudo_fips_ctrdrbg.h"
#include "fips/qudo_fips_hmac.h"
#include "fips/qudo_fips_sha2.h"
#include "qudo_pqc.h"
#include "qudo_pqc_platform.h"
#include "qudo_pqc_selftest.h"
#include <string.h>

static QUDO_ATOMIC_QUALIFIER int g_post_drbg_kat_passed = 0;
static QUDO_ATOMIC_QUALIFIER int g_post_integrity_passed = 0;

QUDO_PQC_API int qudo_pqc_post_drbg_kat_passed(void)
{
    return qudo_atomic_load(&g_post_drbg_kat_passed) ? 1 : 0;
}

QUDO_PQC_API int qudo_pqc_post_integrity_passed(void)
{
    return qudo_atomic_load(&g_post_integrity_passed) ? 1 : 0;
}

void qudo_pqc_post_mark_integrity_passed(void)
{
    qudo_atomic_store(&g_post_integrity_passed, 1);
}

void qudo_pqc_post_reset_status(void)
{
    qudo_atomic_store(&g_post_drbg_kat_passed, 0);
    qudo_atomic_store(&g_post_integrity_passed, 0);
}

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "slhdsa_wrapper.h"

#include "qudo_self_test_data.inc"

static int qudo_post_keygen_mlkem(qudo_st_ctx_t *st)
{
    size_t t;
    static const struct {
        const char *desc;
        int security_level;
        const unsigned char *seed;
        const unsigned char *expected_sk;
        size_t expected_sk_len;
    } tests[] = {
        {QUDO_ST_DESC_ML_KEM_512, 512, ml_kem_512_keygen_seed, ml_kem_512_sk,
         1632},
        {QUDO_ST_DESC_ML_KEM_768, 768, ml_kem_768_keygen_seed, ml_kem_768_sk,
         2400},
        {QUDO_ST_DESC_ML_KEM_1024, 1024, ml_kem_1024_keygen_seed,
         ml_kem_1024_sk, 3168},
    };

    for (t = 0; t < QUDO_NELEM(tests); t++) {
        QUDO_KEM *kem = NULL;
        uint8_t *pk = NULL, *sk = NULL;
        int ok = 0;

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_ASYM_KEYGEN, tests[t].desc);

        kem = QUDO_KEM_new(tests[t].security_level == 512   ? "ML-KEM-512"
                           : tests[t].security_level == 768 ? "ML-KEM-768"
                                                            : "ML-KEM-1024");
        if (kem == NULL)
            goto keygen_end;

        pk = (uint8_t *)qudo_malloc(kem->length_public_key);
        sk = (uint8_t *)qudo_malloc(kem->length_secret_key);
        if (pk == NULL || sk == NULL)
            goto keygen_end;

        if (QUDO_KEM_keypair_from_seed(kem, pk, sk, tests[t].seed)
            != QUDO_KEM_SUCCESS)
            goto keygen_end;

        qudo_st_corrupt(st, sk);

        if (qudo_memcmp_ct(sk, tests[t].expected_sk, tests[t].expected_sk_len)
            != 0)
            goto keygen_end;

        ok = 1;
    keygen_end:
        qudo_st_end(st, ok);
        if (sk != NULL) {
            qudo_cleanse(sk, kem ? kem->length_secret_key : 0);
            qudo_free(sk);
        }
        if (pk != NULL)
            qudo_free(pk);
        QUDO_KEM_free(kem);
        if (!ok)
            return 0;
    }
    return 1;
}

static int qudo_post_kem(qudo_st_ctx_t *st)
{
    size_t t;

    for (t = 0; t < QUDO_KAT_KEM_NUM; t++) {
        const QUDO_KAT_KEM *tv = &qudo_kat_kem_tests[t];
        QUDO_KEM *kem = NULL;
        uint8_t *pk = NULL;
        uint8_t *ct = NULL;
        uint8_t ss_enc[32], ss_dec[32], reject_dec[32];
        size_t ct_len;
        int encaps_ok = 0, decaps_ok = 0, reject_ok = 0;

        kem = QUDO_KEM_new(tv->security_level == 512   ? "ML-KEM-512"
                           : tv->security_level == 768 ? "ML-KEM-768"
                                                       : "ML-KEM-1024");
        if (kem == NULL)
            return 0;

        ct_len = kem->length_ciphertext;
        ct = (uint8_t *)qudo_malloc(ct_len);
        pk = (uint8_t *)qudo_malloc(kem->length_public_key);
        if (ct == NULL || pk == NULL) {
            qudo_free(ct);
            qudo_free(pk);
            QUDO_KEM_free(kem);
            return 0;
        }

        {
            if (tv->sk_len < kem->length_public_key + 64) {
                qudo_free(ct);
                qudo_free(pk);
                QUDO_KEM_free(kem);
                return 0;
            }
            size_t pk_offset = tv->sk_len - kem->length_public_key - 64;
            memcpy(pk, tv->sk + pk_offset, kem->length_public_key);
        }

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_KEM, tv->desc);

        if (QUDO_KEM_encaps_derand(kem, ct, ss_enc, pk, tv->encaps_rand)
            != QUDO_KEM_SUCCESS)
            goto encaps_end;

        qudo_st_corrupt(st, ss_enc);

        if (qudo_memcmp_ct(ss_enc, tv->expected_ss, 32) != 0)
            goto encaps_end;
        if (ct_len != tv->ct_len
            || qudo_memcmp_ct(ct, tv->expected_ct, tv->ct_len) != 0)
            goto encaps_end;

        encaps_ok = 1;
    encaps_end:
        qudo_st_end(st, encaps_ok);
        if (!encaps_ok) {
            qudo_cleanse(ss_enc, sizeof(ss_enc));
            qudo_free(ct);
            qudo_free(pk);
            QUDO_KEM_free(kem);
            return 0;
        }

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_KEM, tv->desc);

        if (QUDO_KEM_decaps(kem, ss_dec, ct, tv->sk) != QUDO_KEM_SUCCESS)
            goto decaps_end;

        qudo_st_corrupt(st, ss_dec);

        if (qudo_memcmp_ct(ss_enc, ss_dec, 32) != 0)
            goto decaps_end;

        decaps_ok = 1;
    decaps_end:
        qudo_st_end(st, decaps_ok);
        qudo_cleanse(ss_dec, sizeof(ss_dec));
        if (!decaps_ok) {
            qudo_cleanse(ss_enc, sizeof(ss_enc));
            qudo_free(ct);
            qudo_free(pk);
            QUDO_KEM_free(kem);
            return 0;
        }

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_KEM, tv->desc);
        {
            uint8_t *zero_ct = (uint8_t *)qudo_zalloc(ct_len);
            if (zero_ct == NULL)
                goto reject_end;

            if (QUDO_KEM_decaps(kem, reject_dec, zero_ct, tv->sk)
                != QUDO_KEM_SUCCESS) {
                qudo_free(zero_ct);
                goto reject_end;
            }
            qudo_free(zero_ct);

            qudo_st_corrupt(st, reject_dec);

            if (qudo_memcmp_ct(reject_dec, tv->reject_ss, 32) != 0)
                goto reject_end;
            if (qudo_memcmp_ct(reject_dec, ss_enc, 32) == 0)
                goto reject_end;

            reject_ok = 1;
        }
    reject_end:
        qudo_st_end(st, reject_ok);
        qudo_cleanse(ss_enc, sizeof(ss_enc));
        qudo_cleanse(reject_dec, sizeof(reject_dec));
        qudo_free(ct);
        qudo_free(pk);
        QUDO_KEM_free(kem);

        if (!reject_ok)
            return 0;
    }
    return 1;
}

static int qudo_post_keygen_mldsa(qudo_st_ctx_t *st)
{
    size_t t;

    for (t = 0; t < QUDO_KAT_SIGN_NUM; t++) {
        const QUDO_KAT_SIGN *tv = &qudo_kat_sign_tests[t];
        QUDO_MLDSA *sig = NULL;
        uint8_t *pk = NULL, *sk = NULL;
        int ok = 0;

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_ASYM_KEYGEN, tv->desc);

        sig = QUDO_MLDSA_new(tv->alg_name);
        if (sig == NULL)
            goto mldsa_keygen_end;

        pk = (uint8_t *)qudo_malloc(sig->length_public_key);
        sk = (uint8_t *)qudo_malloc(sig->length_secret_key);
        if (pk == NULL || sk == NULL)
            goto mldsa_keygen_end;

        if (QUDO_MLDSA_keypair_internal(sig, pk, sk, tv->keygen_seed)
            != QUDO_MLDSA_SUCCESS)
            goto mldsa_keygen_end;

        qudo_st_corrupt(st, sk);

        if (qudo_memcmp_ct(sk, tv->sk, tv->sk_len) != 0)
            goto mldsa_keygen_end;

        ok = 1;
    mldsa_keygen_end:
        qudo_st_end(st, ok);
        if (sk != NULL) {
            qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
            qudo_free(sk);
        }
        if (pk != NULL)
            qudo_free(pk);
        QUDO_MLDSA_free(sig);
        if (!ok)
            return 0;
    }
    return 1;
}

static int qudo_post_mldsa(qudo_st_ctx_t *st)
{
    size_t t;

    for (t = 0; t < QUDO_KAT_SIGN_NUM; t++) {
        const QUDO_KAT_SIGN *tv = &qudo_kat_sign_tests[t];
        QUDO_MLDSA *sig = NULL;
        uint8_t *pk = NULL, *sk = NULL;
        uint8_t *sig_buf = NULL;
        size_t sig_len = 0;
        uint8_t rnd[32];
        int ok = 0;

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_SIGNATURE, tv->desc);

        sig = QUDO_MLDSA_new(tv->alg_name);
        if (sig == NULL)
            goto mldsa_end;

        pk = (uint8_t *)qudo_malloc(sig->length_public_key);
        sk = (uint8_t *)qudo_malloc(sig->length_secret_key);
        sig_buf = (uint8_t *)qudo_malloc(sig->length_signature);
        if (pk == NULL || sk == NULL || sig_buf == NULL)
            goto mldsa_end;

        if (QUDO_MLDSA_keypair_internal(sig, pk, sk, tv->keygen_seed)
            != QUDO_MLDSA_SUCCESS)
            goto mldsa_end;

        memset(rnd, 0, sizeof(rnd));

        if (QUDO_MLDSA_sign_internal(sig, sig_buf, &sig_len, tv->msg,
                                     tv->msg_len, (const uint8_t *)"\x00\x00",
                                     2, rnd, sk, 0)
            != QUDO_MLDSA_SUCCESS)
            goto mldsa_end;

        qudo_st_corrupt(st, sig_buf);

        if (sig_len != tv->sig_len
            || qudo_memcmp_ct(sig_buf, tv->expected_sig, tv->sig_len) != 0)
            goto mldsa_end;

        if (QUDO_MLDSA_verify_internal(sig, sig_buf, sig_len, tv->msg,
                                       tv->msg_len, (const uint8_t *)"\x00\x00",
                                       2, pk, 0)
            != QUDO_MLDSA_SUCCESS)
            goto mldsa_end;

        ok = 1;
    mldsa_end:
        qudo_st_end(st, ok);
        if (sk != NULL) {
            qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
            qudo_free(sk);
        }
        if (pk != NULL)
            qudo_free(pk);
        qudo_free(sig_buf);
        QUDO_MLDSA_free(sig);
        if (!ok)
            return 0;
    }
    return 1;
}

static int qudo_post_keygen_slhdsa(qudo_st_ctx_t *st)
{
    size_t t;

    for (t = 0; t < QUDO_KAT_SLHDSA_NUM; t++) {
        const QUDO_KAT_SLHDSA *tv = &qudo_kat_slhdsa_tests[t];
        QUDO_SLHDSA *sig = NULL;
        uint8_t *pk = NULL, *sk = NULL;
        int ok = 0;

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_ASYM_KEYGEN, tv->desc);

        sig = QUDO_SLHDSA_new(tv->param_set);
        if (sig == NULL)
            goto slhdsa_keygen_end;

        pk = (uint8_t *)qudo_malloc(sig->length_public_key);
        sk = (uint8_t *)qudo_malloc(sig->length_secret_key);
        if (pk == NULL || sk == NULL)
            goto slhdsa_keygen_end;

        if (QUDO_SLHDSA_keypair_internal(sig, pk, sk, tv->sk_seed, tv->sk_prf,
                                         tv->pk_seed)
            != QUDO_SLHDSA_SUCCESS)
            goto slhdsa_keygen_end;

        qudo_st_corrupt(st, sk);

        if (qudo_memcmp_ct(sk, tv->sk, tv->sk_len) != 0)
            goto slhdsa_keygen_end;

        ok = 1;
    slhdsa_keygen_end:
        qudo_st_end(st, ok);
        if (sk != NULL) {
            qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
            qudo_free(sk);
        }
        if (pk != NULL)
            qudo_free(pk);
        QUDO_SLHDSA_free(sig);
        if (!ok)
            return 0;
    }
    return 1;
}

static int qudo_post_slhdsa(qudo_st_ctx_t *st)
{
    size_t t;

    for (t = 0; t < QUDO_KAT_SLHDSA_NUM; t++) {
        const QUDO_KAT_SLHDSA *tv = &qudo_kat_slhdsa_tests[t];
        QUDO_SLHDSA *sig = NULL;
        uint8_t *pk = NULL, *sk = NULL;
        uint8_t *sig_buf = NULL;
        size_t sig_len = 0;
        int ok = 0;

        qudo_st_begin(st, QUDO_ST_TYPE_KAT_SIGNATURE, tv->desc);

        sig = QUDO_SLHDSA_new(tv->param_set);
        if (sig == NULL)
            goto slhdsa_end;

        pk = (uint8_t *)qudo_malloc(sig->length_public_key);
        sk = (uint8_t *)qudo_malloc(sig->length_secret_key);
        sig_buf = (uint8_t *)qudo_malloc(sig->length_signature);
        if (pk == NULL || sk == NULL || sig_buf == NULL)
            goto slhdsa_end;

        if (QUDO_SLHDSA_keypair_internal(sig, pk, sk, tv->sk_seed, tv->sk_prf,
                                         tv->pk_seed)
            != QUDO_SLHDSA_SUCCESS)
            goto slhdsa_end;

        sig_len = sig->length_signature;

        if (QUDO_SLHDSA_sign_ex(sig, sig_buf, &sig_len, tv->msg, tv->msg_len,
                                NULL, 0, NULL, sk)
            != QUDO_SLHDSA_SUCCESS)
            goto slhdsa_end;

        if (tv->sig_sha256 != NULL) {
            uint8_t sig_digest[32];
            sha2_256(sig_digest, sig_buf, sig_len);
            if (qudo_memcmp_ct(sig_digest, tv->sig_sha256, 32) != 0) {
                qudo_cleanse(sig_digest, sizeof(sig_digest));
                goto slhdsa_end;
            }
            qudo_cleanse(sig_digest, sizeof(sig_digest));
        }

        qudo_st_corrupt(st, sig_buf);

        if (QUDO_SLHDSA_verify(sig, tv->msg, tv->msg_len, sig_buf, sig_len, pk)
            != QUDO_SLHDSA_SUCCESS)
            goto slhdsa_end;

        ok = 1;
    slhdsa_end:
        qudo_st_end(st, ok);
        if (sk != NULL) {
            qudo_cleanse(sk, sig ? sig->length_secret_key : 0);
            qudo_free(sk);
        }
        if (pk != NULL)
            qudo_free(pk);
        qudo_free(sig_buf);
        QUDO_SLHDSA_free(sig);
        if (!ok)
            return 0;
    }
    return 1;
}

static int qudo_post_sha256_kat(qudo_st_ctx_t *st)
{
    uint8_t md[QUDO_SHA2_256_DIGEST_SIZE];
    int ok = 0;

    qudo_st_begin(st, QUDO_ST_TYPE_KAT_DIGEST, "SHA-256");

    sha2_256(md, sha256_kat_msg, sizeof(sha256_kat_msg));

    qudo_st_corrupt(st, md);
    ok = (qudo_memcmp_ct(md, sha256_kat_expected, sizeof(sha256_kat_expected))
          == 0);

    qudo_cleanse(md, sizeof(md));
    qudo_st_end(st, ok);
    return ok;
}

static int qudo_post_hmac_sha256_kat(qudo_st_ctx_t *st)
{
    uint8_t tag[32];
    int ok = 0;

    qudo_st_begin(st, QUDO_ST_TYPE_KAT_MAC, "HMAC-SHA-256");

    qudo_fips_hmac_sha256(hmac_sha256_kat_key, sizeof(hmac_sha256_kat_key),
                          hmac_sha256_kat_msg, sizeof(hmac_sha256_kat_msg),
                          tag);

    qudo_st_corrupt(st, tag);
    ok = (qudo_memcmp_ct(tag, hmac_sha256_kat_expected,
                         sizeof(hmac_sha256_kat_expected))
          == 0);

    qudo_cleanse(tag, sizeof(tag));
    qudo_st_end(st, ok);
    return ok;
}

static int qudo_post_ctrdrbg_kat(qudo_st_ctx_t *st)
{
    qudo_ctrdrbg_ctx_t ctx;
    uint8_t out[sizeof(ctr_drbg_aes256_expected)];
    int ok = 0;

    qudo_st_begin(st, QUDO_ST_TYPE_KAT_DRBG, "CTR-DRBG-AES-256");

    memset(&ctx, 0, sizeof(ctx));

    if (qudo_ctrdrbg_init(&ctx, 32, ctr_drbg_aes256_seed,
                          sizeof(ctr_drbg_aes256_seed))
        != 0)
        goto done;

    if (qudo_ctrdrbg_reseed(&ctx, ctr_drbg_aes256_reseed,
                            sizeof(ctr_drbg_aes256_reseed))
        != 0)
        goto done;

    if (qudo_ctrdrbg_generate(&ctx, out, sizeof(out), ctr_drbg_aes256_addin0,
                              sizeof(ctr_drbg_aes256_addin0))
        != 0)
        goto done;

    if (qudo_ctrdrbg_generate(&ctx, out, sizeof(out), ctr_drbg_aes256_addin1,
                              sizeof(ctr_drbg_aes256_addin1))
        != 0)
        goto done;

    qudo_st_corrupt(st, out);
    ok = (qudo_memcmp_ct(out, ctr_drbg_aes256_expected, sizeof(out)) == 0);

done:
    qudo_ctrdrbg_free(&ctx);
    qudo_cleanse(out, sizeof(out));
    qudo_st_end(st, ok);
    return ok;
}

QUDO_PQC_API int qudo_pqc_run_post_primitives(qudo_st_ctx_t *st)
{
    if (!qudo_post_sha256_kat(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "SHA-256 KAT failed");
        return 0;
    }

    if (!qudo_post_hmac_sha256_kat(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "HMAC-SHA-256 KAT failed");
        return 0;
    }

    if (!qudo_post_ctrdrbg_kat(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "CTR-DRBG KAT failed");
        return 0;
    }
    qudo_atomic_store(&g_post_drbg_kat_passed, 1);

    return 1;
}

QUDO_PQC_API int qudo_pqc_run_post_algorithms(qudo_st_ctx_t *st)
{
    if (!qudo_post_keygen_mlkem(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KEYGEN_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "ML-KEM keygen KAT failed");
        return 0;
    }
    if (!qudo_post_keygen_mldsa(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KEYGEN_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "ML-DSA keygen KAT failed");
        return 0;
    }
    if (!qudo_post_keygen_slhdsa(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KEYGEN_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "SLH-DSA keygen KAT failed");
        return 0;
    }

    if (!qudo_post_kem(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_KEM_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "ML-KEM encaps/decaps KAT failed");
        return 0;
    }

    if (!qudo_post_mldsa(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_SIG_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "ML-DSA sign/verify KAT failed");
        return 0;
    }

    if (!qudo_post_slhdsa(st)) {
        qudo_audit_log(QUDO_SEV_FATAL, QUDO_ERR_POST_SIG_KAT_FAIL,
                       QUDO_AUDIT_COMP_POST, "SLH-DSA sign/verify KAT failed");
        return 0;
    }

    qudo_pqc_set_cast_status(QUDO_CAST_ML_KEM_512, QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_ML_KEM_768, QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_ML_KEM_1024, QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_ML_DSA_44, QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_ML_DSA_65, QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_ML_DSA_87, QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_SLH_DSA_SHA2_128,
                             QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_SLH_DSA_SHA2_192,
                             QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_SLH_DSA_SHA2_256,
                             QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_SLH_DSA_SHAKE_128,
                             QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_SLH_DSA_SHAKE_192,
                             QUDO_CAST_STATE_SUCCESS);
    qudo_pqc_set_cast_status(QUDO_CAST_SLH_DSA_SHAKE_256,
                             QUDO_CAST_STATE_SUCCESS);

    return 1;
}

QUDO_PQC_API int qudo_pqc_run_post(qudo_st_ctx_t *st)
{
    if (!qudo_pqc_run_post_primitives(st))
        return 0;
    return qudo_pqc_run_post_algorithms(st);
}
