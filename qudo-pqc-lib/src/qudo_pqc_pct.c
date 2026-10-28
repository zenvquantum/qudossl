/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_wrapper.h"
#include "mlkem_wrapper.h"
#include "qudo_pqc.h"
#include "qudo_pqc_audit.h"
#include "qudo_pqc_platform.h"
#include "qudo_pqc_selftest.h"
#include "slhdsa_wrapper.h"
#include <string.h>

#ifndef ML_DSA_87_SIGNATURE_BYTES
#    define ML_DSA_87_SIGNATURE_BYTES 4627
#endif

#ifndef MLDSA_SEEDBYTES
#    define MLDSA_SEEDBYTES 32
#endif

int qudo_pqc_mlkem_pct(const void *kem_ptr, const uint8_t *pk,
                       const uint8_t *sk, int use_random)
{
    const QUDO_KEM *kem = (const QUDO_KEM *)kem_ptr;
    qudo_st_ctx_t st;
    void *event = NULL;
    uint8_t entropy[32] = {0};
    uint8_t secret[32] = {0};
    uint8_t out[32] = {0};
    uint8_t *ctext = NULL;
    int operation_result;
    int ret = 0;

    if (kem == NULL)
        return 0;
    if (pk == NULL || sk == NULL)
        return 0;

    if (qudo_pqc_is_self_testing())
        return 1;

    qudo_pqc_get_st_ctx(&st);
    st.event = &event;

    qudo_st_begin(&st, QUDO_ST_TYPE_PCT, QUDO_ST_DESC_PCT_ML_KEM);

    ctext = (uint8_t *)qudo_malloc(kem->length_ciphertext);
    if (ctext == NULL)
        goto err;

    memset(out, 0, sizeof(out));

    if (use_random) {
        operation_result = QUDO_KEM_encaps(kem, ctext, secret, pk);
    } else {
        memset(entropy, 0x55, sizeof(entropy));
        operation_result
            = QUDO_KEM_encaps_derand(kem, ctext, secret, pk, entropy);
    }
    if (operation_result != QUDO_KEM_SUCCESS)
        goto err;

    qudo_st_corrupt(&st, ctext);

    operation_result = QUDO_KEM_decaps(kem, out, ctext, sk);
    if (operation_result != QUDO_KEM_SUCCESS
        || qudo_memcmp_ct(out, secret, sizeof(out)) != 0)
        goto err;

    ret = 1;
err:
    qudo_st_end(&st, ret);
    if (!ret)
        qudo_audit_log(QUDO_SEV_ERROR, QUDO_ERR_PCT_ENCAPS_FAIL,
                       QUDO_AUDIT_COMP_PCT, "ML-KEM PCT failed");
    qudo_free(ctext);
    qudo_cleanse(secret, sizeof(secret));
    qudo_cleanse(out, sizeof(out));
    qudo_cleanse(entropy, sizeof(entropy));
    return ret;
}

int qudo_pqc_mldsa_pct(const void *sig_ptr, const uint8_t *pk,
                       const uint8_t *sk)
{
    const QUDO_MLDSA *sig = (const QUDO_MLDSA *)sig_ptr;
    qudo_st_ctx_t st;
    void *event = NULL;
    static const uint8_t msg[] = {80, 108, 117, 103, 104};
    uint8_t rnd[MLDSA_SEEDBYTES] = {0};
    uint8_t *sig_buf = NULL;
    size_t sig_len = 0;
    int ret = 0;

    if (sig == NULL)
        return 0;
    if (pk == NULL || sk == NULL)
        return 0;

    if (qudo_pqc_is_self_testing())
        return 1;

    qudo_pqc_get_st_ctx(&st);
    st.event = &event;

    qudo_st_begin(&st, QUDO_ST_TYPE_PCT, QUDO_ST_DESC_PCT_ML_DSA);

    sig_buf = (uint8_t *)qudo_malloc(sig->length_signature);
    if (sig_buf == NULL)
        goto err;

    memset(rnd, 0, sizeof(rnd));

    if (QUDO_MLDSA_sign_internal((QUDO_MLDSA *)sig, sig_buf, &sig_len, msg,
                                 sizeof(msg), (const uint8_t *)"\x00\x00", 2,
                                 rnd, sk, 0)
        != QUDO_MLDSA_SUCCESS)
        goto err;

    qudo_st_corrupt(&st, sig_buf);

    if (QUDO_MLDSA_verify_internal((QUDO_MLDSA *)sig, sig_buf, sig_len, msg,
                                   sizeof(msg), (const uint8_t *)"\x00\x00", 2,
                                   pk, 0)
        != QUDO_MLDSA_SUCCESS)
        goto err;

    ret = 1;
err:
    qudo_st_end(&st, ret);
    if (!ret)
        qudo_audit_log(QUDO_SEV_ERROR, QUDO_ERR_PCT_SIGN_FAIL,
                       QUDO_AUDIT_COMP_PCT, "ML-DSA PCT failed");
    qudo_free(sig_buf);
    qudo_cleanse(rnd, sizeof(rnd));
    return ret;
}

int qudo_pqc_slhdsa_pct(const void *sig_ptr, const uint8_t *pk,
                        const uint8_t *sk)
{
    const QUDO_SLHDSA *sig = (const QUDO_SLHDSA *)sig_ptr;
    qudo_st_ctx_t st;
    void *event = NULL;
    uint8_t msg[16] = {0};
    uint8_t *sig_buf = NULL;
    size_t sig_len = 0;
    int ret = 0;

    if (sig == NULL)
        return 0;
    if (pk == NULL || sk == NULL)
        return 0;

    if (qudo_pqc_is_self_testing())
        return 1;

    qudo_pqc_get_st_ctx(&st);
    st.event = &event;

    qudo_st_begin(&st, QUDO_ST_TYPE_PCT, QUDO_ST_DESC_PCT_SLH_DSA);

    sig_buf = (uint8_t *)qudo_malloc(sig->length_signature);
    if (sig_buf == NULL)
        goto err;

    sig_len = sig->length_signature;

    if (QUDO_SLHDSA_sign(sig, sig_buf, &sig_len, msg, sizeof(msg), sk)
        != QUDO_SLHDSA_SUCCESS)
        goto err;

    qudo_st_corrupt(&st, sig_buf);

    if (QUDO_SLHDSA_verify(sig, msg, sizeof(msg), sig_buf, sig_len, pk)
        != QUDO_SLHDSA_SUCCESS)
        goto err;

    ret = 1;
err:
    qudo_st_end(&st, ret);
    if (!ret)
        qudo_audit_log(QUDO_SEV_ERROR, QUDO_ERR_PCT_SIGN_FAIL,
                       QUDO_AUDIT_COMP_PCT, "SLH-DSA PCT failed");
    qudo_free(sig_buf);
    return ret;
}
