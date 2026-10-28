/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef QUDO_PQC_SELFTEST_H
#define QUDO_PQC_SELFTEST_H

#include "qudo_pqc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    qudo_st_event_cb cb;
    void *cb_arg;
    const char *current_type;
    const char *current_desc;
    void **event;
} qudo_st_ctx_t;

static inline int qudo_st_begin(qudo_st_ctx_t *st, const char *type,
                                const char *desc)
{
    st->current_type = type;
    st->current_desc = desc;
    if (st->cb != NULL)
        return st->cb(QUDO_ST_PHASE_BEGIN, type, desc, 0, NULL, st->event,
                      st->cb_arg);
    return 1;
}

static inline int qudo_st_corrupt(qudo_st_ctx_t *st, unsigned char *data)
{
    if (st->cb != NULL)
        return st->cb(QUDO_ST_PHASE_CORRUPT, st->current_type, st->current_desc,
                      0, data, st->event, st->cb_arg);
    return 1;
}

static inline void qudo_st_end(qudo_st_ctx_t *st, int result)
{
    if (st->cb != NULL)
        st->cb(QUDO_ST_PHASE_END, st->current_type, st->current_desc, result,
               NULL, st->event, st->cb_arg);
}

void qudo_pqc_get_st_ctx(qudo_st_ctx_t *st);

#ifdef __cplusplus
}
#endif

#endif
