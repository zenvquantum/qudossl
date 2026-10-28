/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLDSA_ERROR_H
#define MLDSA_ERROR_H

#include "mldsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    QUDO_MLDSA_status_t code;
    const char *func;
    const char *detail;
    int line;
} QUDO_MLDSA_error_info_t;

QUDO_MLDSA_API const QUDO_MLDSA_error_info_t *QUDO_MLDSA_get_last_error(void);

QUDO_MLDSA_API const char *QUDO_MLDSA_error_string(QUDO_MLDSA_status_t code);

QUDO_MLDSA_API void QUDO_MLDSA_clear_error(void);

void qudo_mldsa_set_error_internal(QUDO_MLDSA_status_t code, const char *func,
                                   const char *detail, int line);

#define QUDO_MLDSA_SET_ERROR(code, detail) \
    qudo_mldsa_set_error_internal(code, __func__, detail, __LINE__)

#ifdef __cplusplus
}
#endif

#endif
