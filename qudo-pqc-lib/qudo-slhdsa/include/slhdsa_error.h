/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef SLHDSA_ERROR_H
#define SLHDSA_ERROR_H

#include "slhdsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    QUDO_SLHDSA_status_t code;
    const char *func;
    const char *detail;
    int line;
} QUDO_SLHDSA_error_info_t;

QUDO_SLHDSA_API const QUDO_SLHDSA_error_info_t *
QUDO_SLHDSA_get_last_error(void);

QUDO_SLHDSA_API const char *QUDO_SLHDSA_error_string(QUDO_SLHDSA_status_t code);

QUDO_SLHDSA_API void QUDO_SLHDSA_clear_error(void);

void qudo_slhdsa_set_error_internal(QUDO_SLHDSA_status_t code, const char *func,
                                    const char *detail, int line);

#define QUDO_SLHDSA_SET_ERROR(code, detail) \
    qudo_slhdsa_set_error_internal(code, __func__, detail, __LINE__)

#ifdef __cplusplus
}
#endif

#endif
