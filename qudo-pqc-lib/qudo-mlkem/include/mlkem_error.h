/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLKEM_ERROR_H
#define MLKEM_ERROR_H

#include "mlkem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    QUDO_KEM_status_t code;
    const char *func;
    const char *detail;
    int line;
} QUDO_KEM_error_info_t;

QUDO_KEM_API const QUDO_KEM_error_info_t *QUDO_KEM_get_last_error(void);

QUDO_KEM_API const char *QUDO_KEM_error_string(QUDO_KEM_status_t code);

QUDO_KEM_API void QUDO_KEM_clear_error(void);

void qudo_kem_set_error_internal(QUDO_KEM_status_t code, const char *func,
                                 const char *detail, int line);

#define QUDO_KEM_SET_ERROR(code, detail) \
    qudo_kem_set_error_internal(code, __func__, detail, __LINE__)

#ifdef __cplusplus
}
#endif

#endif
