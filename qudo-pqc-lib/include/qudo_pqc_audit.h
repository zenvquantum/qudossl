/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef QUDO_PQC_AUDIT_H
#define QUDO_PQC_AUDIT_H

#include "qudo_pqc_err.h"

#ifndef QUDO_PQC_API
#    if defined(_WIN32) || defined(__CYGWIN__)
#        ifdef QUDO_PQC_BUILDING
#            define QUDO_PQC_API __declspec(dllexport)
#        else
#            define QUDO_PQC_API __declspec(dllimport)
#        endif
#    elif defined(__GNUC__) && __GNUC__ >= 4
#        define QUDO_PQC_API __attribute__((visibility("default")))
#    else
#        define QUDO_PQC_API
#    endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_AUDIT_COMP_STATE     "STATE"
#define QUDO_AUDIT_COMP_POST      "POST"
#define QUDO_AUDIT_COMP_INTEGRITY "INTEGRITY"
#define QUDO_AUDIT_COMP_PCT       "PCT"
#define QUDO_AUDIT_COMP_CAST      "CAST"
#define QUDO_AUDIT_COMP_DRBG      "DRBG"
#define QUDO_AUDIT_COMP_KEY       "KEY"
#define QUDO_AUDIT_COMP_INDICATOR "INDICATOR"

typedef void (*qudo_audit_cb)(qudo_sev_t severity, qudo_err_t code,
                              const char *component, const char *detail,
                              void *cb_arg);

QUDO_PQC_API void qudo_audit_log(qudo_sev_t severity, qudo_err_t code,
                                 const char *component, const char *detail);

QUDO_PQC_API void qudo_audit_set_callback(qudo_audit_cb cb, void *cb_arg);

QUDO_PQC_API void qudo_audit_cleanup(void);

#define QUDO_AUDIT_RATE_LIMIT 100

#ifdef __cplusplus
}
#endif

#endif
