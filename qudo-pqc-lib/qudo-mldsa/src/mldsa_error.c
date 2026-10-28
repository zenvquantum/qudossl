/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_error.h"
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>

static DWORD fls_key = FLS_OUT_OF_INDEXES;
static volatile LONG fls_init_done = 0;

static VOID WINAPI fls_callback(PVOID ptr)
{
    if (ptr != NULL) {
        memset(ptr, 0, sizeof(QUDO_MLDSA_error_info_t));
        free(ptr);
    }
}

static void fls_ensure_init(void)
{
    if (InterlockedCompareExchange(&fls_init_done, 1, 0) == 0)
        fls_key = FlsAlloc(fls_callback);
}

static QUDO_MLDSA_error_info_t *tls_get_state(void)
{
    QUDO_MLDSA_error_info_t *state;
    fls_ensure_init();
    if (fls_key == FLS_OUT_OF_INDEXES)
        return NULL;
    state = (QUDO_MLDSA_error_info_t *)FlsGetValue(fls_key);
    if (state == NULL) {
        state = (QUDO_MLDSA_error_info_t *)calloc(1, sizeof(*state));
        if (state != NULL)
            FlsSetValue(fls_key, state);
    }
    return state;
}

#else
#    include <pthread.h>

static pthread_key_t tls_key;
static pthread_once_t tls_once = PTHREAD_ONCE_INIT;

static void tls_free_state(void *ptr)
{
    if (ptr != NULL) {
        memset(ptr, 0, sizeof(QUDO_MLDSA_error_info_t));
        free(ptr);
    }
}

static void tls_init_key(void)
{
    pthread_key_create(&tls_key, tls_free_state);
}

static QUDO_MLDSA_error_info_t *tls_get_state(void)
{
    QUDO_MLDSA_error_info_t *state;
    pthread_once(&tls_once, tls_init_key);
    state = (QUDO_MLDSA_error_info_t *)pthread_getspecific(tls_key);
    if (state == NULL) {
        state = (QUDO_MLDSA_error_info_t *)calloc(1, sizeof(*state));
        if (state != NULL)
            pthread_setspecific(tls_key, state);
    }
    return state;
}
#endif

void qudo_mldsa_set_error_internal(QUDO_MLDSA_status_t code, const char *func,
                                   const char *detail, int line)
{
    QUDO_MLDSA_error_info_t *state = tls_get_state();
    if (state == NULL)
        return;
    state->code = code;
    state->func = func;
    state->detail = detail;
    state->line = line;
}

QUDO_MLDSA_API const QUDO_MLDSA_error_info_t *QUDO_MLDSA_get_last_error(void)
{
    QUDO_MLDSA_error_info_t *state = tls_get_state();
    if (state == NULL || state->code == QUDO_MLDSA_SUCCESS)
        return NULL;
    return state;
}

QUDO_MLDSA_API const char *QUDO_MLDSA_error_string(QUDO_MLDSA_status_t code)
{
    switch (code) {
    case QUDO_MLDSA_SUCCESS:
        return "success";
    case QUDO_MLDSA_ERROR:
        return "generic error";
    case QUDO_MLDSA_ERROR_INVALID_ARG:
        return "invalid argument";
    case QUDO_MLDSA_ERROR_NULL_PTR:
        return "null pointer";
    case QUDO_MLDSA_ERROR_ALLOC:
        return "memory allocation failed";
    case QUDO_MLDSA_ERROR_RNG:
        return "random number generation failed";
    case QUDO_MLDSA_ERROR_VERIFY:
        return "verification failed";
    case QUDO_MLDSA_ERROR_DECODE:
        return "decoding failed";
    case QUDO_MLDSA_ERROR_NOT_IMPL:
        return "not implemented";
    case QUDO_MLDSA_ERROR_CRYPTO:
        return "cryptographic operation failed";
    case QUDO_MLDSA_ERROR_FILE_IO:
        return "file I/O error";
    case QUDO_MLDSA_ERROR_ENCODE:
        return "encoding failed";
    case QUDO_MLDSA_ERROR_BUFFER_TOO_SMALL:
        return "buffer too small";
    case QUDO_MLDSA_ERROR_INVALID_SIGNATURE:
        return "invalid signature";
    default:
        return "unknown error";
    }
}

QUDO_MLDSA_API void QUDO_MLDSA_clear_error(void)
{
    QUDO_MLDSA_error_info_t *state = tls_get_state();
    if (state != NULL)
        memset(state, 0, sizeof(*state));
}
