/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/slhdsa_config.h"
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
int slhdsa_randombytes_fallback(uint8_t *out, size_t outlen)
{
    return (QUDO_SLHDSA_randombytes(out, outlen) == 0) ? 0 : -1;
}
#    pragma comment(linker, \
                    "/alternatename:randombytes=slhdsa_randombytes_fallback")
#else
#    if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#    endif
int randombytes(uint8_t *out, size_t outlen)
{

    return (QUDO_SLHDSA_randombytes(out, outlen) == 0) ? 0 : -1;
}
#endif
