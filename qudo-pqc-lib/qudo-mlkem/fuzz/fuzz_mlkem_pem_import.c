/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "mlkem_wrapper.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *pem_str = malloc(size + 1);
    if (!pem_str)
        return 0;

    memcpy(pem_str, data, size);
    pem_str[size] = '\0';

    uint8_t public_key[1568];
    size_t public_key_len = sizeof(public_key);

    QUDO_KEM_import_public_key_pem(pem_str, public_key, &public_key_len);

    free(pem_str);
    return 0;
}
