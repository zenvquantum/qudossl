/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mlkem_wrapper.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t public_key[1568];
    size_t public_key_len = sizeof(public_key);

    QUDO_KEM_import_public_key_der(data, size, public_key, &public_key_len);

    if (public_key_len > 0 && public_key_len <= sizeof(public_key)) {
        uint8_t der_out[2048];
        size_t der_out_len = sizeof(der_out);
        QUDO_KEM_export_public_key_der(public_key, public_key_len,
                                        der_out, &der_out_len);
    }

    return 0;
}
