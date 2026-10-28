/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mldsa_wrapper.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t public_key[2592];
    size_t public_key_len = sizeof(public_key);

    QUDO_MLDSA_status_t status = QUDO_MLDSA_import_public_key_der(
        data, size, public_key, &public_key_len);

    if (status == QUDO_MLDSA_SUCCESS && public_key_len > 0) {
        uint8_t der_out[4096];
        size_t der_out_len = sizeof(der_out);
        QUDO_MLDSA_export_public_key_der(public_key, public_key_len,
                                        der_out, &der_out_len);
    }

    return 0;
}
