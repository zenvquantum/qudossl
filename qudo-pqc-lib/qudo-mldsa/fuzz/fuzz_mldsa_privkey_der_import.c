/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mldsa_wrapper.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t private_key[4896];
    size_t private_key_len = sizeof(private_key);

    QUDO_MLDSA_status_t status = QUDO_MLDSA_import_private_key_der(
        data, size, private_key, &private_key_len);

    if (status == QUDO_MLDSA_SUCCESS && private_key_len > 0) {
        uint8_t der_out[8192];
        size_t der_out_len = sizeof(der_out);
        QUDO_MLDSA_export_private_key_der(private_key, private_key_len,
                                         der_out, &der_out_len);
    }

    return 0;
}
