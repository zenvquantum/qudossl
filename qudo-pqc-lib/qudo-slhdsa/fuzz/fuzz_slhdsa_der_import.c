/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "../include/slhdsa_wrapper.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t public_key[SLH_DSA_MAX_PUBLIC_KEY_BYTES];
    size_t public_key_len = sizeof(public_key);

    QUDO_SLHDSA_import_public_key_der(data, size, public_key, &public_key_len);

    if (public_key_len > 0 && public_key_len <= sizeof(public_key)) {
        uint8_t der_out[256];
        size_t der_out_len = sizeof(der_out);
        QUDO_SLHDSA_export_public_key_der(public_key, public_key_len,
                                          QUDO_SLHDSA_SHA2_128s, der_out,
                                          &der_out_len);
    }

    uint8_t private_key[SLH_DSA_MAX_SECRET_KEY_BYTES];
    size_t private_key_len = sizeof(private_key);

    if (QUDO_SLHDSA_import_private_key_der(data, size, private_key,
                                           &private_key_len)
            == QUDO_SLHDSA_SUCCESS
        && private_key_len > 0 && private_key_len <= sizeof(private_key)) {
        uint8_t der_out[512];
        size_t der_out_len = sizeof(der_out);
        QUDO_SLHDSA_export_private_key_der(private_key, private_key_len,
                                           QUDO_SLHDSA_SHA2_128s, der_out,
                                           &der_out_len);
    }

    return 0;
}
