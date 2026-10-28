/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "../include/slhdsa_wrapper.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) return 0;

    uint8_t pubkey[SLH_DSA_MAX_PUBLIC_KEY_BYTES];
    size_t pubkey_len = sizeof(pubkey);

    QUDO_SLHDSA_import_public_key_der(data, size, pubkey, &pubkey_len);

    uint8_t privkey[SLH_DSA_MAX_SECRET_KEY_BYTES];
    size_t privkey_len = sizeof(privkey);

    QUDO_SLHDSA_import_private_key_der(data, size, privkey, &privkey_len);

    return 0;
}
