/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "../include/slhdsa_wrapper.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 64) return 0;

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new("SLH-DSA-SHA2-128s");
    if (!sig) return 0;

    uint8_t pk[SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES];
    uint8_t sk[SLH_DSA_SHA2_128S_SECRET_KEY_BYTES];

    QUDO_SLHDSA_keypair(sig, pk, sk);

    size_t sig_len = size / 2;
    size_t msg_len = size - sig_len;

    QUDO_SLHDSA_verify(sig, data + sig_len, msg_len, data, sig_len, pk);

    QUDO_SLHDSA_free(sig);
    return 0;
}
