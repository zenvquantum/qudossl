/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mldsa_wrapper.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    const char *algs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    QUDO_MLDSA *sig = QUDO_MLDSA_new(algs[data[0] % 3]);
    if (!sig)
        return 0;

    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    uint8_t pk[2592], sk[4896];
    if (QUDO_MLDSA_keypair(sig, pk, sk) != QUDO_MLDSA_SUCCESS) {
        QUDO_MLDSA_free(sig);
        return 0;
    }

    size_t sig_bytes = sig->length_signature;
    if (payload_len > sig_bytes) {
        const uint8_t *fuzz_sig = payload;
        const uint8_t *fuzz_msg = payload + sig_bytes;
        size_t fuzz_msg_len = payload_len - sig_bytes;

        QUDO_MLDSA_verify(sig, fuzz_sig, sig_bytes,
                         fuzz_msg, fuzz_msg_len, pk);
    }

    if (payload_len >= sig->length_public_key) {
        uint8_t real_sig[4627];
        size_t real_sig_len = sizeof(real_sig);
        const uint8_t msg[] = "test";

        if (QUDO_MLDSA_sign(sig, real_sig, &real_sig_len, msg, 4, sk) == QUDO_MLDSA_SUCCESS) {
            QUDO_MLDSA_verify(sig, real_sig, real_sig_len, msg, 4, payload);
        }
    }

    QUDO_MLDSA_free(sig);
    return 0;
}
