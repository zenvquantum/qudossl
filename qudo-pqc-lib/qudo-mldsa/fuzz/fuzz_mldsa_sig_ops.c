/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../include/mldsa_wrapper.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    uint8_t op = data[0] % 3;
    const char *algs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    const char *alg = algs[data[1] % 3];
    const uint8_t *payload = data + 2;
    size_t payload_len = size - 2;

    QUDO_MLDSA *sig = QUDO_MLDSA_new(alg);
    if (!sig)
        return 0;

    switch (op) {
    case 0: {
        if (payload_len >= sig->length_public_key + sig->length_signature) {
            const uint8_t *pk = payload;
            const uint8_t *signature = payload + sig->length_public_key;
            size_t sig_len = sig->length_signature;
            const uint8_t *msg = payload + sig->length_public_key + sig->length_signature;
            size_t msg_len = payload_len - sig->length_public_key - sig->length_signature;

            sig->verify(msg, msg_len, signature, sig_len, pk);
        }
        break;
    }
    case 1: {
        uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
        uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
        if (sig->keypair(pk, sk) == QUDO_MLDSA_SUCCESS && payload_len > 0) {
            sig->verify(payload, payload_len / 2,
                       payload + payload_len / 2, payload_len - payload_len / 2,
                       pk);
        }
        break;
    }
    case 2: {
        uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];
        uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
        uint8_t signature[ML_DSA_87_SIGNATURE_BYTES];
        size_t sig_len = sizeof(signature);
        if (sig->keypair(pk, sk) == QUDO_MLDSA_SUCCESS && payload_len > 0) {
            sig->sign(signature, &sig_len, payload, payload_len, sk);
        }
        break;
    }
    }

    QUDO_MLDSA_free(sig);
    return 0;
}
