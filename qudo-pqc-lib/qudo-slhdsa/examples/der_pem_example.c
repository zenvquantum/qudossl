/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include "../include/slhdsa_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int demo_der_pem(const char *alg_name)
{
    printf("\n=== DER/PEM Demo: %s ===\n", alg_name);

    QUDO_SLHDSA *sig = QUDO_SLHDSA_new(alg_name);
    if (!sig) {
        printf("Failed to create instance\n");
        return 1;
    }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    QUDO_SLHDSA_keypair(sig, pk, sk);
    printf("Generated keypair (pk=%zu bytes, sk=%zu bytes)\n",
           sig->length_public_key, sig->length_secret_key);

    uint8_t der_buf[256];
    size_t der_len = sizeof(der_buf);
    QUDO_SLHDSA_status_t ret = QUDO_SLHDSA_export_public_key_der(
        pk, sig->length_public_key, sig->param_set, der_buf, &der_len);
    if (ret == QUDO_SLHDSA_SUCCESS) {
        printf("Public key DER: %zu bytes\n", der_len);
    } else {
        printf("DER export failed: %s\n", QUDO_SLHDSA_get_error_string(ret));
    }

    uint8_t *pk2 = malloc(sig->length_public_key);
    size_t pk2_len = sig->length_public_key;
    ret = QUDO_SLHDSA_import_public_key_der(der_buf, der_len, pk2, &pk2_len);
    if (ret == QUDO_SLHDSA_SUCCESS) {
        if (memcmp(pk, pk2, sig->length_public_key) == 0) {
            printf("DER round-trip: OK (keys match)\n");
        } else {
            printf("DER round-trip: FAILED (keys differ)\n");
        }
    }

    char pem_buf[4096];
    size_t pem_len = sizeof(pem_buf);
    ret = QUDO_SLHDSA_export_public_key_pem(pk, sig->length_public_key,
                                            sig->param_set, pem_buf, &pem_len);
    if (ret == QUDO_SLHDSA_SUCCESS) {
        printf("Public key PEM: %zu bytes\n", pem_len);
        char *first_line = strtok(pem_buf, "\n");
        if (first_line)
            printf("  %s\n  ...\n", first_line);
    }

    uint8_t sk_der_buf[512];
    size_t sk_der_len = sizeof(sk_der_buf);
    ret = QUDO_SLHDSA_export_private_key_der(
        sk, sig->length_secret_key, sig->param_set, sk_der_buf, &sk_der_len);
    if (ret == QUDO_SLHDSA_SUCCESS) {
        printf("Private key DER: %zu bytes\n", sk_der_len);
    }

    uint8_t msg[] = "Hello from SLH-DSA DER/PEM example!";
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = sig->length_signature;

    ret = QUDO_SLHDSA_sign(sig, signature, &sig_len, msg, sizeof(msg) - 1, sk);
    if (ret == QUDO_SLHDSA_SUCCESS) {
        ret = QUDO_SLHDSA_verify(sig, msg, sizeof(msg) - 1, signature, sig_len,
                                 pk2);
        printf("Sign with original, verify with imported: %s\n",
               ret == QUDO_SLHDSA_SUCCESS ? "OK" : "FAILED");
    }

    free(pk);
    free(sk);
    free(pk2);
    free(signature);
    QUDO_SLHDSA_free(sig);
    return 0;
}

int main(void)
{
    printf("SLH-DSA DER/PEM Serialization Example\n");
    printf("=====================================\n");

    QUDO_SLHDSA_print_system_info();

    demo_der_pem("SLH-DSA-SHA2-128f");
    demo_der_pem("SLH-DSA-SHAKE-128f");

    printf("\nDone.\n");
    return 0;
}
