/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <string.h>
#include "../include/mlkem_wrapper.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < (len > 16 ? 16 : len); i++) {
        printf("%02x", data[i]);
    }
    if (len > 16) printf("...");
    printf(" (%zu bytes)\n", len);
}

int main(void) {
    printf("===========================================\n");
    printf("QUDO KEM - DER/PEM Export/Import Example\n");
    printf("===========================================\n\n");

    if (QUDO_KEM_init() != QUDO_KEM_SUCCESS) {
        printf("ERROR: Failed to initialize QUDO KEM\n");
        return 1;
    }

    printf("Generating ML-KEM-512 keypair...\n");
    uint8_t public_key[QUDO_KEM_512_PUBLIC_KEY_BYTES];
    uint8_t secret_key[QUDO_KEM_512_SECRET_KEY_BYTES];

    if (QUDO_KEM_keypair_generate(QUDO_KEM_512, public_key, secret_key) != QUDO_KEM_SUCCESS) {
        printf("ERROR: Keypair generation failed\n");
        return 1;
    }

    print_hex("  Original public key", public_key, QUDO_KEM_512_PUBLIC_KEY_BYTES);

    printf("\n--- Exporting to DER format ---\n");
    uint8_t der_buffer[4096];
    size_t der_len = sizeof(der_buffer);

    QUDO_KEM_status_t status = QUDO_KEM_export_public_key_der(
        public_key, QUDO_KEM_512_PUBLIC_KEY_BYTES,
        der_buffer, &der_len
    );

    if (status == QUDO_KEM_SUCCESS) {
        print_hex("  DER encoded", der_buffer, der_len);
        printf("SUCCESS: DER export\n");

        FILE *f = fopen("qudo_pubkey.der", "wb");
        if (f) {
            fwrite(der_buffer, 1, der_len, f);
            fclose(f);
            printf("  Saved to qudo_pubkey.der\n");
        }
    } else {
        printf("ERROR: DER export failed (status=%d)\n", status);
        return 1;
    }

    printf("\n--- Exporting to PEM format ---\n");
    char pem_buffer[8192];
    size_t pem_len = sizeof(pem_buffer);

    status = QUDO_KEM_export_public_key_pem(
        public_key, QUDO_KEM_512_PUBLIC_KEY_BYTES,
        pem_buffer, &pem_len
    );

    if (status == QUDO_KEM_SUCCESS) {
        printf("SUCCESS: PEM export\n");
        printf("PEM output:\n%s\n", pem_buffer);

        FILE *f = fopen("qudo_pubkey.pem", "w");
        if (f) {
            fwrite(pem_buffer, 1, pem_len, f);
            fclose(f);
            printf("  Saved to qudo_pubkey.pem\n");
        }
    } else {
        printf("ERROR: PEM export failed (status=%d)\n", status);
        return 1;
    }

    printf("\n--- Importing from DER format ---\n");
    uint8_t imported_key_der[QUDO_KEM_512_PUBLIC_KEY_BYTES];
    size_t imported_len_der = sizeof(imported_key_der);

    status = QUDO_KEM_import_public_key_der(
        der_buffer, der_len,
        imported_key_der, &imported_len_der
    );

    if (status == QUDO_KEM_SUCCESS) {
        if (memcmp(public_key, imported_key_der, QUDO_KEM_512_PUBLIC_KEY_BYTES) == 0) {
            printf("SUCCESS: DER import - keys match!\n");
        } else {
            printf("ERROR: DER import - keys don't match\n");
            return 1;
        }
    } else {
        printf("ERROR: DER import failed (status=%d)\n", status);
        return 1;
    }

    printf("\n--- Importing from PEM format ---\n");
    uint8_t imported_key_pem[QUDO_KEM_512_PUBLIC_KEY_BYTES];
    size_t imported_len_pem = sizeof(imported_key_pem);

    status = QUDO_KEM_import_public_key_pem(
        pem_buffer,
        imported_key_pem, &imported_len_pem
    );

    if (status == QUDO_KEM_SUCCESS) {
        if (memcmp(public_key, imported_key_pem, QUDO_KEM_512_PUBLIC_KEY_BYTES) == 0) {
            printf("SUCCESS: PEM import - keys match!\n");
        } else {
            printf("ERROR: PEM import - keys don't match\n");
            return 1;
        }
    } else {
        printf("ERROR: PEM import failed (status=%d)\n", status);
        return 1;
    }

    QUDO_KEM_cleanup();

    printf("\n===========================================\n");
    printf("All DER/PEM operations completed successfully!\n");
    printf("===========================================\n");

    return 0;
}
