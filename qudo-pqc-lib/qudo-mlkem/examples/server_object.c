/* SPDX-License-Identifier: Apache-2.0 AND MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
    typedef int socklen_t;
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

#include "mlkem_wrapper.h"
#include "common_network.h"

int main(int argc, char *argv[]) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    const char *algorithm = QUDO_KEM_alg_mlkem_768;
    QUDO_KEM *kem = NULL;

    if (argc > 1) {
        if (strcmp(argv[1], "512") == 0) algorithm = QUDO_KEM_alg_mlkem_512;
        else if (strcmp(argv[1], "768") == 0) algorithm = QUDO_KEM_alg_mlkem_768;
        else if (strcmp(argv[1], "1024") == 0) algorithm = QUDO_KEM_alg_mlkem_1024;
        else {
            fprintf(stderr, "Usage: %s [512|768|1024]\n", argv[0]);
            return 1;
        }
    }

    printf("==================================================\n");
    printf("ML-KEM Server - Object API\n");
    printf("==================================================\n\n");

    printf("[INIT] Creating QUDO_KEM object...\n");
    kem = QUDO_KEM_new(algorithm);
    if (!kem) {
        fprintf(stderr, "ERROR: Failed to create QUDO_KEM object for %s\n", algorithm);
        return 1;
    }
    printf("  Library version: %s\n", QUDO_KEM_get_version());
    printf("  Platform: %s (%s)\n", QUDO_KEM_get_platform(), QUDO_KEM_get_architecture());

    printf("  Algorithm:     %s\n", kem->algorithm_name);
    printf("  NIST Level:    %d\n", kem->claimed_nist_level);
    printf("  IND-CCA2:      %s\n", kem->ind_cca ? "Yes" : "No");
    printf("  Public key:    %zu bytes\n", kem->length_public_key);
    printf("  Secret key:    %zu bytes\n", kem->length_secret_key);
    printf("  Ciphertext:    %zu bytes\n", kem->length_ciphertext);
    printf("  Shared secret: %zu bytes\n\n", kem->length_shared_secret);

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !shared_secret) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        QUDO_KEM_free(kem);
        return 1;
    }

    printf("[1] Generating ML-KEM keypair (Object API)...\n");

    QUDO_KEM_status_t status = QUDO_KEM_keypair(kem, public_key, secret_key);

    if (status != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "ERROR: Keypair generation failed (status=%d)\n", status);
        goto cleanup;
    }

    printf("  [OK] Keypair generated\n");
    print_hex("  Public key", public_key, kem->length_public_key);
    printf("\n");

    printf("[2] Setting up server socket...\n");
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("  ERROR: Socket creation failed");
        goto cleanup;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt))) {
        perror("  ERROR: Setsockopt failed");
        close(server_fd);
        goto cleanup;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("  ERROR: Bind failed");
        close(server_fd);
        goto cleanup;
    }

    if (listen(server_fd, 3) < 0) {
        perror("  ERROR: Listen failed");
        close(server_fd);
        goto cleanup;
    }

    printf("  [OK] Server listening on port %d\n\n", SERVER_PORT);

    printf("[3] Waiting for client connection...\n");
    if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("  ERROR: Accept failed");
        close(server_fd);
        goto cleanup;
    }
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("  [OK] Client connected from %s\n\n", client_ip);

    printf("[4] Sending public key to client...\n");
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE);
    if (bytes_read <= 0) {
        fprintf(stderr, "  ERROR: Failed to read request\n");
        close(client_fd);
        close(server_fd);
        goto cleanup;
    }
    buffer[bytes_read] = '\0';
    printf("  Received request: %s\n", buffer);

    if (send(client_fd, public_key, kem->length_public_key, 0) != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "  ERROR: Failed to send public key\n");
        close(client_fd);
        close(server_fd);
        goto cleanup;
    }
    printf("  [OK] Public key sent (%zu bytes)\n\n", kem->length_public_key);

    printf("[5] Receiving ciphertext from client...\n");
    bytes_read = read(client_fd, ciphertext, kem->length_ciphertext);
    if (bytes_read != (ssize_t)kem->length_ciphertext) {
        fprintf(stderr, "  ERROR: Expected %zu bytes, got %zd\n", kem->length_ciphertext, bytes_read);
        close(client_fd);
        close(server_fd);
        goto cleanup;
    }
    printf("  [OK] Ciphertext received (%zd bytes)\n", bytes_read);
    print_hex("  Ciphertext", ciphertext, kem->length_ciphertext);
    printf("\n");

    printf("[6] Decapsulating shared secret (Object API)...\n");

    status = QUDO_KEM_decaps(kem, shared_secret, ciphertext, secret_key);

    if (status != QUDO_KEM_SUCCESS) {
        fprintf(stderr, "  ERROR: Decapsulation failed (status=%d)\n", status);
        close(client_fd);
        close(server_fd);
        goto cleanup;
    }

    printf("  [OK] Decapsulation successful\n");
    print_hex("  Shared secret", shared_secret, kem->length_shared_secret);
    printf("\n");

    printf("[7] Receiving encrypted message...\n");
    uint8_t encrypted_msg[256];
    bytes_read = read(client_fd, encrypted_msg, sizeof(encrypted_msg));
    if (bytes_read > 0) {
        uint8_t decrypted_msg[256];
        xor_encrypt_decrypt(decrypted_msg, encrypted_msg, bytes_read, shared_secret, kem->length_shared_secret);
        decrypted_msg[bytes_read] = '\0';
        printf("  [OK] Decrypted message: \"%s\"\n\n", decrypted_msg);

        const char *response = "Hello from Server (ML-KEM secured - Object API)";
        uint8_t encrypted_response[256];
        size_t resp_len = strlen(response);
        xor_encrypt_decrypt(encrypted_response, (const uint8_t*)response, resp_len,
                          shared_secret, kem->length_shared_secret);
        send(client_fd, encrypted_response, resp_len, 0);
        printf("  [OK] Sent encrypted response\n");
    }

    printf("\n==================================================\n");
    printf("[OK] Key exchange complete - secure channel established!\n");
    printf("==================================================\n");

    close(client_fd);
    close(server_fd);

cleanup:
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret);
    QUDO_KEM_free(kem);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
