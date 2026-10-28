/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mlkem_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static QUDO_KEM_config_t default_config = {.default_level = QUDO_KEM_768,
                                           .enable_512 = 1,
                                           .enable_768 = 1,
                                           .enable_1024 = 1,
                                           .use_avx2 = 1,
                                           .use_neon = 1,
                                           .use_rvv = 0,
                                           .use_openssl = 1,
                                           .runtime_cpu_detect = 1,
                                           .replace_rsa = 0,
                                           .hybrid_mode = 0,
                                           .constant_time = 1,
                                           .secure_memory = 1,
                                           .memory_lock = 0,
                                           .verbose = 0,
                                           .log_to_file = 0,
#if defined(_WIN32)
                                           .log_file_path = "mlkem.log",
#else
                                           .log_file_path = "mlkem.log",
#endif
                                           .max_threads = 4,
                                           .thread_safe = 1};

QUDO_KEM_API QUDO_KEM_config_t *QUDO_KEM_config_default(void)
{
    QUDO_KEM_config_t *config
        = (QUDO_KEM_config_t *)malloc(sizeof(QUDO_KEM_config_t));
    if (config) {
        memcpy(config, &default_config, sizeof(QUDO_KEM_config_t));
    }
    return config;
}

QUDO_KEM_API QUDO_KEM_config_t *QUDO_KEM_config_load(const char *config_file)
{
    FILE *fp;
    char line[256];
    QUDO_KEM_config_t *config;

    if (!config_file) {
        return QUDO_KEM_config_default();
    }

    fp = fopen(config_file, "r");
    if (!fp) {
        return QUDO_KEM_config_default();
    }

    config = QUDO_KEM_config_default();
    if (!config) {
        fclose(fp);
        return NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *key, *value, *equals;

        if (line[0] == '#' || line[0] == ';' || line[0] == '\n') {
            continue;
        }

        equals = strchr(line, '=');
        if (!equals) {
            continue;
        }

        *equals = '\0';
        key = line;
        value = equals + 1;

        while (*key == ' ' || *key == '\t')
            key++;
        {
            char *key_end = equals - 1;
            while (key_end >= key && (*key_end == ' ' || *key_end == '\t')) {
                *key_end = '\0';
                key_end--;
            }
        }
        while (*value == ' ' || *value == '\t')
            value++;

        {
            size_t vlen = strlen(value);
            if (vlen > 0) {
                char *end = value + vlen - 1;
                while (end > value
                       && (*end == '\n' || *end == '\r' || *end == ' '
                           || *end == '\t')) {
                    *end = '\0';
                    end--;
                }
            }
        }

        if (strcmp(key, "enable_512") == 0) {
            config->enable_512
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enable_768") == 0) {
            config->enable_768
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enable_1024") == 0) {
            config->enable_1024
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "use_avx2") == 0) {
            config->use_avx2
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "use_neon") == 0) {
            config->use_neon
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        }
    }

    fclose(fp);
    return config;
}

QUDO_KEM_API int QUDO_KEM_config_save(const QUDO_KEM_config_t *config,
                                      const char *config_file)
{
    FILE *fp;

    if (!config || !config_file) {
        return QUDO_KEM_ERROR_NULL_PTR;
    }

    fp = fopen(config_file, "w");
    if (!fp) {
        return QUDO_KEM_ERROR_FILE_IO;
    }

    fprintf(fp, "# ML-KEM Configuration File\n");
    fprintf(fp, "# Auto-generated\n\n");

    fprintf(fp, "[security_levels]\n");
    fprintf(fp, "enable_512 = %s\n", config->enable_512 ? "true" : "false");
    fprintf(fp, "enable_768 = %s\n", config->enable_768 ? "true" : "false");
    fprintf(fp, "enable_1024 = %s\n\n", config->enable_1024 ? "true" : "false");

    fprintf(fp, "[optimizations]\n");
    fprintf(fp, "use_avx2 = %s\n", config->use_avx2 ? "true" : "false");
    fprintf(fp, "use_neon = %s\n", config->use_neon ? "true" : "false");

    fclose(fp);
    return QUDO_KEM_SUCCESS;
}

QUDO_KEM_API void QUDO_KEM_config_free(QUDO_KEM_config_t *config)
{
    if (config) {
        free(config);
    }
}

QUDO_KEM_API int QUDO_KEM_config_validate(const QUDO_KEM_config_t *config)
{
    if (!config) {
        return QUDO_KEM_ERROR_NULL_PTR;
    }

    if (!config->enable_512 && !config->enable_768 && !config->enable_1024) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    return QUDO_KEM_SUCCESS;
}

QUDO_KEM_API int QUDO_KEM_config_apply(const QUDO_KEM_config_t *config)
{
    if (QUDO_KEM_config_validate(config) != QUDO_KEM_SUCCESS) {
        return QUDO_KEM_ERROR_INVALID_ARG;
    }

    return QUDO_KEM_SUCCESS;
}
