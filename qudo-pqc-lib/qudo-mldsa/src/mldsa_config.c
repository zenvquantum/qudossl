/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/mldsa_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static mldsa_config_t default_config = {.default_level = QUDO_MLDSA_65,
                                        .enable_44 = 1,
                                        .enable_65 = 1,
                                        .enable_87 = 1,
                                        .use_avx2 = 1,
                                        .use_neon = 1,
                                        .runtime_cpu_detect = 1,
                                        .use_openssl = 1,
                                        .constant_time = 1,
                                        .secure_memory = 1,
                                        .memory_lock = 0,
                                        .deterministic = 0,
                                        .enable_context = 1,
                                        .verbose = 0,
                                        .enable_logging = 0,
#if defined(_WIN32)
                                        .log_file_path = "mldsa.log",
#else
                                        .log_file_path
                                        = "/var/log/mldsa/mldsa.log",
#endif
                                        .max_threads = 4,
                                        .thread_safe = 1};

QUDO_MLDSA_API const mldsa_config_t *mldsa_get_default_config(void)
{
    return &default_config;
}

QUDO_MLDSA_API const char *mldsa_get_version(void)
{
    return QUDO_MLDSA_VERSION_STRING;
}

QUDO_MLDSA_API const char *
mldsa_get_algorithm_name(QUDO_MLDSA_security_level_t level)
{
    switch (level) {
    case QUDO_MLDSA_44:
        return "ML-DSA-44";
    case QUDO_MLDSA_65:
        return "ML-DSA-65";
    case QUDO_MLDSA_87:
        return "ML-DSA-87";
    default:
        return "Unknown";
    }
}

QUDO_MLDSA_API size_t
mldsa_get_public_key_bytes(QUDO_MLDSA_security_level_t level)
{
    switch (level) {
    case QUDO_MLDSA_44:
        return ML_DSA_44_PUBLIC_KEY_BYTES;
    case QUDO_MLDSA_65:
        return ML_DSA_65_PUBLIC_KEY_BYTES;
    case QUDO_MLDSA_87:
        return ML_DSA_87_PUBLIC_KEY_BYTES;
    default:
        return 0;
    }
}

QUDO_MLDSA_API size_t
mldsa_get_secret_key_bytes(QUDO_MLDSA_security_level_t level)
{
    switch (level) {
    case QUDO_MLDSA_44:
        return ML_DSA_44_SECRET_KEY_BYTES;
    case QUDO_MLDSA_65:
        return ML_DSA_65_SECRET_KEY_BYTES;
    case QUDO_MLDSA_87:
        return ML_DSA_87_SECRET_KEY_BYTES;
    default:
        return 0;
    }
}

QUDO_MLDSA_API size_t
mldsa_get_signature_bytes(QUDO_MLDSA_security_level_t level)
{
    switch (level) {
    case QUDO_MLDSA_44:
        return ML_DSA_44_SIGNATURE_BYTES;
    case QUDO_MLDSA_65:
        return ML_DSA_65_SIGNATURE_BYTES;
    case QUDO_MLDSA_87:
        return ML_DSA_87_SIGNATURE_BYTES;
    default:
        return 0;
    }
}

QUDO_MLDSA_API mldsa_config_t *QUDO_MLDSA_config_default(void)
{
    mldsa_config_t *config = (mldsa_config_t *)malloc(sizeof(mldsa_config_t));
    if (config) {
        memcpy(config, &default_config, sizeof(mldsa_config_t));
    }
    return config;
}

QUDO_MLDSA_API mldsa_config_t *QUDO_MLDSA_config_load(const char *config_file)
{
    FILE *fp;
    char line[256];
    mldsa_config_t *config;

    if (!config_file) {
        return QUDO_MLDSA_config_default();
    }

    fp = fopen(config_file, "r");
    if (!fp) {

        return QUDO_MLDSA_config_default();
    }

    config = QUDO_MLDSA_config_default();
    if (!config) {
        fclose(fp);
        return NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *key, *value, *equals;

        if (line[0] == '#' || line[0] == ';' || line[0] == '\n') {
            continue;
        }

        if (line[0] == '[') {
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

        if (strcmp(key, "enable_44") == 0) {
            config->enable_44
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enable_65") == 0) {
            config->enable_65
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enable_87") == 0) {
            config->enable_87
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "use_avx2") == 0) {
            config->use_avx2
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "use_neon") == 0) {
            config->use_neon
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "deterministic") == 0) {
            config->deterministic
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enable_context") == 0) {
            config->enable_context
                = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        }
    }

    fclose(fp);
    return config;
}

QUDO_MLDSA_API int QUDO_MLDSA_config_save(const mldsa_config_t *config,
                                          const char *config_file)
{
    FILE *fp;

    if (!config || !config_file) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    fp = fopen(config_file, "w");
    if (!fp) {
        return QUDO_MLDSA_ERROR_FILE_IO;
    }

    fprintf(fp, "# ML-DSA Configuration File\n");
    fprintf(fp, "# Auto-generated\n\n");

    fprintf(fp, "[security_levels]\n");
    fprintf(fp, "enable_44 = %s\n", config->enable_44 ? "true" : "false");
    fprintf(fp, "enable_65 = %s\n", config->enable_65 ? "true" : "false");
    fprintf(fp, "enable_87 = %s\n\n", config->enable_87 ? "true" : "false");

    fprintf(fp, "[optimizations]\n");
    fprintf(fp, "use_avx2 = %s\n", config->use_avx2 ? "true" : "false");
    fprintf(fp, "use_neon = %s\n\n", config->use_neon ? "true" : "false");

    fprintf(fp, "[algorithm]\n");
    fprintf(fp, "deterministic = %s\n",
            config->deterministic ? "true" : "false");
    fprintf(fp, "enable_context = %s\n",
            config->enable_context ? "true" : "false");

    fclose(fp);
    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API void QUDO_MLDSA_config_free(mldsa_config_t *config)
{
    if (config) {
        free(config);
    }
}

QUDO_MLDSA_API int QUDO_MLDSA_config_validate(const mldsa_config_t *config)
{
    if (!config) {
        return QUDO_MLDSA_ERROR_NULL_PTR;
    }

    if (!config->enable_44 && !config->enable_65 && !config->enable_87) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return QUDO_MLDSA_SUCCESS;
}

QUDO_MLDSA_API int QUDO_MLDSA_config_apply(const mldsa_config_t *config)
{
    if (QUDO_MLDSA_config_validate(config) != QUDO_MLDSA_SUCCESS) {
        return QUDO_MLDSA_ERROR_INVALID_ARG;
    }

    return QUDO_MLDSA_SUCCESS;
}
