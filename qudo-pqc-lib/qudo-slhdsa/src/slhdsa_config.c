/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "slhdsa_config.h"
#include <string.h>

typedef struct {
    QUDO_SLHDSA_parameter_set_t param_set;
    const char *name;
    int nist_level;
    size_t pk_bytes;
    size_t sk_bytes;
    size_t sig_bytes;
} slhdsa_param_info_t;

static const slhdsa_param_info_t param_table[] = {
    {QUDO_SLHDSA_SHA2_128s, "SLH-DSA-SHA2-128s", 1, 32, 64, 7856},
    {QUDO_SLHDSA_SHA2_128f, "SLH-DSA-SHA2-128f", 1, 32, 64, 17088},
    {QUDO_SLHDSA_SHA2_192s, "SLH-DSA-SHA2-192s", 3, 48, 96, 16224},
    {QUDO_SLHDSA_SHA2_192f, "SLH-DSA-SHA2-192f", 3, 48, 96, 35664},
    {QUDO_SLHDSA_SHA2_256s, "SLH-DSA-SHA2-256s", 5, 64, 128, 29792},
    {QUDO_SLHDSA_SHA2_256f, "SLH-DSA-SHA2-256f", 5, 64, 128, 49856},
    {QUDO_SLHDSA_SHAKE_128s, "SLH-DSA-SHAKE-128s", 1, 32, 64, 7856},
    {QUDO_SLHDSA_SHAKE_128f, "SLH-DSA-SHAKE-128f", 1, 32, 64, 17088},
    {QUDO_SLHDSA_SHAKE_192s, "SLH-DSA-SHAKE-192s", 3, 48, 96, 16224},
    {QUDO_SLHDSA_SHAKE_192f, "SLH-DSA-SHAKE-192f", 3, 48, 96, 35664},
    {QUDO_SLHDSA_SHAKE_256s, "SLH-DSA-SHAKE-256s", 5, 64, 128, 29792},
    {QUDO_SLHDSA_SHAKE_256f, "SLH-DSA-SHAKE-256f", 5, 64, 128, 49856},
};

static const slhdsa_param_info_t *find_param(QUDO_SLHDSA_parameter_set_t ps)
{
    for (int i = 0; i < SLHDSA_NUM_PARAMETER_SETS; i++) {
        if (param_table[i].param_set == ps)
            return &param_table[i];
    }
    return NULL;
}

QUDO_SLHDSA_API const char *
slhdsa_get_algorithm_name(QUDO_SLHDSA_parameter_set_t param_set)
{
    const slhdsa_param_info_t *info = find_param(param_set);
    return info ? info->name : NULL;
}

QUDO_SLHDSA_API size_t
slhdsa_get_public_key_bytes(QUDO_SLHDSA_parameter_set_t param_set)
{
    const slhdsa_param_info_t *info = find_param(param_set);
    return info ? info->pk_bytes : 0;
}

QUDO_SLHDSA_API size_t
slhdsa_get_secret_key_bytes(QUDO_SLHDSA_parameter_set_t param_set)
{
    const slhdsa_param_info_t *info = find_param(param_set);
    return info ? info->sk_bytes : 0;
}

QUDO_SLHDSA_API size_t
slhdsa_get_signature_bytes(QUDO_SLHDSA_parameter_set_t param_set)
{
    const slhdsa_param_info_t *info = find_param(param_set);
    return info ? info->sig_bytes : 0;
}

QUDO_SLHDSA_API int slhdsa_get_nist_level(QUDO_SLHDSA_parameter_set_t param_set)
{
    const slhdsa_param_info_t *info = find_param(param_set);
    return info ? info->nist_level : 0;
}

QUDO_SLHDSA_API QUDO_SLHDSA_parameter_set_t
slhdsa_get_parameter_set(const char *algorithm_name)
{
    if (!algorithm_name)
        return 0;
    for (int i = 0; i < SLHDSA_NUM_PARAMETER_SETS; i++) {
        if (strcmp(param_table[i].name, algorithm_name) == 0)
            return param_table[i].param_set;
    }
    return 0;
}

#include <stdio.h>
#include <stdlib.h>

QUDO_SLHDSA_API slhdsa_config_t *QUDO_SLHDSA_config_default(void)
{
    slhdsa_config_t *config
        = (slhdsa_config_t *)malloc(sizeof(slhdsa_config_t));
    if (!config)
        return NULL;

    memset(config, 0, sizeof(slhdsa_config_t));

    config->enable_sha2_128s = 1;
    config->enable_sha2_128f = 1;
    config->enable_sha2_192s = 1;
    config->enable_sha2_192f = 1;
    config->enable_sha2_256s = 1;
    config->enable_sha2_256f = 1;
    config->enable_shake_128s = 1;
    config->enable_shake_128f = 1;
    config->enable_shake_192s = 1;
    config->enable_shake_192f = 1;
    config->enable_shake_256s = 1;
    config->enable_shake_256f = 1;

    config->use_avx2 = 1;
    config->use_neon = 1;
    config->secure_memory = 1;
    config->verbose = 0;

    return config;
}

static int parse_bool(const char *value)
{
    return (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
}

QUDO_SLHDSA_API slhdsa_config_t *
QUDO_SLHDSA_config_load(const char *config_file)
{
    FILE *fp;
    char line[512];
    slhdsa_config_t *config;

    if (!config_file) {
        return QUDO_SLHDSA_config_default();
    }

    fp = fopen(config_file, "r");
    if (!fp) {

        return QUDO_SLHDSA_config_default();
    }

    config = QUDO_SLHDSA_config_default();
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
            char *end = key + strlen(key) - 1;
            while (end > key && (*end == ' ' || *end == '\t')) {
                *end = '\0';
                end--;
            }
        }

        {
            char *end = value + strlen(value) - 1;
            while (end > value
                   && (*end == '\n' || *end == '\r' || *end == ' '
                       || *end == '\t')) {
                *end = '\0';
                end--;
            }
        }

        if (strcmp(key, "enable_sha2_128s") == 0) {
            config->enable_sha2_128s = parse_bool(value);
        } else if (strcmp(key, "enable_sha2_128f") == 0) {
            config->enable_sha2_128f = parse_bool(value);
        } else if (strcmp(key, "enable_sha2_192s") == 0) {
            config->enable_sha2_192s = parse_bool(value);
        } else if (strcmp(key, "enable_sha2_192f") == 0) {
            config->enable_sha2_192f = parse_bool(value);
        } else if (strcmp(key, "enable_sha2_256s") == 0) {
            config->enable_sha2_256s = parse_bool(value);
        } else if (strcmp(key, "enable_sha2_256f") == 0) {
            config->enable_sha2_256f = parse_bool(value);
        } else if (strcmp(key, "enable_shake_128s") == 0) {
            config->enable_shake_128s = parse_bool(value);
        } else if (strcmp(key, "enable_shake_128f") == 0) {
            config->enable_shake_128f = parse_bool(value);
        } else if (strcmp(key, "enable_shake_192s") == 0) {
            config->enable_shake_192s = parse_bool(value);
        } else if (strcmp(key, "enable_shake_192f") == 0) {
            config->enable_shake_192f = parse_bool(value);
        } else if (strcmp(key, "enable_shake_256s") == 0) {
            config->enable_shake_256s = parse_bool(value);
        } else if (strcmp(key, "enable_shake_256f") == 0) {
            config->enable_shake_256f = parse_bool(value);
        }

        else if (strcmp(key, "use_avx2") == 0) {
            config->use_avx2 = parse_bool(value);
        } else if (strcmp(key, "use_neon") == 0) {
            config->use_neon = parse_bool(value);
        }

        else if (strcmp(key, "secure_memory") == 0) {
            config->secure_memory = parse_bool(value);
        }

        else if (strcmp(key, "verbose") == 0) {
            config->verbose = parse_bool(value);
        } else if (strcmp(key, "log_file") == 0) {
            if (strlen(value) > 0
                && strlen(value) < sizeof(config->log_file_path)) {
                strncpy(config->log_file_path, value,
                        sizeof(config->log_file_path) - 1);
                config->log_file_path[sizeof(config->log_file_path) - 1] = '\0';
            }
        }
    }

    fclose(fp);
    return config;
}

QUDO_SLHDSA_API int QUDO_SLHDSA_config_save(const slhdsa_config_t *config,
                                            const char *config_file)
{
    FILE *fp;

    if (!config || !config_file) {
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    }

    fp = fopen(config_file, "w");
    if (!fp) {
        return QUDO_SLHDSA_ERROR_FILE_IO;
    }

    fprintf(fp, "; QUDO SLH-DSA Configuration File\n");
    fprintf(fp, "; Auto-generated by QUDO_SLHDSA_config_save\n\n");

    fprintf(fp, "[general]\n");
    fprintf(fp, "verbose = %d\n", config->verbose);
    fprintf(fp, "log_file = %s\n\n", config->log_file_path);

    fprintf(fp, "[parameter_sets]\n");
    fprintf(fp, "enable_sha2_128s = %s\n",
            config->enable_sha2_128s ? "true" : "false");
    fprintf(fp, "enable_sha2_128f = %s\n",
            config->enable_sha2_128f ? "true" : "false");
    fprintf(fp, "enable_sha2_192s = %s\n",
            config->enable_sha2_192s ? "true" : "false");
    fprintf(fp, "enable_sha2_192f = %s\n",
            config->enable_sha2_192f ? "true" : "false");
    fprintf(fp, "enable_sha2_256s = %s\n",
            config->enable_sha2_256s ? "true" : "false");
    fprintf(fp, "enable_sha2_256f = %s\n",
            config->enable_sha2_256f ? "true" : "false");
    fprintf(fp, "enable_shake_128s = %s\n",
            config->enable_shake_128s ? "true" : "false");
    fprintf(fp, "enable_shake_128f = %s\n",
            config->enable_shake_128f ? "true" : "false");
    fprintf(fp, "enable_shake_192s = %s\n",
            config->enable_shake_192s ? "true" : "false");
    fprintf(fp, "enable_shake_192f = %s\n",
            config->enable_shake_192f ? "true" : "false");
    fprintf(fp, "enable_shake_256s = %s\n",
            config->enable_shake_256s ? "true" : "false");
    fprintf(fp, "enable_shake_256f = %s\n\n",
            config->enable_shake_256f ? "true" : "false");

    fprintf(fp, "[performance]\n");
    fprintf(fp, "use_avx2 = %s\n", config->use_avx2 ? "true" : "false");
    fprintf(fp, "use_neon = %s\n\n", config->use_neon ? "true" : "false");

    fprintf(fp, "[security]\n");
    fprintf(fp, "secure_memory = %s\n",
            config->secure_memory ? "true" : "false");

    fclose(fp);
    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API void QUDO_SLHDSA_config_free(slhdsa_config_t *config)
{
    if (config != NULL) {
        memset(config, 0, sizeof(*config));
        free(config);
    }
}

QUDO_SLHDSA_API int QUDO_SLHDSA_config_validate(const slhdsa_config_t *config)
{
    if (!config)
        return QUDO_SLHDSA_ERROR_NULL_PTR;

    if (!config->enable_sha2_128s && !config->enable_sha2_128f
        && !config->enable_sha2_192s && !config->enable_sha2_192f
        && !config->enable_sha2_256s && !config->enable_sha2_256f
        && !config->enable_shake_128s && !config->enable_shake_128f
        && !config->enable_shake_192s && !config->enable_shake_192f
        && !config->enable_shake_256s && !config->enable_shake_256f) {
        return QUDO_SLHDSA_ERROR_INVALID_ARG;
    }

    return QUDO_SLHDSA_SUCCESS;
}

QUDO_SLHDSA_API int QUDO_SLHDSA_config_apply(const slhdsa_config_t *config)
{
    if (!config)
        return QUDO_SLHDSA_ERROR_NULL_PTR;
    return QUDO_SLHDSA_SUCCESS;
}
