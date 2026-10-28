/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mldsa_config.h"
#include "mldsa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            failures++;                         \
        }                                       \
    } while (0)

static void test_default(void)
{
    mldsa_config_t *c = QUDO_MLDSA_config_default();
    CHECK(c != NULL, "default returned NULL");
    if (!c)
        return;
    CHECK(c->default_level == QUDO_MLDSA_65, "default level != 65");
    CHECK(c->enable_44 == 1, "default enable_44");
    CHECK(c->enable_65 == 1, "default enable_65");
    CHECK(c->enable_87 == 1, "default enable_87");
    CHECK(c->runtime_cpu_detect == 1, "default runtime_cpu_detect");
    CHECK(c->thread_safe == 1, "default thread_safe");
    QUDO_MLDSA_config_free(c);
}

static void test_free_null(void)
{
    QUDO_MLDSA_config_free(NULL);
}

static void test_validate(void)
{
    CHECK(QUDO_MLDSA_config_validate(NULL) == QUDO_MLDSA_ERROR_NULL_PTR,
          "validate(NULL)");

    mldsa_config_t *c = QUDO_MLDSA_config_default();
    CHECK(c != NULL, "default for validate");
    CHECK(QUDO_MLDSA_config_validate(c) == QUDO_MLDSA_SUCCESS,
          "validate(default)");

    c->enable_44 = c->enable_65 = c->enable_87 = 0;
    CHECK(QUDO_MLDSA_config_validate(c) == QUDO_MLDSA_ERROR_INVALID_ARG,
          "validate(no-levels)");

    c->enable_65 = 1;
    CHECK(QUDO_MLDSA_config_validate(c) == QUDO_MLDSA_SUCCESS,
          "validate(one-level)");

    QUDO_MLDSA_config_free(c);
}

static void test_apply(void)
{
    CHECK(QUDO_MLDSA_config_apply(NULL) == QUDO_MLDSA_ERROR_INVALID_ARG,
          "apply(NULL)");

    mldsa_config_t *c = QUDO_MLDSA_config_default();
    CHECK(QUDO_MLDSA_config_apply(c) == QUDO_MLDSA_SUCCESS, "apply(default)");

    c->enable_44 = c->enable_65 = c->enable_87 = 0;
    CHECK(QUDO_MLDSA_config_apply(c) == QUDO_MLDSA_ERROR_INVALID_ARG,
          "apply(invalid)");

    QUDO_MLDSA_config_free(c);
}

static void test_save_errors(void)
{
    mldsa_config_t *c = QUDO_MLDSA_config_default();
    CHECK(QUDO_MLDSA_config_save(NULL, "x.ini") == QUDO_MLDSA_ERROR_NULL_PTR,
          "save(NULL,_)");
    CHECK(QUDO_MLDSA_config_save(c, NULL) == QUDO_MLDSA_ERROR_NULL_PTR,
          "save(_,NULL)");
    CHECK(QUDO_MLDSA_config_save(c, "/proc/self/no/such/path/to/write")
              == QUDO_MLDSA_ERROR_FILE_IO,
          "save(_,unwritable)");
    QUDO_MLDSA_config_free(c);
}

static void test_load_save_roundtrip(void)
{
    const char *path = "mldsa_config_test_tmp.ini";
    mldsa_config_t *orig = QUDO_MLDSA_config_default();
    orig->enable_44 = 0;
    orig->enable_65 = 1;
    orig->enable_87 = 1;
    orig->use_avx2 = 1;
    orig->use_neon = 0;
    orig->deterministic = 1;
    orig->enable_context = 0;

    CHECK(QUDO_MLDSA_config_save(orig, path) == QUDO_MLDSA_SUCCESS, "save ok");

    mldsa_config_t *loaded = QUDO_MLDSA_config_load(path);
    CHECK(loaded != NULL, "load returned NULL");
    if (loaded) {
        CHECK(loaded->enable_44 == 0, "roundtrip enable_44");
        CHECK(loaded->enable_65 == 1, "roundtrip enable_65");
        CHECK(loaded->enable_87 == 1, "roundtrip enable_87");
        CHECK(loaded->use_avx2 == 1, "roundtrip use_avx2");
        CHECK(loaded->use_neon == 0, "roundtrip use_neon");
        CHECK(loaded->deterministic == 1, "roundtrip deterministic");
        CHECK(loaded->enable_context == 0, "roundtrip enable_context");
        QUDO_MLDSA_config_free(loaded);
    }
    remove(path);
    QUDO_MLDSA_config_free(orig);
}

static void test_load_null(void)
{
    mldsa_config_t *c = QUDO_MLDSA_config_load(NULL);
    CHECK(c != NULL, "load(NULL) returns default");
    if (c) {
        CHECK(c->enable_44 == 1 && c->enable_65 == 1 && c->enable_87 == 1,
              "load(NULL) has default flags");
        QUDO_MLDSA_config_free(c);
    }
}

static void test_load_missing(void)
{
    mldsa_config_t *c
        = QUDO_MLDSA_config_load("/tmp/__qudo_mldsa_no_such_file_abc.ini");
    CHECK(c != NULL, "load(missing) returns default");
    if (c) {
        CHECK(c->enable_44 == 1 && c->enable_65 == 1 && c->enable_87 == 1,
              "load(missing) has default flags");
        QUDO_MLDSA_config_free(c);
    }
}

static void test_load_comments_and_sections(void)
{
    const char *path = "mldsa_config_test_comments.ini";
    FILE *fp = fopen(path, "w");
    if (!fp)
        return;
    fprintf(fp, "# top-level comment\n");
    fprintf(fp, "; semicolon comment\n");
    fprintf(fp, "\n");
    fprintf(fp, "[security_levels]\n");
    fprintf(fp, "enable_44 = false\n");
    fprintf(fp, "enable_65 = 1\n");
    fprintf(fp, "enable_87 = true\n");
    fprintf(fp, "[optimizations]\n");
    fprintf(fp, "use_avx2 = 0\n");
    fprintf(fp, "use_neon = false\n");
    fprintf(fp, "[algorithm]\n");
    fprintf(fp, "deterministic = true\n");
    fprintf(fp, "enable_context = 0\n");
    fprintf(fp, "unknown_key = whatever\n");
    fclose(fp);

    mldsa_config_t *c = QUDO_MLDSA_config_load(path);
    CHECK(c != NULL, "load comments");
    if (c) {
        CHECK(c->enable_44 == 0, "comments enable_44 false");
        CHECK(c->enable_65 == 1, "comments enable_65 1");
        CHECK(c->enable_87 == 1, "comments enable_87 true");
        CHECK(c->use_avx2 == 0, "comments use_avx2 0");
        CHECK(c->use_neon == 0, "comments use_neon false");
        CHECK(c->deterministic == 1, "comments deterministic true");
        CHECK(c->enable_context == 0, "comments enable_context 0");
        QUDO_MLDSA_config_free(c);
    }
    remove(path);
}

int main(void)
{
    test_default();
    test_free_null();
    test_validate();
    test_apply();
    test_save_errors();
    test_load_null();
    test_load_missing();
    test_load_save_roundtrip();
    test_load_comments_and_sections();

    if (failures == 0) {
        printf("test_mldsa_config: ALL PASS\n");
        return 0;
    }
    printf("test_mldsa_config: %d FAIL\n", failures);
    return 1;
}
