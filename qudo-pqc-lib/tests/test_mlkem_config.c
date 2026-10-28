/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "mlkem_config.h"
#include "mlkem_types.h"
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
    QUDO_KEM_config_t *c = QUDO_KEM_config_default();
    CHECK(c != NULL, "default returned NULL");
    if (!c)
        return;
    CHECK(c->default_level == QUDO_KEM_768, "default level != 768");
    CHECK(c->enable_512 == 1, "default enable_512");
    CHECK(c->enable_768 == 1, "default enable_768");
    CHECK(c->enable_1024 == 1, "default enable_1024");
    CHECK(c->runtime_cpu_detect == 1, "default runtime_cpu_detect");
    CHECK(c->thread_safe == 1, "default thread_safe");
    QUDO_KEM_config_free(c);
}

static void test_free_null(void)
{
    QUDO_KEM_config_free(NULL);
}

static void test_validate(void)
{
    CHECK(QUDO_KEM_config_validate(NULL) == QUDO_KEM_ERROR_NULL_PTR,
          "validate(NULL)");

    QUDO_KEM_config_t *c = QUDO_KEM_config_default();
    CHECK(c != NULL, "default for validate");
    CHECK(QUDO_KEM_config_validate(c) == QUDO_KEM_SUCCESS, "validate(default)");

    c->enable_512 = 0;
    c->enable_768 = 0;
    c->enable_1024 = 0;
    CHECK(QUDO_KEM_config_validate(c) == QUDO_KEM_ERROR_INVALID_ARG,
          "validate(no-levels)");

    c->enable_512 = 1;
    CHECK(QUDO_KEM_config_validate(c) == QUDO_KEM_SUCCESS,
          "validate(one-level)");

    QUDO_KEM_config_free(c);
}

static void test_apply(void)
{
    CHECK(QUDO_KEM_config_apply(NULL) == QUDO_KEM_ERROR_INVALID_ARG,
          "apply(NULL)");

    QUDO_KEM_config_t *c = QUDO_KEM_config_default();
    CHECK(QUDO_KEM_config_apply(c) == QUDO_KEM_SUCCESS, "apply(default)");

    c->enable_512 = c->enable_768 = c->enable_1024 = 0;
    CHECK(QUDO_KEM_config_apply(c) == QUDO_KEM_ERROR_INVALID_ARG,
          "apply(invalid)");

    QUDO_KEM_config_free(c);
}

static void test_save_errors(void)
{
    QUDO_KEM_config_t *c = QUDO_KEM_config_default();
    CHECK(QUDO_KEM_config_save(NULL, "x.ini") == QUDO_KEM_ERROR_NULL_PTR,
          "save(NULL,_)");
    CHECK(QUDO_KEM_config_save(c, NULL) == QUDO_KEM_ERROR_NULL_PTR,
          "save(_,NULL)");
    CHECK(QUDO_KEM_config_save(c, "/proc/self/no/such/path/to/write")
              == QUDO_KEM_ERROR_FILE_IO,
          "save(_,unwritable)");
    QUDO_KEM_config_free(c);
}

static void test_load_save_roundtrip(void)
{
    const char *path = "mlkem_config_test_tmp.ini";
    QUDO_KEM_config_t *orig = QUDO_KEM_config_default();
    orig->enable_512 = 0;
    orig->enable_768 = 1;
    orig->enable_1024 = 1;
    orig->use_avx2 = 1;
    orig->use_neon = 0;

    CHECK(QUDO_KEM_config_save(orig, path) == QUDO_KEM_SUCCESS, "save ok");

    QUDO_KEM_config_t *loaded = QUDO_KEM_config_load(path);
    CHECK(loaded != NULL, "load returned NULL");
    if (loaded) {
        CHECK(loaded->enable_512 == 0, "roundtrip enable_512");
        CHECK(loaded->enable_768 == 1, "roundtrip enable_768");
        CHECK(loaded->enable_1024 == 1, "roundtrip enable_1024");
        CHECK(loaded->use_avx2 == 1, "roundtrip use_avx2");
        CHECK(loaded->use_neon == 0, "roundtrip use_neon");
        QUDO_KEM_config_free(loaded);
    }
    remove(path);
    QUDO_KEM_config_free(orig);
}

static void test_load_null(void)
{
    QUDO_KEM_config_t *c = QUDO_KEM_config_load(NULL);
    CHECK(c != NULL, "load(NULL) returns default");
    if (c) {
        CHECK(c->enable_512 == 1 && c->enable_768 == 1 && c->enable_1024 == 1,
              "load(NULL) has default flags");
        QUDO_KEM_config_free(c);
    }
}

static void test_load_missing(void)
{
    QUDO_KEM_config_t *c
        = QUDO_KEM_config_load("/tmp/__qudo_kem_no_such_file_abc.ini");
    CHECK(c != NULL, "load(missing) returns default");
    if (c) {
        CHECK(c->enable_512 == 1 && c->enable_768 == 1 && c->enable_1024 == 1,
              "load(missing) has default flags");
        QUDO_KEM_config_free(c);
    }
}

static void test_load_comments_and_sections(void)
{
    const char *path = "mlkem_config_test_comments.ini";
    FILE *fp = fopen(path, "w");
    if (!fp)
        return;
    fprintf(fp, "# top-level comment\n");
    fprintf(fp, "; semicolon comment\n");
    fprintf(fp, "\n");
    fprintf(fp, "[security_levels]\n");
    fprintf(fp, "enable_512 = false\n");
    fprintf(fp, "enable_768 = 1\n");
    fprintf(fp, "enable_1024 = true\n");
    fprintf(fp, "[optimizations]\n");
    fprintf(fp, "use_avx2 = 0\n");
    fprintf(fp, "use_neon = false\n");
    fprintf(fp, "unknown_key = whatever\n");
    fclose(fp);

    QUDO_KEM_config_t *c = QUDO_KEM_config_load(path);
    CHECK(c != NULL, "load comments");
    if (c) {
        CHECK(c->enable_512 == 0, "comments enable_512 false");
        CHECK(c->enable_768 == 1, "comments enable_768 1");
        CHECK(c->enable_1024 == 1, "comments enable_1024 true");
        CHECK(c->use_avx2 == 0, "comments use_avx2 0");
        CHECK(c->use_neon == 0, "comments use_neon false");
        QUDO_KEM_config_free(c);
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
        printf("test_mlkem_config: ALL PASS\n");
        return 0;
    }
    printf("test_mlkem_config: %d FAIL\n", failures);
    return 1;
}
