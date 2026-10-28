/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "slhdsa_config.h"
#include "slhdsa_types.h"
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
    slhdsa_config_t *c = QUDO_SLHDSA_config_default();
    CHECK(c != NULL, "default not null");
    if (!c)
        return;
    CHECK(c->enable_sha2_128s == 1, "default sha2_128s");
    CHECK(c->enable_shake_256f == 1, "default shake_256f");
    CHECK(c->use_avx2 == 1, "default use_avx2");
    CHECK(c->secure_memory == 1, "default secure_memory");
    CHECK(c->verbose == 0, "default verbose");
    QUDO_SLHDSA_config_free(c);
}

static void test_free_null(void)
{
    QUDO_SLHDSA_config_free(NULL);
}

static void test_validate(void)
{
    CHECK(QUDO_SLHDSA_config_validate(NULL) == QUDO_SLHDSA_ERROR_NULL_PTR,
          "validate(NULL)");

    slhdsa_config_t *c = QUDO_SLHDSA_config_default();
    CHECK(QUDO_SLHDSA_config_validate(c) == QUDO_SLHDSA_SUCCESS,
          "validate(default)");

    c->enable_sha2_128s = 0;
    c->enable_sha2_128f = 0;
    c->enable_sha2_192s = 0;
    c->enable_sha2_192f = 0;
    c->enable_sha2_256s = 0;
    c->enable_sha2_256f = 0;
    c->enable_shake_128s = 0;
    c->enable_shake_128f = 0;
    c->enable_shake_192s = 0;
    c->enable_shake_192f = 0;
    c->enable_shake_256s = 0;
    c->enable_shake_256f = 0;
    CHECK(QUDO_SLHDSA_config_validate(c) == QUDO_SLHDSA_ERROR_INVALID_ARG,
          "validate(no-params)");

    c->enable_sha2_128s = 1;
    CHECK(QUDO_SLHDSA_config_validate(c) == QUDO_SLHDSA_SUCCESS,
          "validate(one-param)");

    QUDO_SLHDSA_config_free(c);
}

static void test_apply(void)
{
    CHECK(QUDO_SLHDSA_config_apply(NULL) == QUDO_SLHDSA_ERROR_NULL_PTR,
          "apply(NULL)");

    slhdsa_config_t *c = QUDO_SLHDSA_config_default();
    CHECK(QUDO_SLHDSA_config_apply(c) == QUDO_SLHDSA_SUCCESS, "apply(default)");
    QUDO_SLHDSA_config_free(c);
}

static void test_save_errors(void)
{
    slhdsa_config_t *c = QUDO_SLHDSA_config_default();
    CHECK(QUDO_SLHDSA_config_save(NULL, "x.ini") == QUDO_SLHDSA_ERROR_NULL_PTR,
          "save(NULL,_)");
    CHECK(QUDO_SLHDSA_config_save(c, NULL) == QUDO_SLHDSA_ERROR_NULL_PTR,
          "save(_,NULL)");
    CHECK(QUDO_SLHDSA_config_save(c, "/proc/self/no/such/path/to/write")
              == QUDO_SLHDSA_ERROR_FILE_IO,
          "save(_,unwritable)");
    QUDO_SLHDSA_config_free(c);
}

static void test_load_save_roundtrip(void)
{
    const char *path = "slhdsa_config_test_tmp.ini";
    slhdsa_config_t *orig = QUDO_SLHDSA_config_default();
    orig->enable_sha2_128s = 0;
    orig->enable_sha2_128f = 1;
    orig->enable_shake_256f = 0;
    orig->use_avx2 = 0;
    orig->use_neon = 1;
    orig->secure_memory = 0;

    CHECK(QUDO_SLHDSA_config_save(orig, path) == QUDO_SLHDSA_SUCCESS,
          "save ok");

    slhdsa_config_t *loaded = QUDO_SLHDSA_config_load(path);
    CHECK(loaded != NULL, "load not null");
    if (loaded) {
        CHECK(loaded->enable_sha2_128s == 0, "rt sha2_128s");
        CHECK(loaded->enable_sha2_128f == 1, "rt sha2_128f");
        CHECK(loaded->enable_shake_256f == 0, "rt shake_256f");
        CHECK(loaded->use_avx2 == 0, "rt use_avx2");
        CHECK(loaded->use_neon == 1, "rt use_neon");
        CHECK(loaded->secure_memory == 0, "rt secure_memory");
        QUDO_SLHDSA_config_free(loaded);
    }
    remove(path);
    QUDO_SLHDSA_config_free(orig);
}

static void test_load_null_and_missing(void)
{
    slhdsa_config_t *c = QUDO_SLHDSA_config_load(NULL);
    CHECK(c != NULL, "load(NULL) returns default");
    if (c) {
        CHECK(c->enable_sha2_128s == 1, "load(NULL) default");
        QUDO_SLHDSA_config_free(c);
    }

    c = QUDO_SLHDSA_config_load("/tmp/__qudo_slhdsa_no_such_file_xyz.ini");
    CHECK(c != NULL, "load(missing) returns default");
    if (c) {
        CHECK(c->enable_sha2_128s == 1, "load(missing) default");
        QUDO_SLHDSA_config_free(c);
    }
}

static void test_load_comments_and_log(void)
{
    const char *path = "slhdsa_config_test_comments.ini";
    FILE *fp = fopen(path, "w");
    if (!fp)
        return;
    fprintf(fp, "; sample SLH-DSA config\n");
    fprintf(fp, "# another comment\n");
    fprintf(fp, "\n");
    fprintf(fp, "[general]\n");
    fprintf(fp, "verbose = 1\n");
    fprintf(fp, "log_file = /tmp/slhdsa-test.log\n");
    fprintf(fp, "[parameter_sets]\n");
    fprintf(fp, "enable_sha2_128s = false\n");
    fprintf(fp, "enable_shake_192f = false\n");
    fprintf(fp, "[performance]\n");
    fprintf(fp, "use_avx2 = 0\n");
    fprintf(fp, "unknown_key = whatever\n");
    fclose(fp);

    slhdsa_config_t *c = QUDO_SLHDSA_config_load(path);
    CHECK(c != NULL, "load comments");
    if (c) {
        CHECK(c->verbose == 1, "comments verbose 1");
        CHECK(strcmp(c->log_file_path, "/tmp/slhdsa-test.log") == 0,
              "comments log_file");
        CHECK(c->enable_sha2_128s == 0, "comments sha2_128s false");
        CHECK(c->enable_shake_192f == 0, "comments shake_192f false");
        CHECK(c->use_avx2 == 0, "comments use_avx2 0");
        QUDO_SLHDSA_config_free(c);
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
    test_load_null_and_missing();
    test_load_save_roundtrip();
    test_load_comments_and_log();

    if (failures == 0) {
        printf("test_slhdsa_config: ALL PASS\n");
        return 0;
    }
    printf("test_slhdsa_config: %d FAIL\n", failures);
    return 1;
}
