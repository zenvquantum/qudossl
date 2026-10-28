/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#    include <windows.h>
#    define QUDO_PATH_SEP "\\"
#    define QUDO_PATH_MAX MAX_PATH
#else
#    include <dirent.h>
#    define QUDO_PATH_SEP "/"
#    ifdef PATH_MAX
#        define QUDO_PATH_MAX PATH_MAX
#    else
#        define QUDO_PATH_MAX 4096
#    endif
#endif

#ifndef S_ISDIR
#    define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int is_dir(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
        return 0;
    return S_ISDIR(st.st_mode);
}

static void replay_file(const char *path)
{
    FILE *f;
    long sz;
    unsigned char *buf;
    size_t got;

    f = fopen(path, "rb");
    if (f == NULL)
        return;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0
        || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return;
    }

    buf = (unsigned char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return;
    }
    got = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    printf("# %s\n", path);
    fflush(stdout);
    LLVMFuzzerTestOneInput(buf, got);
    free(buf);
}

static void replay_dir(const char *dir)
{
    char path[QUDO_PATH_MAX];

#ifdef _WIN32
    char pattern[QUDO_PATH_MAX];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    snprintf(pattern, sizeof(pattern), "%s%s*", dir, QUDO_PATH_SEP);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        snprintf(path, sizeof(path), "%s%s%s", dir, QUDO_PATH_SEP,
                 fd.cFileName);
        replay_file(path);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    struct dirent *e;

    if (d == NULL)
        return;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(path, sizeof(path), "%s%s%s", dir, QUDO_PATH_SEP, e->d_name);
        if (!is_dir(path))
            replay_file(path);
    }
    closedir(d);
#endif
}

int main(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (is_dir(argv[i]))
            replay_dir(argv[i]);
        else
            replay_file(argv[i]);
    }
    return 0;
}
