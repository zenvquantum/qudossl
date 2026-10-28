/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "../include/slhdsa_config.h"
#include "../include/slhdsa_wrapper.h"
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#    define SLHDSA_PLATFORM "Windows"
#    include <intrin.h>
#    include <windows.h>
#elif defined(__APPLE__) && defined(__MACH__)
#    define SLHDSA_PLATFORM "macOS"
#    include <sys/sysctl.h>
#    include <unistd.h>
#elif defined(__linux__)
#    define SLHDSA_PLATFORM "Linux"
#    include <unistd.h>
#    if defined(__aarch64__)
#        include <sys/auxv.h>
#    endif
#elif defined(__FreeBSD__)
#    define SLHDSA_PLATFORM "FreeBSD"
#    include <unistd.h>
#else
#    define SLHDSA_PLATFORM "Unknown"
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
#    define SLHDSA_ARCH        "x86_64"
#    define SLHDSA_ARCH_X86_64 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#    define SLHDSA_ARCH       "aarch64"
#    define SLHDSA_ARCH_ARM64 1
#elif defined(__riscv) && (__riscv_xlen == 64)
#    define SLHDSA_ARCH "riscv64"
#elif defined(__arm__) || defined(_M_ARM)
#    define SLHDSA_ARCH "arm"
#else
#    define SLHDSA_ARCH "unknown"
#endif

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_version(void)
{
    return QUDO_SLHDSA_VERSION_STRING;
}

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_platform(void)
{
    return SLHDSA_PLATFORM;
}

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_architecture(void)
{
    return SLHDSA_ARCH;
}

#ifdef SLHDSA_ARCH_X86_64

static void cpuid(int info[4], int function_id)
{
#    if defined(_WIN32)
    __cpuid(info, function_id);
#    elif defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("cpuid"
                         : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]),
                           "=d"(info[3])
                         : "a"(function_id), "c"(0));
#    else
    info[0] = info[1] = info[2] = info[3] = 0;
#    endif
}

QUDO_SLHDSA_API int QUDO_SLHDSA_has_avx2(void)
{
    int info[4];
    cpuid(info, 0);
    if (info[0] < 7) {
        return 0;
    }
    cpuid(info, 7);
    return (info[1] & (1 << 5)) != 0;
}

#else
QUDO_SLHDSA_API int QUDO_SLHDSA_has_avx2(void)
{
    return 0;
}
#endif

#ifdef SLHDSA_ARCH_ARM64

QUDO_SLHDSA_API int QUDO_SLHDSA_has_neon(void)
{
#    if defined(__APPLE__)
    return 1;
#    elif defined(__linux__)
    unsigned long hwcap = getauxval(AT_HWCAP);
    return (hwcap & HWCAP_ASIMD) != 0;
#    elif defined(_WIN32)
    return IsProcessorFeaturePresent(PF_ARM_NEON_INSTRUCTIONS_AVAILABLE);
#    else
    return 1;
#    endif
}

#else
QUDO_SLHDSA_API int QUDO_SLHDSA_has_neon(void)
{
    return 0;
}
#endif

QUDO_SLHDSA_API int QUDO_SLHDSA_get_cpu_count(void)
{
#if defined(_WIN32)
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return (int)sysinfo.dwNumberOfProcessors;
#elif defined(__linux__) || defined(__APPLE__)
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    return (nprocs > 0) ? (int)nprocs : 1;
#else
    return 1;
#endif
}

QUDO_SLHDSA_API const char *QUDO_SLHDSA_get_features(void)
{
    static char features[256] = {0};

    if (features[0] == '\0') {
        int offset = 0;
        int remaining = (int)sizeof(features);
        int n;

#ifdef QUDO_SLHDSA_USE_OPENSSL
        n = snprintf(features + offset, remaining, "OpenSSL ");
        if (n > 0 && n < remaining) {
            offset += n;
            remaining -= n;
        }
#endif

        if (QUDO_SLHDSA_has_avx2()) {
            n = snprintf(features + offset, remaining, "AVX2 ");
            if (n > 0 && n < remaining) {
                offset += n;
                remaining -= n;
            }
        }

        if (QUDO_SLHDSA_has_neon()) {
            n = snprintf(features + offset, remaining, "NEON ");
            if (n > 0 && n < remaining) {
                offset += n;
                remaining -= n;
            }
        }

        n = snprintf(features + offset, remaining, "SHA-NI ");
        if (n > 0 && n < remaining) {
            offset += n;
            remaining -= n;
        }

        if (offset > 0 && features[offset - 1] == ' ') {
            features[offset - 1] = '\0';
        }

        if (features[0] == '\0') {
            snprintf(features, sizeof(features), "None");
        }
    }

    return features;
}

QUDO_SLHDSA_API void QUDO_SLHDSA_print_system_info(void)
{
    printf("QUDO SLH-DSA Library Information:\n");
    printf("  Version: %s\n", QUDO_SLHDSA_get_version());
    printf("  Platform: %s\n", QUDO_SLHDSA_get_platform());
    printf("  Architecture: %s\n", QUDO_SLHDSA_get_architecture());
    printf("  CPU Cores: %d\n", QUDO_SLHDSA_get_cpu_count());
    printf("  Features: %s\n", QUDO_SLHDSA_get_features());
    printf("  AVX2 Support: %s\n", QUDO_SLHDSA_has_avx2() ? "Yes" : "No");
    printf("  NEON Support: %s\n", QUDO_SLHDSA_has_neon() ? "Yes" : "No");
}

QUDO_SLHDSA_API int QUDO_SLHDSA_is_platform_supported(void)
{
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    return 1;
#else
    return 0;
#endif
}

QUDO_SLHDSA_API size_t QUDO_SLHDSA_get_cache_line_size(void)
{
#if defined(_WIN32)
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer[256];
    DWORD length = sizeof(buffer);
    size_t i;

    if (GetLogicalProcessorInformation(buffer, &length)) {
        for (i = 0; i < length / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
             i++) {
            if (buffer[i].Relationship == RelationCache
                && buffer[i].Cache.Level == 1) {
                return buffer[i].Cache.LineSize;
            }
        }
    }
    return 64;

#elif defined(__linux__)
    long size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    return (size > 0) ? (size_t)size : 64;

#elif defined(__APPLE__)
    size_t line_size = 0;
    size_t sz = sizeof(line_size);
    if (sysctlbyname("hw.cachelinesize", &line_size, &sz, NULL, 0) == 0) {
        return line_size;
    }
    return 64;

#else
    return 64;
#endif
}
