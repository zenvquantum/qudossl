// SPDX-License-Identifier: Apache-2.0
#include "cpu_features.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(MLD_CONFIG_RUNTIME_DISPATCH)
static unsigned int cpu_ext_data[MLD_CPU_EXT_COUNT] = {0};

#if defined(__x86_64__) || defined(_M_X64)
static void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
#if defined(_MSC_VER)
    int regs[4];
    __cpuidex(regs, leaf, 0);
    *eax = regs[0];
    *ebx = regs[1];
    *ecx = regs[2];
    *edx = regs[3];
#elif defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(0)
    );
#endif
}

static uint32_t xgetbv_eax(uint32_t xcr) {
#if defined(_MSC_VER)
    return (uint32_t)_xgetbv(xcr);
#elif defined(__GNUC__) || defined(__clang__)
    uint32_t eax, edx;
    __asm__ __volatile__(
        "xgetbv"
        : "=a"(eax), "=d"(edx)
        : "c"(xcr)
    );
    return eax;
#else
    (void)xcr;
    return 0;
#endif
}

#define MASK_XMM        (1 << 1)
#define MASK_YMM        (1 << 2)

static void detect_x86_64_features(void) {
    uint32_t eax1, ebx1, ecx1, edx1;
    uint32_t eax7, ebx7, ecx7, edx7;
    
    cpuid(1, &eax1, &ebx1, &ecx1, &edx1);
    if (eax1 == 0) {
        return;
    }
    
    cpuid(7, &eax7, &ebx7, &ecx7, &edx7);
    
    const unsigned int has_xsave = (ecx1 >> 26) & 1;
    const unsigned int has_osxsave = (ecx1 >> 27) & 1;
    const uint32_t xcr0_eax = (has_xsave && has_osxsave) ? xgetbv_eax(0) : 0;
    
    /* AVX2 is usable only if the OS saves both XMM and YMM state. */
    if ((xcr0_eax & (MASK_XMM | MASK_YMM)) == (MASK_XMM | MASK_YMM)) {
        const unsigned int has_avx2 = (ebx7 >> 5) & 1;
        if (has_avx2) {
            cpu_ext_data[MLD_CPU_EXT_AVX2] = 1;
        }
    }
}

#elif defined(__aarch64__) || defined(_M_ARM64)
#if defined(__APPLE__)
#include <sys/sysctl.h>

static unsigned int macos_feature_detection(const char *feature_name) {
    int p = 0;
    size_t p_len = sizeof(p);
    if (sysctlbyname(feature_name, &p, &p_len, NULL, 0) != 0) {
        return 0;
    }
    return (p != 0) ? 1 : 0;
}

static void detect_arm64_features(void) {
    if (macos_feature_detection("hw.optional.neon") || 
        macos_feature_detection("hw.optional.AdvSIMD")) {
        cpu_ext_data[MLD_CPU_EXT_NEON] = 1;
    }
}

#elif defined(_WIN32)
#include <windows.h>

static void detect_arm64_features(void) {
    BOOL neon = IsProcessorFeaturePresent(PF_ARM_VFP_32_REGISTERS_AVAILABLE);
    if (neon) {
        cpu_ext_data[MLD_CPU_EXT_NEON] = 1;
    }
}

#else
#include <sys/auxv.h>

#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1 << 1)
#endif

static void detect_arm64_features(void) {
    unsigned long hwcaps = getauxval(AT_HWCAP);
    
    if (hwcaps & HWCAP_ASIMD) {
        cpu_ext_data[MLD_CPU_EXT_NEON] = 1;
    }
}
#endif

#else
static void detect_cpu_features(void) {
}
#endif

static void set_available_cpu_extensions(void) {
    cpu_ext_data[MLD_CPU_EXT_INIT] = 1;
    
#if defined(__x86_64__) || defined(_M_X64)
    detect_x86_64_features();
#elif defined(__aarch64__) || defined(_M_ARM64)
    detect_arm64_features();
#endif
}

#endif /* MLD_CONFIG_RUNTIME_DISPATCH */

void mld_cpu_init(void) {
#if defined(MLD_CONFIG_RUNTIME_DISPATCH)
    if (cpu_ext_data[MLD_CPU_EXT_INIT] == 0) {
        set_available_cpu_extensions();
    }
#endif
}

int mld_cpu_has_extension(mld_cpu_ext ext) {
#if defined(MLD_CONFIG_RUNTIME_DISPATCH)
    if (cpu_ext_data[MLD_CPU_EXT_INIT] == 0) {
        mld_cpu_init();
    }
    
    if (ext > 0 && ext < MLD_CPU_EXT_COUNT) {
        return (int)cpu_ext_data[ext];
    }
#else
    (void)ext;
#endif
    return 0;
}

const char* mld_cpu_get_os(void) {
#if defined(_WIN32) || defined(_WIN64)
    return "Windows";
#elif defined(__APPLE__) && defined(__MACH__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#elif defined(__unix__) || defined(__unix)
    return "Unix";
#elif defined(__FreeBSD__)
    return "FreeBSD";
#elif defined(__OpenBSD__)
    return "OpenBSD";
#elif defined(__NetBSD__)
    return "NetBSD";
#else
    return "Unknown";
#endif
}

const char* mld_cpu_get_arch(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "ARM64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__arm__) || defined(_M_ARM)
    return "ARM32";
#elif defined(__riscv)
    return "RISC-V";
#else
    return "Unknown";
#endif
}

void mld_cpu_print_info(void) {
#if defined(MLD_CONFIG_RUNTIME_DISPATCH)
    if (cpu_ext_data[MLD_CPU_EXT_INIT] == 0) {
        mld_cpu_init();
    }
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         QUDO ML-DSA Runtime System Information              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("OS:                   %s\n", mld_cpu_get_os());
    printf("Architecture:         %s\n", mld_cpu_get_arch());
    
#if defined(__x86_64__) || defined(_M_X64)
    printf("AVX2 Detected:        %s\n", cpu_ext_data[MLD_CPU_EXT_AVX2] ? "YES" : "NO");
#ifdef QUDO_HAS_AVX2_VARIANT
    printf("AVX2 Variant Built:   YES\n");
#else
    printf("AVX2 Variant Built:   NO\n");
#endif
#ifdef QUDO_HAS_AVX2_VARIANT
    if (cpu_ext_data[MLD_CPU_EXT_AVX2]) {
        printf("Active Implementation: AVX2 Optimized\n");
    } else {
        printf("Active Implementation: Reference (Portable C)\n");
    }
#else
    printf("Active Implementation: Reference (Portable C)\n");
#endif
    
#elif defined(__aarch64__) || defined(_M_ARM64)
    printf("NEON Detected:        %s\n", cpu_ext_data[MLD_CPU_EXT_NEON] ? "YES" : "NO");
#ifdef QUDO_HAS_NEON_VARIANT
    printf("NEON Variant Built:   YES\n");
#else
    printf("NEON Variant Built:   NO\n");
#endif
#ifdef QUDO_HAS_NEON_VARIANT
    if (cpu_ext_data[MLD_CPU_EXT_NEON]) {
        printf("Active Implementation: NEON Optimized\n");
    } else {
        printf("Active Implementation: Reference (Portable C)\n");
    }
#else
    printf("Active Implementation: Reference (Portable C)\n");
#endif

#else
    printf("Active Implementation: Reference (Portable C)\n");
#endif
    printf("══════════════════════════════════════════════════════════════\n\n");
#else
    printf("Runtime dispatch disabled (static build)\n");
#endif
}
