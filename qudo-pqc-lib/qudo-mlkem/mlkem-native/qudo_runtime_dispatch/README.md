# Runtime CPU Dispatch

This directory contains additions to mlkem-native for runtime CPU feature dispatch.

## Purpose

Selects the best available implementation (AVX2, NEON, or portable C) at runtime based on CPU capabilities.

## Files

- `cpu_features.h` - CPU feature detection API
- `cpu_features.c` - Cross-platform CPU detection (x86_64, ARM64, Windows, Linux, macOS)
- `README.md` - This file

## Layout

This code is kept in its own directory, separate from the mlkem-native sources, so that the additions are clearly identifiable, mlkem-native can be updated without conflicts, and the feature can be enabled or disabled through CMake options.

## Integration

When `MLK_CONFIG_RUNTIME_DISPATCH=ON`:
1. This code is compiled into libmlkem_native.a
2. mlkem-native dispatch points call `mlk_cpu_has_extension()`
3. The wrapper calls `mlk_cpu_init()` once at startup
4. All variants (AVX2 + NEON + C) are included in one library

## Maintenance

- Keep in sync when updating mlkem-native
- Files in this directory do not modify the original mlkem-native sources
