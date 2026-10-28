# QUDO PQC Libraries Versioning Policy

## Scope

This policy covers the combined `libqudo-pqc` library and its three
in-tree sub-libraries (`qudo-mlkem`, `qudo-mldsa`, `qudo-slhdsa`). When
distributed individually, each sub-library carries its own version that
follows the rules below; when consumed via the combined `libqudo-pqc`
all three move together with the umbrella library's version. The current
combined library version is queryable at runtime via `qudo_pqc_version()`
(`include/qudo_pqc.h`).

## Semantic Versioning

All QUDO libraries (qudo-mlkem, qudo-mldsa, qudo-slhdsa) follow [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** version: Incompatible API changes (function signatures changed, types removed, behavior altered)
- **MINOR** version: Backward-compatible additions (new functions, new parameter sets, new features)
- **PATCH** version: Backward-compatible bug fixes (security patches, correctness fixes, performance improvements)

## API Stability Guarantee

The public API is stable within the same MAJOR version. Applications compiled against version 1.0.0 will continue to work with any 1.x.y release without source changes.

Public API surface includes:
- All functions declared with `QUDO_KEM_API`, `QUDO_MLDSA_API`, or `QUDO_SLHDSA_API`
- All types and constants in public headers (`*_types.h`, `*_wrapper.h`, `*_version.h`, `*_error.h`, `*_config.h`)
- All error codes and their numeric values

Internal functions (prefixed with `qudo_kem_`, `qudo_mldsa_`, `qudo_slhdsa_` in lowercase) are not part of the stable API.

## ABI Policy

Shared library SONAME tracks the MAJOR version number:

- `libqudo-pqc.so.1` for all 1.x.y releases (the installed combined library)
- `libqudo-mlkem.so.1`, `libqudo-mldsa.so.1`, `libqudo-slhdsa.so.1` when a
  sub-library is built individually

SONAME is bumped only on breaking ABI changes (MAJOR version increment). MINOR and PATCH releases are ABI-compatible drop-in replacements.

## Symbol Versioning

In the combined `libqudo-pqc.so` all public symbols are tagged `LIBQUDOPQC_1.0` (`config/libqudo-pqc.map`). Individually built sub-libraries use the per-sub-library map files (`qudo-*/config/libqudo-*.map`):

- `LIBQUDOPQC_1.0` -- all symbols exported by the combined `libqudo-pqc` 1.0 release (`config/libqudo-pqc.map`)
- `QUDO_KEM_1.0` -- all symbols from the 1.0 release
- `QUDO_MLDSA_1.0` -- all symbols from the 1.0 release
- `QUDO_SLHDSA_1.0` -- all symbols from the 1.0 release

New symbols added in future MINOR releases will receive new version tags (e.g., `LIBQUDOPQC_1.1`, `QUDO_KEM_1.1`). Internal symbols are hidden (`local: *`).

## Deprecation Process

1. **Mark**: In a MINOR release, deprecated functions are annotated with compiler warnings and documented in release notes.
2. **Grace period**: Deprecated functions remain functional for at least one full MINOR release cycle.
3. **Remove**: Deprecated functions are removed in the next MAJOR release.

## Compile-Time Version Checking

Use the `VERSION_AT_LEAST` macro to conditionally compile against specific versions:

```c
#include "mlkem_version.h"

#if QUDO_KEM_VERSION_AT_LEAST(1, 1, 0)
    /* Use feature added in 1.1.0 */
#else
    /* Fallback for older versions */
#endif
```

Equivalent macros exist for all libraries:
- `QUDO_KEM_VERSION_AT_LEAST(major, minor, patch)`
- `QUDO_MLDSA_VERSION_AT_LEAST(major, minor, patch)`
- `QUDO_SLHDSA_VERSION_AT_LEAST(major, minor, patch)`

## Runtime Version Checking

Query the library version at runtime to verify compatibility:

```c
#include "mlkem_version.h"

/* Check API compatibility */
if (QUDO_KEM_api_version() < QUDO_KEM_API_VERSION_MIN) {
    fprintf(stderr, "Incompatible library version\n");
    return -1;
}

/* Query version components */
printf("qudo-mlkem %d.%d.%d\n",
       QUDO_KEM_version_major(),
       QUDO_KEM_version_minor(),
       QUDO_KEM_version_patch());
```

Equivalent functions exist for all libraries:
- `QUDO_KEM_api_version()`, `QUDO_KEM_version_major()`, `QUDO_KEM_version_minor()`, `QUDO_KEM_version_patch()`
- `QUDO_MLDSA_api_version()`, `QUDO_MLDSA_version_major()`, `QUDO_MLDSA_version_minor()`, `QUDO_MLDSA_version_patch()`
- `QUDO_SLHDSA_api_version()`, `QUDO_SLHDSA_version_major()`, `QUDO_SLHDSA_version_minor()`, `QUDO_SLHDSA_version_patch()`

## Version Files

| Library | Version Header | Version Source | Symbol Map |
|---------|---------------|----------------|------------|
| qudo-mlkem | `qudo-mlkem/include/mlkem_version.h` | `qudo-mlkem/src/mlkem_version.c` | `qudo-mlkem/config/libqudo-mlkem.map` |
| qudo-mldsa | `qudo-mldsa/include/mldsa_version.h` | `qudo-mldsa/src/mldsa_version.c` | `qudo-mldsa/config/libqudo-mldsa.map` |
| qudo-slhdsa | `qudo-slhdsa/include/slhdsa_version.h` | `qudo-slhdsa/src/slhdsa_version.c` | `qudo-slhdsa/config/libqudo-slhdsa.map` |
