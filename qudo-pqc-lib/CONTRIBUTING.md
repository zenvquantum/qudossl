# Contributing

Engineering contribution guide for the QUDO PQC library (`libqudo-pqc`).

Changes that affect the FIPS 140-3 module build (`QUDO_FIPS_MODULE=ON`) must
keep its integrity region and self-tests intact — see
[FIPS discipline](#fips-discipline) below.

## Development workflow

1. Create a feature branch (`git checkout -b feature/my-change`)
2. Make your changes
3. Run `clang-format` on the C/C++ files you changed (the repository's
   [.clang-format](.clang-format) defines the style)
4. Run the suite (`ctest --output-on-failure`, and the FIPS build — see below)
5. Open a pull request for review

The pre-commit hook runs `clang-format --dry-run --Werror` on every
project-owned `.c`/`.h` file under `src/`, `include/`, `tests/`, `tools/` and
the `qudo-{mlkem,mldsa,slhdsa}/{src,include}` directories (vendored `*-native`
code excluded), not only staged files. It is skipped if `clang-format` is not
installed. `./run_all_tests.sh --full` adds `cppcheck`, `clang-tidy` and a
clang-format check (top-level `src/` and `include/` only).

For the full developer workflow — build/test loop, FIPS-module build constraints,
debugging, and updating the vendored `*-native` upstreams — see the
[Development Guide](docs/development/DEVELOPMENT.md).

## Requirements

- All code must be C99 compliant
- Cross-platform: Linux, macOS, Windows (MSVC + MinGW)
- No VLAs (Variable Length Arrays) — MSVC does not support them
- All cryptographic functions must have self-tests
- All sensitive data must be zeroized after use (`qudo_secure_clear` / `qudo_cleanse`)
- No POSIX-only or MSVC-only functions without platform guards

## Code Style

- Public API: `QUDO_KEM_*` / `QUDO_MLDSA_*` / `QUDO_SLHDSA_*` (uppercase)
- Internal functions: `qudo_*` (lowercase)
- Constants: `QUDO_KEM_SUCCESS`, `QUDO_ERR_*`
- New internal symbols stay hidden (not added to `config/libqudo-pqc.map`)
- Comments reference FIPS/NIST standards only (FIPS 203, FIPS 204, FIPS 205)
- Every source file carries an SPDX license header

## Testing

Every change must:

- Build on all platforms (check CI results)
- Pass the full CTest suite in both standard and FIPS builds
  (`-DQUDO_FIPS_MODULE=ON`)
- Include tests for new functionality
- For algorithm changes, pass the NIST ACVP vectors (`bash acvp/run_acvp.sh`)

See the [Testing Guide](docs/development/TESTING.md).

## FIPS discipline

- **Do not** enable LTO or `-ffunction-sections`/`-fdata-sections` for
  `QUDO_FIPS_MODULE=ON` builds — they break the contiguous-`.text` integrity
  region (the build enforces this).
- Any change that alters the module binary requires re-finalising the integrity
  HMAC (`qudo_fipsinstall -embed`, then re-codesign on macOS).
- Changes must keep POST, CAST, and PCT passing without weakening or bypassing
  any self-test.
- Adding or removing an algorithm or parameter set requires matching self-test,
  ACVP and documentation updates (see the [Development Guide](docs/development/DEVELOPMENT.md)).
- Vendored `*-native` upstreams are not edited in-tree; they are updated by
  importing a pinned upstream commit.

## Security

Report security vulnerabilities through the channel in [SECURITY.md](SECURITY.md)
— do not file them in the normal issue tracker.

## License

By contributing, you agree that your contributions are licensed under the same
terms as the project (Apache-2.0 AND MIT), and that any third-party code is
recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
