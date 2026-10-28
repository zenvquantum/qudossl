# Contributing to QudoSSL

Thanks for helping. QudoSSL is an OpenSSL 3.5.7 fork that ships a FIPS 140-3
provider module, so a few rules here are stricter than in a typical project.
Please read them before opening a pull request.

## Reporting bugs and asking questions

- **Bugs and feature requests:** open a GitHub issue using the templates.
- **Security vulnerabilities:** do **not** open a public issue. Follow
  [SECURITY.md](SECURITY.md).
- **Bugs in upstream OpenSSL** that are not specific to QudoSSL belong with the
  [OpenSSL project](https://github.com/openssl/openssl/issues).

## Where changes go

| Area | Rule |
|---|---|
| `openssl/` | A git subtree of OpenSSL 3.5.7. CI (`upstream-parity`) permits modifications only to the ML-KEM / ML-DSA delegation seam (`crypto/ml_kem/`, `crypto/ml_dsa/`, `include/crypto/ml_dsa.h`), `Configure`, `VERSION.dat`, and the name strings in the four `providers/{base,deflt,legacy,null}prov.c`; it fails any other divergence from upstream, including added or removed files. Fix general OpenSSL bugs upstream. |
| `openssl/providers/fips.module.sources` | Any change to a file listed here changes the FIPS module. Expect extra review, and call it out in the PR description. |
| `qudo-pqc-lib/` | The PQC math library, vendored as a git subtree. Changes are made here by pull request; see [docs/vendored-versions.md](docs/vendored-versions.md). |
| `build/`, `ci/`, `demos/`, `docs/` | Ordinary review. |

## Development workflow

1. Fork and branch: `feat/<topic>` or `fix/<slug>`
   (see [docs/branching.md](docs/branching.md)).
2. Build and run the suite as described in the [README](README.md#test):

   ```sh
   make -C build all
   env -u OPENSSL_CONF -u OPENSSL_MODULES make -C build test
   ```

3. Run the boundary gates. They are fast and catch the mistakes that matter most:

   ```sh
   ci/check-boundary-symbols.sh
   ci/check-seeded-entrypoints.sh
   ci/check-mlkem-constructible.sh
   ```

4. Open a pull request. Fill in the template, including how you tested.

## Rules for code that touches PQC

- Delegated calls must use the **seeded** `qudo-pqc` entry points and pass
  randomness drawn from OpenSSL's DRBG. `ci/check-seeded-entrypoints.sh`
  enforces this.
- No second implementation of an approved primitive (AES, SHA, HMAC, DRBG) may
  enter the FIPS module. `ci/check-boundary-symbols.sh` enforces this.
- Zeroize secrets with `OPENSSL_cleanse`, never a plain `memset`.

## Licensing

QudoSSL is licensed under Apache-2.0. By submitting a contribution you agree it
is licensed under the same terms. Keep existing copyright and SPDX headers
intact, and add an SPDX header to new files.
