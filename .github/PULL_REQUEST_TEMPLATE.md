## What this changes

A short description, and the issue it fixes (`Fixes #...`), if any.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Build, CI or demos
- [ ] Upstream subtree sync (`openssl/`)

## FIPS module impact

- [ ] This PR changes a file listed in `openssl/providers/fips.module.sources`
      (explain why below)
- [ ] This PR changes code under `openssl/` outside the ML-KEM / ML-DSA
      delegation seam (explain why below)

## How it was tested

Commands you ran and their results, for example:

- [ ] `make -C build all`
- [ ] `env -u OPENSSL_CONF -u OPENSSL_MODULES make -C build test`
- [ ] `ci/check-boundary-symbols.sh`, `ci/check-seeded-entrypoints.sh`
- [ ] `CHANGELOG.md` updated for user-visible changes
