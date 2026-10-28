# Third-Party Notices

`libqudo-pqc` is distributed under **Apache-2.0 AND MIT** (see [LICENSE](LICENSE)).
It includes third-party components vendored in-tree. Their copyright notices and
license terms are reproduced below; the authoritative, full license text for each
ships alongside the code at the path indicated.

The QUDO wrapper layer (`src/`, `include/`, `qudo-*/src`, `qudo-*/include`) is
QUDO-authored; the components below provide the underlying lattice/hash
mathematics. QUDO additions inside the vendored trees are the
`qudo_runtime_dispatch/` directories, `qudo-slhdsa/slhdsa-native/sha2_256_shani.c`
(derived from SHA-Intrinsics, section 4), and the `qudo_` prefix on the
`SHA3_absorb`/`SHA3_squeeze` symbols in the OpenSSL-generated
`qudo-slhdsa/slhdsa-native/keccak1600-x86_64*.s` (section 5).

---

## 1. mlkem-native (ML-KEM / FIPS 203)

- **Path:** `qudo-mlkem/mlkem-native/`
- **Full license:** `qudo-mlkem/mlkem-native/LICENSE`
- **Origin:** a fork of the public-domain Kyber reference implementation
  (https://github.com/pq-crystals/kyber).
- **Upstream:** https://github.com/pq-code-package/mlkem-native, commit `183f2809` (main).
- **License (vendored code in `mlkem/`):** Apache-2.0 **OR** ISC **OR** MIT (recipient's choice).
- **Copyright:**
  - Copyright (c) The mlkem-native project authors
  - Copyright (c) 2020 Dougall Johnson
  - Copyright (c) 2022 Arm Limited
- **Note:** upstream test-only code is not vendored.

## 2. mldsa-native (ML-DSA / FIPS 204)

- **Path:** `qudo-mldsa/mldsa-native/`
- **Full license:** `qudo-mldsa/mldsa-native/LICENSE`
- **Origin:** a fork of the public-domain Dilithium reference implementation
  (https://github.com/pq-crystals/dilithium).
- **Upstream:** https://github.com/pq-code-package/mldsa-native, commit `93a4fc74` (main).
- **License (new + derived files):** Apache-2.0 **OR** ISC **OR** MIT (recipient's choice).
- **Copyright:**
  - Copyright (c) The mldsa-native project authors
  - Copyright (c) The mlkem-native project authors
  - Copyright (c) 2020 Dougall Johnson
  - Copyright (c) 2022 Arm Limited
- **Note:** test-only code carries separate terms and is not part of the shipped library.

## 3. slhdsa-native / slhdsa-c (SLH-DSA / FIPS 205)

- **Path:** `qudo-slhdsa/slhdsa-native/`
- **Full license:** `qudo-slhdsa/slhdsa-native/LICENSE`
- **Origin:** the slhdsa-c project; originally written by
  Markku-Juhani O. Saarinen (2023–2025) and donated to the slhdsa-c project and
  derived projects.
- **License:** Apache-2.0 **OR** ISC **OR** MIT (recipient's choice).
- **Copyright:**
  - Copyright (c) The slhdsa-c project authors

## 4. SHA-Intrinsics (SHA-256 using Intel SHA extensions)

- **Path:** `qudo-slhdsa/slhdsa-native/sha2_256_shani.c`
- **Origin:** derived from the SHA-Intrinsics reference implementation
  (https://github.com/noloader/SHA-Intrinsics).
- **License:** Apache-2.0 OR ISC OR MIT (file header); derived from the
  public-domain SHA-Intrinsics reference.

## 5. OpenSSL Keccak-1600 assembly (x86-64)

- **Path:** `qudo-slhdsa/slhdsa-native/keccak1600-x86_64.s`,
  `qudo-slhdsa/slhdsa-native/keccak1600-x86_64-macho.s`
- **Origin:** generated from OpenSSL `crypto/sha/asm/keccak1600-x86_64.pl`
  (CRYPTOGAMS, written by Andy Polyakov); the Mach-O file is the same code with
  macOS assembler directives.
- **License:** Apache-2.0.
- **Copyright:**
  - Copyright 2017-2024 The OpenSSL Project Authors

---

## License texts

The complete text of every license referenced above is reproduced verbatim in
the corresponding `LICENSE` file under each component directory. Where a
component is offered under a choice of licenses ("A OR B OR C"), recipients of
`libqudo-pqc` may select any one of the offered licenses for that component.

This NOTICE is provided to satisfy the attribution requirements of the Apache
License 2.0 (§4(d)) and the reproduction-of-copyright requirements of the ISC
and MIT licenses. It does not modify any of the referenced licenses.
