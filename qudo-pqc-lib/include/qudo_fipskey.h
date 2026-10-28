// SPDX-License-Identifier: Apache-2.0 AND MIT

#ifndef QUDO_FIPSKEY_H
#define QUDO_FIPSKEY_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define QUDO_FIPS_KEY_ELEMENTS                                              \
    0x98, 0x7d, 0x57, 0x22, 0x41, 0x23, 0xc8, 0x8f, 0xa3, 0x4e, 0x39, 0x09, \
        0xeb, 0x79, 0x05, 0x5b, 0x28, 0xe8, 0x03, 0x5c, 0x98, 0xa6, 0xda,   \
        0xad, 0xad, 0x24, 0xc6, 0xe8, 0x34, 0xd8, 0x3a, 0x85

#define QUDO_FIPS_KEY_STRING \
    "987d57224123c88fa34e3909eb79055b28e8035c98a6daadad24c6e834d83a85"

#define QUDO_FIPS_VENDOR "ZenV Quantum qudo-pqc FIPS module"

#ifdef __cplusplus
}
#endif

#endif
