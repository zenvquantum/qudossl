/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#if defined(_MSC_VER)
#    pragma data_seg(".fips_hmac")
#endif

#if defined(__GNUC__) || defined(__clang__)
__attribute__((used, visibility("default")))
#endif
unsigned char qudo_fips_integrity_hmac[32]
    = {'Q', 'U', 'D',  'O',  '_',  'F',  'I',  'P',  'S',  '_', 'N',
       'O', 'T', '_',  'P',  'A',  'T',  'C',  'H',  'E',  'D', '_',
       '_', '_', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#if defined(_MSC_VER)
#    pragma data_seg()
#endif
