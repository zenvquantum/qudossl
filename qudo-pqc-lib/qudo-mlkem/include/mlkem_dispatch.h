/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLKEM_DISPATCH_H
#define MLKEM_DISPATCH_H

#include <stdint.h>

#ifdef MLK_CONFIG_RUNTIME_DISPATCH

extern int mlkem_ref512_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_ref512_keypair_derand(uint8_t *pk, uint8_t *sk,
                                       const uint8_t *coins);
extern int mlkem_ref512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_ref512_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                   const uint8_t *coins);
extern int mlkem_ref512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int mlkem_ref512_check_pk(const uint8_t *pk);
extern int mlkem_ref512_check_sk(const uint8_t *sk);

#    ifdef QUDO_HAS_AVX2_VARIANT
extern int mlkem_avx2512_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_avx2512_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
extern int mlkem_avx2512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_avx2512_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                    const uint8_t *coins);
extern int mlkem_avx2512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int mlkem_avx2512_check_pk(const uint8_t *pk);
extern int mlkem_avx2512_check_sk(const uint8_t *sk);
#    endif

#    ifdef QUDO_HAS_NEON_VARIANT
extern int mlkem_neon512_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_neon512_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
extern int mlkem_neon512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_neon512_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                    const uint8_t *coins);
extern int mlkem_neon512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int mlkem_neon512_check_pk(const uint8_t *pk);
extern int mlkem_neon512_check_sk(const uint8_t *sk);
#    endif

extern int mlkem_ref768_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_ref768_keypair_derand(uint8_t *pk, uint8_t *sk,
                                       const uint8_t *coins);
extern int mlkem_ref768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_ref768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                   const uint8_t *coins);
extern int mlkem_ref768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int mlkem_ref768_check_pk(const uint8_t *pk);
extern int mlkem_ref768_check_sk(const uint8_t *sk);

#    ifdef QUDO_HAS_AVX2_VARIANT
extern int mlkem_avx2768_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_avx2768_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
extern int mlkem_avx2768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_avx2768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                    const uint8_t *coins);
extern int mlkem_avx2768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int mlkem_avx2768_check_pk(const uint8_t *pk);
extern int mlkem_avx2768_check_sk(const uint8_t *sk);
#    endif

#    ifdef QUDO_HAS_NEON_VARIANT
extern int mlkem_neon768_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_neon768_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
extern int mlkem_neon768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_neon768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                    const uint8_t *coins);
extern int mlkem_neon768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int mlkem_neon768_check_pk(const uint8_t *pk);
extern int mlkem_neon768_check_sk(const uint8_t *sk);
#    endif

extern int mlkem_ref1024_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_ref1024_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
extern int mlkem_ref1024_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_ref1024_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                    const uint8_t *coins);
extern int mlkem_ref1024_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int mlkem_ref1024_check_pk(const uint8_t *pk);
extern int mlkem_ref1024_check_sk(const uint8_t *sk);

#    ifdef QUDO_HAS_AVX2_VARIANT
extern int mlkem_avx21024_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_avx21024_keypair_derand(uint8_t *pk, uint8_t *sk,
                                         const uint8_t *coins);
extern int mlkem_avx21024_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_avx21024_enc_derand(uint8_t *ct, uint8_t *ss,
                                     const uint8_t *pk, const uint8_t *coins);
extern int mlkem_avx21024_dec(uint8_t *ss, const uint8_t *ct,
                              const uint8_t *sk);
extern int mlkem_avx21024_check_pk(const uint8_t *pk);
extern int mlkem_avx21024_check_sk(const uint8_t *sk);
#    endif

#    ifdef QUDO_HAS_NEON_VARIANT
extern int mlkem_neon1024_keypair(uint8_t *pk, uint8_t *sk);
extern int mlkem_neon1024_keypair_derand(uint8_t *pk, uint8_t *sk,
                                         const uint8_t *coins);
extern int mlkem_neon1024_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int mlkem_neon1024_enc_derand(uint8_t *ct, uint8_t *ss,
                                     const uint8_t *pk, const uint8_t *coins);
extern int mlkem_neon1024_dec(uint8_t *ss, const uint8_t *ct,
                              const uint8_t *sk);
extern int mlkem_neon1024_check_pk(const uint8_t *pk);
extern int mlkem_neon1024_check_sk(const uint8_t *sk);
#    endif

#endif
#endif
