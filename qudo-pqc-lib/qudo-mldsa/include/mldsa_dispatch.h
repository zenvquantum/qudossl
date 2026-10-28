/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#ifndef MLDSA_DISPATCH_H
#define MLDSA_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef MLDSA_DIST_BUILD

extern int mldsa_ref44_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_ref44_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                 size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                 const uint8_t *sk);
extern int mldsa_ref44_verify(const uint8_t *sig, size_t siglen,
                              const uint8_t *m, size_t mlen, const uint8_t *ctx,
                              size_t ctxlen, const uint8_t *pk);
extern int mldsa_ref44_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_ref44_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_ref44_keypair_internal(uint8_t *pk, uint8_t *sk,
                                        const uint8_t seed[32]);
extern int mldsa_ref44_signature_internal(uint8_t *sig, size_t *siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *pre, size_t prelen,
                                          const uint8_t rnd[32],
                                          const uint8_t *sk, int externalmu);
extern int mldsa_ref44_signature_extmu(uint8_t *sig, size_t *siglen,
                                       const uint8_t mu[64], const uint8_t *sk);
extern int mldsa_ref44_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                            size_t mlen, const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *sk);
extern int mldsa_ref44_verify_internal(const uint8_t *sig, size_t siglen,
                                       const uint8_t *m, size_t mlen,
                                       const uint8_t *pre, size_t prelen,
                                       const uint8_t *pk, int externalmu);
extern int mldsa_ref44_verify_extmu(const uint8_t *sig, size_t siglen,
                                    const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_ref44_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                            size_t smlen, const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *pk);

#    ifdef QUDO_HAS_AVX2_VARIANT
extern int mldsa_avx244_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_avx244_signature(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *sk);
extern int mldsa_avx244_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);
extern int mldsa_avx244_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_avx244_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_avx244_keypair_internal(uint8_t *pk, uint8_t *sk,
                                         const uint8_t seed[32]);
extern int mldsa_avx244_signature_internal(uint8_t *sig, size_t *siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t rnd[32],
                                           const uint8_t *sk, int externalmu);
extern int mldsa_avx244_signature_extmu(uint8_t *sig, size_t *siglen,
                                        const uint8_t mu[64],
                                        const uint8_t *sk);
extern int mldsa_avx244_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa_avx244_verify_internal(const uint8_t *sig, size_t siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *pre, size_t prelen,
                                        const uint8_t *pk, int externalmu);
extern int mldsa_avx244_verify_extmu(const uint8_t *sig, size_t siglen,
                                     const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_avx244_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                             size_t smlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *pk);
#    endif

#    ifdef QUDO_HAS_NEON_VARIANT
extern int mldsa_neon44_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_neon44_signature(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *sk);
extern int mldsa_neon44_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);
extern int mldsa_neon44_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_neon44_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_neon44_keypair_internal(uint8_t *pk, uint8_t *sk,
                                         const uint8_t seed[32]);
extern int mldsa_neon44_signature_internal(uint8_t *sig, size_t *siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t rnd[32],
                                           const uint8_t *sk, int externalmu);
extern int mldsa_neon44_signature_extmu(uint8_t *sig, size_t *siglen,
                                        const uint8_t mu[64],
                                        const uint8_t *sk);
extern int mldsa_neon44_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa_neon44_verify_internal(const uint8_t *sig, size_t siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *pre, size_t prelen,
                                        const uint8_t *pk, int externalmu);
extern int mldsa_neon44_verify_extmu(const uint8_t *sig, size_t siglen,
                                     const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_neon44_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                             size_t smlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *pk);
#    endif

extern int mldsa_ref65_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_ref65_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                 size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                 const uint8_t *sk);
extern int mldsa_ref65_verify(const uint8_t *sig, size_t siglen,
                              const uint8_t *m, size_t mlen, const uint8_t *ctx,
                              size_t ctxlen, const uint8_t *pk);
extern int mldsa_ref65_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_ref65_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_ref65_keypair_internal(uint8_t *pk, uint8_t *sk,
                                        const uint8_t seed[32]);
extern int mldsa_ref65_signature_internal(uint8_t *sig, size_t *siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *pre, size_t prelen,
                                          const uint8_t rnd[32],
                                          const uint8_t *sk, int externalmu);
extern int mldsa_ref65_signature_extmu(uint8_t *sig, size_t *siglen,
                                       const uint8_t mu[64], const uint8_t *sk);
extern int mldsa_ref65_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                            size_t mlen, const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *sk);
extern int mldsa_ref65_verify_internal(const uint8_t *sig, size_t siglen,
                                       const uint8_t *m, size_t mlen,
                                       const uint8_t *pre, size_t prelen,
                                       const uint8_t *pk, int externalmu);
extern int mldsa_ref65_verify_extmu(const uint8_t *sig, size_t siglen,
                                    const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_ref65_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                            size_t smlen, const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *pk);

#    ifdef QUDO_HAS_AVX2_VARIANT
extern int mldsa_avx265_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_avx265_signature(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *sk);
extern int mldsa_avx265_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);
extern int mldsa_avx265_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_avx265_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_avx265_keypair_internal(uint8_t *pk, uint8_t *sk,
                                         const uint8_t seed[32]);
extern int mldsa_avx265_signature_internal(uint8_t *sig, size_t *siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t rnd[32],
                                           const uint8_t *sk, int externalmu);
extern int mldsa_avx265_signature_extmu(uint8_t *sig, size_t *siglen,
                                        const uint8_t mu[64],
                                        const uint8_t *sk);
extern int mldsa_avx265_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa_avx265_verify_internal(const uint8_t *sig, size_t siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *pre, size_t prelen,
                                        const uint8_t *pk, int externalmu);
extern int mldsa_avx265_verify_extmu(const uint8_t *sig, size_t siglen,
                                     const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_avx265_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                             size_t smlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *pk);
#    endif

#    ifdef QUDO_HAS_NEON_VARIANT
extern int mldsa_neon65_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_neon65_signature(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *sk);
extern int mldsa_neon65_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);
extern int mldsa_neon65_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_neon65_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_neon65_keypair_internal(uint8_t *pk, uint8_t *sk,
                                         const uint8_t seed[32]);
extern int mldsa_neon65_signature_internal(uint8_t *sig, size_t *siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t rnd[32],
                                           const uint8_t *sk, int externalmu);
extern int mldsa_neon65_signature_extmu(uint8_t *sig, size_t *siglen,
                                        const uint8_t mu[64],
                                        const uint8_t *sk);
extern int mldsa_neon65_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa_neon65_verify_internal(const uint8_t *sig, size_t siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *pre, size_t prelen,
                                        const uint8_t *pk, int externalmu);
extern int mldsa_neon65_verify_extmu(const uint8_t *sig, size_t siglen,
                                     const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_neon65_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                             size_t smlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *pk);
#    endif

extern int mldsa_ref87_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_ref87_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                 size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                 const uint8_t *sk);
extern int mldsa_ref87_verify(const uint8_t *sig, size_t siglen,
                              const uint8_t *m, size_t mlen, const uint8_t *ctx,
                              size_t ctxlen, const uint8_t *pk);
extern int mldsa_ref87_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_ref87_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_ref87_keypair_internal(uint8_t *pk, uint8_t *sk,
                                        const uint8_t seed[32]);
extern int mldsa_ref87_signature_internal(uint8_t *sig, size_t *siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *pre, size_t prelen,
                                          const uint8_t rnd[32],
                                          const uint8_t *sk, int externalmu);
extern int mldsa_ref87_signature_extmu(uint8_t *sig, size_t *siglen,
                                       const uint8_t mu[64], const uint8_t *sk);
extern int mldsa_ref87_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                            size_t mlen, const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *sk);
extern int mldsa_ref87_verify_internal(const uint8_t *sig, size_t siglen,
                                       const uint8_t *m, size_t mlen,
                                       const uint8_t *pre, size_t prelen,
                                       const uint8_t *pk, int externalmu);
extern int mldsa_ref87_verify_extmu(const uint8_t *sig, size_t siglen,
                                    const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_ref87_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                            size_t smlen, const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *pk);

#    ifdef QUDO_HAS_AVX2_VARIANT
extern int mldsa_avx287_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_avx287_signature(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *sk);
extern int mldsa_avx287_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);
extern int mldsa_avx287_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_avx287_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_avx287_keypair_internal(uint8_t *pk, uint8_t *sk,
                                         const uint8_t seed[32]);
extern int mldsa_avx287_signature_internal(uint8_t *sig, size_t *siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t rnd[32],
                                           const uint8_t *sk, int externalmu);
extern int mldsa_avx287_signature_extmu(uint8_t *sig, size_t *siglen,
                                        const uint8_t mu[64],
                                        const uint8_t *sk);
extern int mldsa_avx287_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa_avx287_verify_internal(const uint8_t *sig, size_t siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *pre, size_t prelen,
                                        const uint8_t *pk, int externalmu);
extern int mldsa_avx287_verify_extmu(const uint8_t *sig, size_t siglen,
                                     const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_avx287_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                             size_t smlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *pk);
#    endif

#    ifdef QUDO_HAS_NEON_VARIANT
extern int mldsa_neon87_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa_neon87_signature(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  const uint8_t *sk);
extern int mldsa_neon87_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);
extern int mldsa_neon87_signature_pre_hash_internal(
    uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t *sk,
    int hashalg);
extern int mldsa_neon87_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
extern int mldsa_neon87_keypair_internal(uint8_t *pk, uint8_t *sk,
                                         const uint8_t seed[32]);
extern int mldsa_neon87_signature_internal(uint8_t *sig, size_t *siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *pre, size_t prelen,
                                           const uint8_t rnd[32],
                                           const uint8_t *sk, int externalmu);
extern int mldsa_neon87_signature_extmu(uint8_t *sig, size_t *siglen,
                                        const uint8_t mu[64],
                                        const uint8_t *sk);
extern int mldsa_neon87_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa_neon87_verify_internal(const uint8_t *sig, size_t siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *pre, size_t prelen,
                                        const uint8_t *pk, int externalmu);
extern int mldsa_neon87_verify_extmu(const uint8_t *sig, size_t siglen,
                                     const uint8_t mu[64], const uint8_t *pk);
extern int mldsa_neon87_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                             size_t smlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *pk);
#    endif

#else

extern int mldsa44_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa44_keypair_internal(uint8_t *pk, uint8_t *sk,
                                    const uint8_t seed[32]);
extern int mldsa44_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa44_signature_internal(uint8_t *sig, size_t *siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *pre, size_t prelen,
                                      const uint8_t rnd[32], const uint8_t *sk,
                                      int externalmu);
extern int mldsa44_signature_extmu(uint8_t *sig, size_t *siglen,
                                   const uint8_t mu[64], const uint8_t *sk);
extern int mldsa44_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                        size_t mlen, const uint8_t *ctx, size_t ctxlen,
                        const uint8_t *sk);
extern int mldsa44_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *pk);
extern int mldsa44_verify_internal(const uint8_t *sig, size_t siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *pk, int externalmu);
extern int mldsa44_verify_extmu(const uint8_t *sig, size_t siglen,
                                const uint8_t mu[64], const uint8_t *pk);
extern int mldsa44_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                        size_t smlen, const uint8_t *ctx, size_t ctxlen,
                        const uint8_t *pk);
extern int mldsa44_signature_pre_hash_internal(uint8_t *sig, size_t *siglen,
                                               const uint8_t *ph, size_t phlen,
                                               const uint8_t *ctx,
                                               size_t ctxlen,
                                               const uint8_t rnd[32],
                                               const uint8_t *sk, int hashalg);
extern int mldsa44_verify_pre_hash_internal(const uint8_t *sig, size_t siglen,
                                            const uint8_t *ph, size_t phlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk, int hashalg);

extern int mldsa65_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa65_keypair_internal(uint8_t *pk, uint8_t *sk,
                                    const uint8_t seed[32]);
extern int mldsa65_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa65_signature_internal(uint8_t *sig, size_t *siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *pre, size_t prelen,
                                      const uint8_t rnd[32], const uint8_t *sk,
                                      int externalmu);
extern int mldsa65_signature_extmu(uint8_t *sig, size_t *siglen,
                                   const uint8_t mu[64], const uint8_t *sk);
extern int mldsa65_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                        size_t mlen, const uint8_t *ctx, size_t ctxlen,
                        const uint8_t *sk);
extern int mldsa65_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *pk);
extern int mldsa65_verify_internal(const uint8_t *sig, size_t siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *pk, int externalmu);
extern int mldsa65_verify_extmu(const uint8_t *sig, size_t siglen,
                                const uint8_t mu[64], const uint8_t *pk);
extern int mldsa65_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                        size_t smlen, const uint8_t *ctx, size_t ctxlen,
                        const uint8_t *pk);
extern int mldsa65_signature_pre_hash_internal(uint8_t *sig, size_t *siglen,
                                               const uint8_t *ph, size_t phlen,
                                               const uint8_t *ctx,
                                               size_t ctxlen,
                                               const uint8_t rnd[32],
                                               const uint8_t *sk, int hashalg);
extern int mldsa65_verify_pre_hash_internal(const uint8_t *sig, size_t siglen,
                                            const uint8_t *ph, size_t phlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk, int hashalg);

extern int mldsa87_keypair(uint8_t *pk, uint8_t *sk);
extern int mldsa87_keypair_internal(uint8_t *pk, uint8_t *sk,
                                    const uint8_t seed[32]);
extern int mldsa87_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                             size_t mlen, const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk);
extern int mldsa87_signature_internal(uint8_t *sig, size_t *siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *pre, size_t prelen,
                                      const uint8_t rnd[32], const uint8_t *sk,
                                      int externalmu);
extern int mldsa87_signature_extmu(uint8_t *sig, size_t *siglen,
                                   const uint8_t mu[64], const uint8_t *sk);
extern int mldsa87_sign(uint8_t *sm, size_t *smlen, const uint8_t *m,
                        size_t mlen, const uint8_t *ctx, size_t ctxlen,
                        const uint8_t *sk);
extern int mldsa87_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *pk);
extern int mldsa87_verify_internal(const uint8_t *sig, size_t siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *pk, int externalmu);
extern int mldsa87_verify_extmu(const uint8_t *sig, size_t siglen,
                                const uint8_t mu[64], const uint8_t *pk);
extern int mldsa87_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                        size_t smlen, const uint8_t *ctx, size_t ctxlen,
                        const uint8_t *pk);
extern int mldsa87_signature_pre_hash_internal(uint8_t *sig, size_t *siglen,
                                               const uint8_t *ph, size_t phlen,
                                               const uint8_t *ctx,
                                               size_t ctxlen,
                                               const uint8_t rnd[32],
                                               const uint8_t *sk, int hashalg);
extern int mldsa87_verify_pre_hash_internal(const uint8_t *sig, size_t siglen,
                                            const uint8_t *ph, size_t phlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk, int hashalg);

#endif
#endif
