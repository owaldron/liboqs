/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * liboqs glue for mldsa-native.
 *
 * liboqs's generated ML-DSA wrapper links against signing and verification
 * functions that carry a signature-length argument, since OQS signatures are
 * variable-length in general. mldsa-native's API omits that argument because
 * ML-DSA signatures have a fixed length. These thin shims re-expose the
 * length-carrying API expected by liboqs on top of the fixed-length one, and
 * are referenced from the per-level META.yml files.
 *
 * The shims also normalize return codes to OQS_STATUS: mldsa-native returns a
 * wider error set than liboqs's OQS_SUCCESS / OQS_ERROR, so any nonzero result
 * is collapsed to OQS_ERROR. keypair is shimmed for this normalization alone.
 *
 * The shims are compiled once per build (parameter set and backend), so the
 * namespaced symbol names match the names liboqs links against.
 */

#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>

#include "mldsa/mldsa_native.h"

/*
 * mldsa-native's public symbols are prefixed with MLD_CONFIG_NAMESPACE_PREFIX.
 * mldsa_native.h builds these names via MLD_API_NAMESPACE(), but #undef's
 * MLD_API_NAMESPACE_PREFIX at the end of the header, so MLD_API_NAMESPACE()
 * cannot be reused here. Replicate the concatenation for both the shim symbols
 * and their callees.
 */
#define MLD_OQS_CONCAT_(x, y) x##y
#define MLD_OQS_CONCAT(x, y) MLD_OQS_CONCAT_(x, y)
#define MLD_OQS_NS(sym) \
  MLD_OQS_CONCAT(MLD_OQS_CONCAT(MLD_CONFIG_NAMESPACE_PREFIX, _), sym)

#define mld_oqs_keypair MLD_OQS_NS(keypair_oqs)
#define mld_oqs_signature MLD_OQS_NS(signature_oqs)
#define mld_oqs_verify MLD_OQS_NS(verify_oqs)
#define mld_oqs_signature_extmu MLD_OQS_NS(signature_extmu_oqs)
#define mld_oqs_verify_extmu MLD_OQS_NS(verify_extmu_oqs)

/* Collapse mldsa-native's error set to OQS_SUCCESS / OQS_ERROR. liboqs declares
 * these shims as returning int and casts the result to OQS_STATUS itself. */
static int mld_oqs_status(int ret)
{
  return ret == 0 ? OQS_SUCCESS : OQS_ERROR;
}

int mld_oqs_keypair(uint8_t *pk, uint8_t *sk)
{
  return mld_oqs_status(MLD_OQS_NS(keypair)(pk, sk));
}

int mld_oqs_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                      size_t mlen, const uint8_t *ctx, size_t ctxlen,
                      const uint8_t *sk)
{
  int ret = MLD_OQS_NS(signature)(sig, m, mlen, ctx, ctxlen, sk);
  if (ret == 0)
  {
    *siglen = MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET);
  }
  return mld_oqs_status(ret);
}

int mld_oqs_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                   size_t mlen, const uint8_t *ctx, size_t ctxlen,
                   const uint8_t *pk)
{
  /* mldsa-native's verify assumes a fixed-length signature, so reject any
   * other length here. */
  if (siglen != MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET))
  {
    return OQS_ERROR;
  }
  return mld_oqs_status(MLD_OQS_NS(verify)(sig, m, mlen, ctx, ctxlen, pk));
}

int mld_oqs_signature_extmu(uint8_t *sig, size_t *siglen, const uint8_t *mu,
                            const uint8_t *sk)
{
  int ret = MLD_OQS_NS(signature_extmu)(sig, mu, sk);
  if (ret == 0)
  {
    *siglen = MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET);
  }
  return mld_oqs_status(ret);
}

int mld_oqs_verify_extmu(const uint8_t *sig, size_t siglen, const uint8_t *mu,
                         const uint8_t *pk)
{
  if (siglen != MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET))
  {
    return OQS_ERROR;
  }
  return mld_oqs_status(MLD_OQS_NS(verify_extmu)(sig, mu, pk));
}

#if defined(OQS_ENABLE_TEST_INTERNAL_API)
/*
 * Test-only shims for FIPS 204 functions that liboqs does not expose in its
 * public API: ML-DSA.KeyGen_internal, ML-DSA.Sign_internal and
 * ML-DSA.Verify_internal (Algorithms 6-8), and HashML-DSA with a caller-
 * computed digest and caller-supplied randomness (Algorithms 4-5). liboqs
 * exposes them as OQS_SIG_TEST_* only when configured with
 * -DOQS_ENABLE_TEST_INTERNAL_API=ON. hashalg is one of MLD_PREHASH_*.
 */
#define mld_oqs_keypair_internal MLD_OQS_NS(keypair_internal_oqs)
#define mld_oqs_signature_internal MLD_OQS_NS(signature_internal_oqs)
#define mld_oqs_verify_internal MLD_OQS_NS(verify_internal_oqs)
#define mld_oqs_signature_pre_hash MLD_OQS_NS(signature_pre_hash_oqs)
#define mld_oqs_verify_pre_hash MLD_OQS_NS(verify_pre_hash_oqs)

int mld_oqs_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  return mld_oqs_status(MLD_OQS_NS(keypair_internal)(pk, sk, seed));
}

int mld_oqs_signature_internal(uint8_t *sig, size_t *siglen, const uint8_t *m,
                               size_t mlen, const uint8_t *rnd,
                               const uint8_t *sk)
{
  int ret = MLD_OQS_NS(signature_internal)(sig, m, mlen, NULL, 0, rnd, sk, 0);
  if (ret == 0)
  {
    *siglen = MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET);
  }
  return mld_oqs_status(ret);
}

int mld_oqs_verify_internal(const uint8_t *sig, size_t siglen,
                            const uint8_t *m, size_t mlen, const uint8_t *pk)
{
  if (siglen != MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET))
  {
    return OQS_ERROR;
  }
  return mld_oqs_status(
      MLD_OQS_NS(verify_internal)(sig, m, mlen, NULL, 0, pk, 0));
}

int mld_oqs_signature_pre_hash(uint8_t *sig, size_t *siglen,
                               const uint8_t *ph, size_t phlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *rnd, const uint8_t *sk,
                               int hashalg)
{
  int ret = MLD_OQS_NS(signature_pre_hash_internal)(sig, ph, phlen, ctx, ctxlen,
                                                    rnd, sk, hashalg);
  if (ret == 0)
  {
    *siglen = MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET);
  }
  return mld_oqs_status(ret);
}

int mld_oqs_verify_pre_hash(const uint8_t *sig, size_t siglen,
                            const uint8_t *ph, size_t phlen,
                            const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *pk, int hashalg)
{
  if (siglen != MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET))
  {
    return OQS_ERROR;
  }
  return mld_oqs_status(MLD_OQS_NS(verify_pre_hash_internal)(
      sig, ph, phlen, ctx, ctxlen, pk, hashalg));
}

#undef mld_oqs_keypair_internal
#undef mld_oqs_signature_internal
#undef mld_oqs_verify_internal
#undef mld_oqs_signature_pre_hash
#undef mld_oqs_verify_pre_hash
#endif /* OQS_ENABLE_TEST_INTERNAL_API */

#undef mld_oqs_keypair
#undef mld_oqs_signature
#undef mld_oqs_verify
#undef mld_oqs_signature_extmu
#undef mld_oqs_verify_extmu
#undef MLD_OQS_NS
#undef MLD_OQS_CONCAT
#undef MLD_OQS_CONCAT_
