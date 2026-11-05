/**
 * \file sig_test.h
 * \brief Test-only access to FIPS-internal signature functions
 *
 * This header exposes functions that FIPS 204 defines but that are not part
 * of the ordinary signing API: 
 * - deterministic key generation from a seed,
 * - ML-DSA.Sign_internal / ML-DSA.Verify_internal, and
 * - HashML-DSA with caller-supplied randomness.
 *
 * They exist so that test harnesses (e.g. NIST ACVP vector tests) can exercise
 * these interfaces through the same backend dispatch as the public API.
 *
 * \warning These functions are not a part of the public API and cannot 
 * be relied upon for production use. They are only compiled when
 * liboqs is configured with `-DOQS_ENABLE_TEST_INTERNAL_API=ON`.
 *
 * Two layers are provided:
 * - Per-scheme functions, e.g. OQS_SIG_TEST_ml_dsa_44_sign_internal().
 * - Generic functions taking an OQS_SIG object, e.g.
 *   OQS_SIG_TEST_sign_internal(), which dispatch on `sig->method_name`.
 *   Use OQS_SIG_TEST_supports_internal() to check whether an algorithm
 *   provides these functions.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_SIG_TEST_H
#define OQS_SIG_TEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>

#if !defined(OQS_ENABLE_TEST_INTERNAL_API)
#error "oqs/sig_test.h requires liboqs to be configured with -DOQS_ENABLE_TEST_INTERNAL_API=ON"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/** Length in bytes of the ML-DSA key generation seed (FIPS 204 xi). */
#define OQS_SIG_TEST_ml_dsa_length_keypair_seed 32
/** Length in bytes of the ML-DSA signing randomness (FIPS 204 rnd). */
#define OQS_SIG_TEST_ml_dsa_length_rnd 32

/**
 * Pre-hash functions for HashML-DSA (FIPS 204, Table 2).
 *
 * The values equal mldsa-native's MLD_PREHASH_* constants and are passed through unchanged.
 */
typedef enum {
	OQS_SIG_TEST_PREHASH_SHA2_224 = 1,
	OQS_SIG_TEST_PREHASH_SHA2_256 = 2,
	OQS_SIG_TEST_PREHASH_SHA2_384 = 3,
	OQS_SIG_TEST_PREHASH_SHA2_512 = 4,
	OQS_SIG_TEST_PREHASH_SHA2_512_224 = 5,
	OQS_SIG_TEST_PREHASH_SHA2_512_256 = 6,
	OQS_SIG_TEST_PREHASH_SHA3_224 = 7,
	OQS_SIG_TEST_PREHASH_SHA3_256 = 8,
	OQS_SIG_TEST_PREHASH_SHA3_384 = 9,
	OQS_SIG_TEST_PREHASH_SHA3_512 = 10,
	OQS_SIG_TEST_PREHASH_SHAKE_128 = 11,
	OQS_SIG_TEST_PREHASH_SHAKE_256 = 12,
} OQS_SIG_TEST_prehash;

/**
 * Indicates whether the named algorithm provides the OQS_SIG_TEST_* functions.
 *
 * @param[in] method_name Name of the signature algorithm.
 * @return true if the algorithm is enabled and supports the test API, false otherwise.
 */
OQS_API bool OQS_SIG_TEST_supports_internal(const char *method_name);

/**
 * Deterministic key generation from a seed (ML-DSA.KeyGen_internal, FIPS 204 Algorithm 6).
 *
 * @param[in] sig The OQS_SIG object.
 * @param[out] public_key The public key; must be `sig->length_public_key` bytes.
 * @param[out] secret_key The secret key; must be `sig->length_secret_key` bytes.
 * @param[in] seed The key generation seed (e.g. OQS_SIG_TEST_ml_dsa_length_keypair_seed bytes).
 * @return OQS_SUCCESS or OQS_ERROR (including if the algorithm is not supported).
 */
OQS_API OQS_STATUS OQS_SIG_TEST_keypair_internal(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);

/**
 * Internal signing on a pre-formatted message (ML-DSA.Sign_internal, FIPS 204 Algorithm 7).
 *
 * @param[in] sig The OQS_SIG object.
 * @param[out] signature The signature; must be `sig->length_signature` bytes.
 * @param[out] signature_len The length of the signature.
 * @param[in] message The formatted message M'.
 * @param[in] message_len The length of M'.
 * @param[in] rnd The signing randomness (e.g. OQS_SIG_TEST_ml_dsa_length_rnd bytes).
 * @param[in] secret_key The secret key.
 * @return OQS_SUCCESS or OQS_ERROR (including if the algorithm is not supported).
 */
OQS_API OQS_STATUS OQS_SIG_TEST_sign_internal(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *rnd, const uint8_t *secret_key);

/**
 * Internal verification on a pre-formatted message (ML-DSA.Verify_internal, FIPS 204 Algorithm 8).
 *
 * @param[in] sig The OQS_SIG object.
 * @param[in] message The formatted message M'.
 * @param[in] message_len The length of M'.
 * @param[in] signature The signature.
 * @param[in] signature_len The length of the signature.
 * @param[in] public_key The public key.
 * @return OQS_SUCCESS if the signature is valid, OQS_ERROR otherwise.
 */
OQS_API OQS_STATUS OQS_SIG_TEST_verify_internal(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * Pre-hash signing with caller-supplied digest and randomness (HashML-DSA.Sign, FIPS 204 Algorithm 4).
 *
 * @param[in] sig The OQS_SIG object.
 * @param[out] signature The signature; must be `sig->length_signature` bytes.
 * @param[out] signature_len The length of the signature.
 * @param[in] prehash The digest PH(M), computed by the caller with `hash_alg`.
 * @param[in] prehash_len The length of the digest.
 * @param[in] ctx_str The context string.
 * @param[in] ctx_str_len The length of the context string (at most 255).
 * @param[in] hash_alg The pre-hash function used to compute `prehash`.
 * @param[in] rnd The signing randomness (e.g. OQS_SIG_TEST_ml_dsa_length_rnd bytes).
 * @param[in] secret_key The secret key.
 * @return OQS_SUCCESS or OQS_ERROR (including if the algorithm is not supported).
 */
OQS_API OQS_STATUS OQS_SIG_TEST_sign_prehash(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *prehash, size_t prehash_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *rnd, const uint8_t *secret_key);

/**
 * Pre-hash verification with caller-supplied digest (HashML-DSA.Verify, FIPS 204 Algorithm 5).
 *
 * @param[in] sig The OQS_SIG object.
 * @param[in] prehash The digest PH(M), computed by the caller with `hash_alg`.
 * @param[in] prehash_len The length of the digest.
 * @param[in] signature The signature.
 * @param[in] signature_len The length of the signature.
 * @param[in] ctx_str The context string.
 * @param[in] ctx_str_len The length of the context string (at most 255).
 * @param[in] hash_alg The pre-hash function used to compute `prehash`.
 * @param[in] public_key The public key.
 * @return OQS_SUCCESS if the signature is valid, OQS_ERROR otherwise.
 */
OQS_API OQS_STATUS OQS_SIG_TEST_verify_prehash(const OQS_SIG *sig, const uint8_t *prehash, size_t prehash_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_ml_dsa_44)
/** ML-DSA-44 variant of OQS_SIG_TEST_keypair_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_44_keypair_internal(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
/** ML-DSA-44 variant of OQS_SIG_TEST_sign_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_44_sign_internal(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *rnd, const uint8_t *secret_key);
/** ML-DSA-44 variant of OQS_SIG_TEST_verify_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_44_verify_internal(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
/** ML-DSA-44 variant of OQS_SIG_TEST_sign_prehash(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_44_sign_prehash(uint8_t *signature, size_t *signature_len, const uint8_t *prehash, size_t prehash_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *rnd, const uint8_t *secret_key);
/** ML-DSA-44 variant of OQS_SIG_TEST_verify_prehash(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_44_verify_prehash(const uint8_t *prehash, size_t prehash_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_ml_dsa_65)
/** ML-DSA-65 variant of OQS_SIG_TEST_keypair_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_keypair_internal(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
/** ML-DSA-65 variant of OQS_SIG_TEST_sign_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_sign_internal(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *rnd, const uint8_t *secret_key);
/** ML-DSA-65 variant of OQS_SIG_TEST_verify_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_verify_internal(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
/** ML-DSA-65 variant of OQS_SIG_TEST_sign_prehash(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_sign_prehash(uint8_t *signature, size_t *signature_len, const uint8_t *prehash, size_t prehash_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *rnd, const uint8_t *secret_key);
/** ML-DSA-65 variant of OQS_SIG_TEST_verify_prehash(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_verify_prehash(const uint8_t *prehash, size_t prehash_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_ml_dsa_87)
/** ML-DSA-87 variant of OQS_SIG_TEST_keypair_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_87_keypair_internal(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
/** ML-DSA-87 variant of OQS_SIG_TEST_sign_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_87_sign_internal(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *rnd, const uint8_t *secret_key);
/** ML-DSA-87 variant of OQS_SIG_TEST_verify_internal(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_87_verify_internal(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
/** ML-DSA-87 variant of OQS_SIG_TEST_sign_prehash(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_87_sign_prehash(uint8_t *signature, size_t *signature_len, const uint8_t *prehash, size_t prehash_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *rnd, const uint8_t *secret_key);
/** ML-DSA-87 variant of OQS_SIG_TEST_verify_prehash(). */
OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_87_verify_prehash(const uint8_t *prehash, size_t prehash_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *public_key);
#endif

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_SIG_TEST_H
