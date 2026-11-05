/**
 * \file kem_test.h
 * \brief Test-only access to FIPS-internal KEM functions
 * 
 * This header exposes functions that FIPS 203 specifies but that are not part
 * of the ordinary API. This includes input checks on encapsulation and
 * decapsulation keys (Section 7.2 and 7.3)
 *
 * They exist so that test harnesses (e.g. NIST ACVP vector tests) can exercise
 * these interfaces through the same backend dispatch as the public API.
 *
 * \warning These functions are not a part of the public API and cannot 
 * be relied upon for production use. They are only compiled when
 * liboqs is configured with `-DOQS_ENABLE_TEST_INTERNAL_API=ON`.
 *
 * Two layers are provided:
 * - Per-scheme functions, e.g. OQS_KEM_TEST_ml_kem_512_check_encaps_key().
 * - Generic functions taking an OQS_KEM object, e.g.
 *   OQS_KEM_TEST_check_encaps_key(), which dispatch on `kem->method_name`.
 *   Use OQS_KEM_TEST_supports_internal() to check whether an algorithm
 *   provides these functions.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_KEM_TEST_H
#define OQS_KEM_TEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>

#if !defined(OQS_ENABLE_TEST_INTERNAL_API)
#error "oqs/kem_test.h requires liboqs to be configured with -DOQS_ENABLE_TEST_INTERNAL_API=ON"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Indicates whether the named algorithm provides the OQS_KEM_TEST_* functions.
 *
 * @param[in] method_name Name of the KEM algorithm.
 * @return true if the algorithm is enabled and supports the test API, false otherwise.
 */
OQS_API bool OQS_KEM_TEST_supports_internal(const char *method_name);

/**
 * Encapsulation key check (FIPS 203, Section 7.2).
 *
 * @param[in] kem The OQS_KEM object.
 * @param[in] public_key The encapsulation key; must be `kem->length_public_key` bytes.
 * @return OQS_SUCCESS if the key passes the check, OQS_ERROR otherwise
 *         (including if the algorithm is not supported).
 */
OQS_API OQS_STATUS OQS_KEM_TEST_check_encaps_key(const OQS_KEM *kem, const uint8_t *public_key);

/**
 * Decapsulation key check (FIPS 203, Section 7.3).
 *
 * @param[in] kem The OQS_KEM object.
 * @param[in] secret_key The decapsulation key; must be `kem->length_secret_key` bytes.
 * @return OQS_SUCCESS if the key passes the check, OQS_ERROR otherwise
 *         (including if the algorithm is not supported).
 */
OQS_API OQS_STATUS OQS_KEM_TEST_check_decaps_key(const OQS_KEM *kem, const uint8_t *secret_key);

#if defined(OQS_ENABLE_KEM_ml_kem_512)
/** ML-KEM-512 variant of OQS_KEM_TEST_check_encaps_key(). */
OQS_API OQS_STATUS OQS_KEM_TEST_ml_kem_512_check_encaps_key(const uint8_t *public_key);
/** ML-KEM-512 variant of OQS_KEM_TEST_check_decaps_key(). */
OQS_API OQS_STATUS OQS_KEM_TEST_ml_kem_512_check_decaps_key(const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_ml_kem_768)
/** ML-KEM-768 variant of OQS_KEM_TEST_check_encaps_key(). */
OQS_API OQS_STATUS OQS_KEM_TEST_ml_kem_768_check_encaps_key(const uint8_t *public_key);
/** ML-KEM-768 variant of OQS_KEM_TEST_check_decaps_key(). */
OQS_API OQS_STATUS OQS_KEM_TEST_ml_kem_768_check_decaps_key(const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_ml_kem_1024)
/** ML-KEM-1024 variant of OQS_KEM_TEST_check_encaps_key(). */
OQS_API OQS_STATUS OQS_KEM_TEST_ml_kem_1024_check_encaps_key(const uint8_t *public_key);
/** ML-KEM-1024 variant of OQS_KEM_TEST_check_decaps_key(). */
OQS_API OQS_STATUS OQS_KEM_TEST_ml_kem_1024_check_decaps_key(const uint8_t *secret_key);
#endif

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_KEM_TEST_H
