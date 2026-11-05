// SPDX-License-Identifier: MIT

#include <stdlib.h>
#if defined(_WIN32)
#include <string.h>
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

#include <oqs/oqs.h>
#include <oqs/kem_test.h>

/*
 * Generic OQS_*_TEST_* functions: dispatch on the algorithm name to the
 * per-scheme functions, which are defined in kem_ml_kem_*.c.
 */

OQS_API bool OQS_KEM_TEST_supports_internal(const char *method_name) {
	if (method_name == NULL) {
		return false;
	}
#if defined(OQS_ENABLE_KEM_ml_kem_512)
	if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_512)) {
		return true;
	}
#endif
#if defined(OQS_ENABLE_KEM_ml_kem_768)
	if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_768)) {
		return true;
	}
#endif
#if defined(OQS_ENABLE_KEM_ml_kem_1024)
	if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_1024)) {
		return true;
	}
#endif
	return false;
}

OQS_API OQS_STATUS OQS_KEM_TEST_check_encaps_key(const OQS_KEM *kem, const uint8_t *public_key) {
	if (kem == NULL) {
		return OQS_ERROR;
	}
#if defined(OQS_ENABLE_KEM_ml_kem_512)
	if (0 == strcasecmp(kem->method_name, OQS_KEM_alg_ml_kem_512)) {
		return OQS_KEM_TEST_ml_kem_512_check_encaps_key(public_key);
	}
#endif
#if defined(OQS_ENABLE_KEM_ml_kem_768)
	if (0 == strcasecmp(kem->method_name, OQS_KEM_alg_ml_kem_768)) {
		return OQS_KEM_TEST_ml_kem_768_check_encaps_key(public_key);
	}
#endif
#if defined(OQS_ENABLE_KEM_ml_kem_1024)
	if (0 == strcasecmp(kem->method_name, OQS_KEM_alg_ml_kem_1024)) {
		return OQS_KEM_TEST_ml_kem_1024_check_encaps_key(public_key);
	}
#endif
	(void)public_key;
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_KEM_TEST_check_decaps_key(const OQS_KEM *kem, const uint8_t *secret_key) {
	if (kem == NULL) {
		return OQS_ERROR;
	}
#if defined(OQS_ENABLE_KEM_ml_kem_512)
	if (0 == strcasecmp(kem->method_name, OQS_KEM_alg_ml_kem_512)) {
		return OQS_KEM_TEST_ml_kem_512_check_decaps_key(secret_key);
	}
#endif
#if defined(OQS_ENABLE_KEM_ml_kem_768)
	if (0 == strcasecmp(kem->method_name, OQS_KEM_alg_ml_kem_768)) {
		return OQS_KEM_TEST_ml_kem_768_check_decaps_key(secret_key);
	}
#endif
#if defined(OQS_ENABLE_KEM_ml_kem_1024)
	if (0 == strcasecmp(kem->method_name, OQS_KEM_alg_ml_kem_1024)) {
		return OQS_KEM_TEST_ml_kem_1024_check_decaps_key(secret_key);
	}
#endif
	(void)secret_key;
	return OQS_ERROR;
}
