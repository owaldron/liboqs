// SPDX-License-Identifier: MIT

#include <stdlib.h>
#if defined(_WIN32)
#include <string.h>
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

#include <oqs/oqs.h>
#include <oqs/sig_test.h>

/*
 * Generic OQS_*_TEST_* functions: dispatch on the algorithm name to the
 * per-scheme functions, which are defined in sig_ml_dsa_*.c.
 */

OQS_API bool OQS_SIG_TEST_supports_internal(const char *method_name) {
	if (method_name == NULL) {
		return false;
	}
#if defined(OQS_ENABLE_SIG_ml_dsa_44)
	if (0 == strcasecmp(method_name, OQS_SIG_alg_ml_dsa_44)) {
		return true;
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65)
	if (0 == strcasecmp(method_name, OQS_SIG_alg_ml_dsa_65)) {
		return true;
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_87)
	if (0 == strcasecmp(method_name, OQS_SIG_alg_ml_dsa_87)) {
		return true;
	}
#endif
	return false;
}

OQS_API OQS_STATUS OQS_SIG_TEST_keypair_internal(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed) {
	if (sig == NULL) {
		return OQS_ERROR;
	}
#if defined(OQS_ENABLE_SIG_ml_dsa_44)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_44)) {
		return OQS_SIG_TEST_ml_dsa_44_keypair_internal(public_key, secret_key, seed);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_65)) {
		return OQS_SIG_TEST_ml_dsa_65_keypair_internal(public_key, secret_key, seed);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_87)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_87)) {
		return OQS_SIG_TEST_ml_dsa_87_keypair_internal(public_key, secret_key, seed);
	}
#endif
#if !defined(OQS_ENABLE_SIG_ml_dsa_44) && !defined(OQS_ENABLE_SIG_ml_dsa_65) && !defined(OQS_ENABLE_SIG_ml_dsa_87)
	(void)public_key;
	(void)secret_key;
	(void)seed;
#endif
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_TEST_sign_internal(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *rnd, const uint8_t *secret_key) {
	if (sig == NULL) {
		return OQS_ERROR;
	}
#if defined(OQS_ENABLE_SIG_ml_dsa_44)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_44)) {
		return OQS_SIG_TEST_ml_dsa_44_sign_internal(signature, signature_len, message, message_len, rnd, secret_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_65)) {
		return OQS_SIG_TEST_ml_dsa_65_sign_internal(signature, signature_len, message, message_len, rnd, secret_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_87)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_87)) {
		return OQS_SIG_TEST_ml_dsa_87_sign_internal(signature, signature_len, message, message_len, rnd, secret_key);
	}
#endif
#if !defined(OQS_ENABLE_SIG_ml_dsa_44) && !defined(OQS_ENABLE_SIG_ml_dsa_65) && !defined(OQS_ENABLE_SIG_ml_dsa_87)
	(void)signature;
	(void)signature_len;
	(void)message;
	(void)message_len;
	(void)rnd;
	(void)secret_key;
#endif
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_TEST_verify_internal(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	if (sig == NULL) {
		return OQS_ERROR;
	}
#if defined(OQS_ENABLE_SIG_ml_dsa_44)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_44)) {
		return OQS_SIG_TEST_ml_dsa_44_verify_internal(message, message_len, signature, signature_len, public_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_65)) {
		return OQS_SIG_TEST_ml_dsa_65_verify_internal(message, message_len, signature, signature_len, public_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_87)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_87)) {
		return OQS_SIG_TEST_ml_dsa_87_verify_internal(message, message_len, signature, signature_len, public_key);
	}
#endif
#if !defined(OQS_ENABLE_SIG_ml_dsa_44) && !defined(OQS_ENABLE_SIG_ml_dsa_65) && !defined(OQS_ENABLE_SIG_ml_dsa_87)
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)public_key;
#endif
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_TEST_sign_prehash(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *prehash, size_t prehash_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *rnd, const uint8_t *secret_key) {
	if (sig == NULL) {
		return OQS_ERROR;
	}
#if defined(OQS_ENABLE_SIG_ml_dsa_44)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_44)) {
		return OQS_SIG_TEST_ml_dsa_44_sign_prehash(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, hash_alg, rnd, secret_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_65)) {
		return OQS_SIG_TEST_ml_dsa_65_sign_prehash(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, hash_alg, rnd, secret_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_87)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_87)) {
		return OQS_SIG_TEST_ml_dsa_87_sign_prehash(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, hash_alg, rnd, secret_key);
	}
#endif
#if !defined(OQS_ENABLE_SIG_ml_dsa_44) && !defined(OQS_ENABLE_SIG_ml_dsa_65) && !defined(OQS_ENABLE_SIG_ml_dsa_87)
	(void)signature;
	(void)signature_len;
	(void)prehash;
	(void)prehash_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)hash_alg;
	(void)rnd;
	(void)secret_key;
#endif
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_TEST_verify_prehash(const OQS_SIG *sig, const uint8_t *prehash, size_t prehash_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *public_key) {
	if (sig == NULL) {
		return OQS_ERROR;
	}
#if defined(OQS_ENABLE_SIG_ml_dsa_44)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_44)) {
		return OQS_SIG_TEST_ml_dsa_44_verify_prehash(prehash, prehash_len, signature, signature_len, ctx_str, ctx_str_len, hash_alg, public_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_65)) {
		return OQS_SIG_TEST_ml_dsa_65_verify_prehash(prehash, prehash_len, signature, signature_len, ctx_str, ctx_str_len, hash_alg, public_key);
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_87)
	if (0 == strcasecmp(sig->method_name, OQS_SIG_alg_ml_dsa_87)) {
		return OQS_SIG_TEST_ml_dsa_87_verify_prehash(prehash, prehash_len, signature, signature_len, ctx_str, ctx_str_len, hash_alg, public_key);
	}
#endif
#if !defined(OQS_ENABLE_SIG_ml_dsa_44) && !defined(OQS_ENABLE_SIG_ml_dsa_65) && !defined(OQS_ENABLE_SIG_ml_dsa_87)
	(void)prehash;
	(void)prehash_len;
	(void)signature;
	(void)signature_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)hash_alg;
	(void)public_key;
#endif
	return OQS_ERROR;
}
