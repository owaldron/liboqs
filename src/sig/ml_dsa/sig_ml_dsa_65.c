// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/sig_ml_dsa.h>
#if defined(OQS_ENABLE_TEST_INTERNAL_API)
#include <oqs/sig_test.h>
#endif

#if defined(OQS_ENABLE_SIG_ml_dsa_65)
OQS_SIG *OQS_SIG_ml_dsa_65_new(void) {

	OQS_SIG *sig = OQS_MEM_calloc(1, sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	sig->method_name = OQS_SIG_alg_ml_dsa_65;
	sig->alg_version = "FIPS204";

	sig->claimed_nist_level = 3;
	sig->euf_cma = true;
	sig->suf_cma = true;
	sig->sig_with_ctx_support = true;

	sig->length_public_key = OQS_SIG_ml_dsa_65_length_public_key;
	sig->length_secret_key = OQS_SIG_ml_dsa_65_length_secret_key;
	sig->length_signature = OQS_SIG_ml_dsa_65_length_signature;

	sig->keypair = OQS_SIG_ml_dsa_65_keypair;
	sig->sign = OQS_SIG_ml_dsa_65_sign;
	sig->verify = OQS_SIG_ml_dsa_65_verify;
	sig->sign_with_ctx_str = OQS_SIG_ml_dsa_65_sign_with_ctx_str;
	sig->verify_with_ctx_str = OQS_SIG_ml_dsa_65_verify_with_ctx_str;

	return sig;
}

extern int PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_oqs(uint8_t *pk, uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_C_signature_oqs(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_C_verify_oqs(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_keypair_oqs(uint8_t *pk, uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_signature_oqs(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_verify_oqs(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
#endif

#if defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_keypair_oqs(uint8_t *pk, uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_signature_oqs(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_verify_oqs(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
#endif

OQS_API OQS_STATUS OQS_SIG_ml_dsa_65_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_keypair_oqs(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_oqs(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_keypair_oqs(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_oqs(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_oqs(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_SIG_ml_dsa_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_signature_oqs(signature, signature_len, message, message_len, NULL, 0, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_oqs(signature, signature_len, message, message_len, NULL, 0, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_signature_oqs(signature, signature_len, message, message_len, NULL, 0, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_oqs(signature, signature_len, message, message_len, NULL, 0, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_oqs(signature, signature_len, message, message_len, NULL, 0, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_SIG_ml_dsa_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_verify_oqs(signature, signature_len, message, message_len, NULL, 0, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_oqs(signature, signature_len, message, message_len, NULL, 0, public_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_verify_oqs(signature, signature_len, message, message_len, NULL, 0, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_oqs(signature, signature_len, message, message_len, NULL, 0, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_oqs(signature, signature_len, message, message_len, NULL, 0, public_key);
#endif
}
OQS_API OQS_STATUS OQS_SIG_ml_dsa_65_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_signature_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_signature_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_SIG_ml_dsa_65_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_verify_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_verify_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_oqs(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
#endif
}

/* ========================================================================== */
/*                             Internal Test API                              */
/* ========================================================================== */
#if defined(OQS_ENABLE_TEST_INTERNAL_API)
extern int PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal_oqs(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal_oqs(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *rnd, const uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_C_verify_internal_oqs(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_C_signature_pre_hash_oqs(uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *rnd, const uint8_t *sk, int hashalg);
extern int PQCP_MLDSA_NATIVE_MLDSA65_C_verify_pre_hash_oqs(const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);

#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_keypair_internal_oqs(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_signature_internal_oqs(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *rnd, const uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_verify_internal_oqs(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_signature_pre_hash_oqs(uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *rnd, const uint8_t *sk, int hashalg);
extern int PQCP_MLDSA_NATIVE_MLDSA65_X86_64_verify_pre_hash_oqs(const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
#endif

#if defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_keypair_internal_oqs(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_signature_internal_oqs(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *rnd, const uint8_t *sk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_verify_internal_oqs(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_signature_pre_hash_oqs(uint8_t *sig, size_t *siglen, const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *rnd, const uint8_t *sk, int hashalg);
extern int PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_verify_pre_hash_oqs(const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, int hashalg);
#endif

OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_keypair_internal(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_keypair_internal_oqs(public_key, secret_key, seed);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal_oqs(public_key, secret_key, seed);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_keypair_internal_oqs(public_key, secret_key, seed);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal_oqs(public_key, secret_key, seed);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal_oqs(public_key, secret_key, seed);
#endif
}

OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_sign_internal(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *rnd, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_signature_internal_oqs(signature, signature_len, message, message_len, rnd, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal_oqs(signature, signature_len, message, message_len, rnd, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_signature_internal_oqs(signature, signature_len, message, message_len, rnd, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal_oqs(signature, signature_len, message, message_len, rnd, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal_oqs(signature, signature_len, message, message_len, rnd, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_verify_internal(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_verify_internal_oqs(signature, signature_len, message, message_len, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_internal_oqs(signature, signature_len, message, message_len, public_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_verify_internal_oqs(signature, signature_len, message, message_len, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_internal_oqs(signature, signature_len, message, message_len, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_internal_oqs(signature, signature_len, message, message_len, public_key);
#endif
}

OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_sign_prehash(uint8_t *signature, size_t *signature_len, const uint8_t *prehash, size_t prehash_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *rnd, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_signature_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, rnd, secret_key, (int) hash_alg);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, rnd, secret_key, (int) hash_alg);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_signature_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, rnd, secret_key, (int) hash_alg);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, rnd, secret_key, (int) hash_alg);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_signature_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, rnd, secret_key, (int) hash_alg);
#endif
}

OQS_API OQS_STATUS OQS_SIG_TEST_ml_dsa_65_verify_prehash(const uint8_t *prehash, size_t prehash_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, OQS_SIG_TEST_prehash hash_alg, const uint8_t *public_key) {
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_X86_64_verify_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, public_key, (int) hash_alg);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, public_key, (int) hash_alg);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_verify_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, public_key, (int) hash_alg);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, public_key, (int) hash_alg);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLDSA_NATIVE_MLDSA65_C_verify_pre_hash_oqs(signature, signature_len, prehash, prehash_len, ctx_str, ctx_str_len, public_key, (int) hash_alg);
#endif
}

#endif /* OQS_ENABLE_TEST_INTERNAL_API */
#endif
