// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_SDITH_H
#define OQS_SIG_SDITH_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_sdith_sdith3_l1_gf2_short)
#define OQS_SIG_sdith_sdith3_l1_gf2_short_length_public_key 70
#define OQS_SIG_sdith_sdith3_l1_gf2_short_length_secret_key 147
#define OQS_SIG_sdith_sdith3_l1_gf2_short_length_signature 3721

OQS_SIG *OQS_SIG_sdith_sdith3_l1_gf2_short_new(void);
OQS_API OQS_STATUS OQS_SIG_sdith_sdith3_l1_gf2_short_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sdith_sdith3_l1_gf2_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sdith_sdith3_l1_gf2_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_sdith_sdith3_l1_gf2_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sdith_sdith3_l1_gf2_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#endif
