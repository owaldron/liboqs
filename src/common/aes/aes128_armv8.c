// SPDX-License-Identifier: Public domain

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <oqs/common.h>

#include <arm_neon.h>

typedef struct {
	uint64_t sk_exp[22];
	uint8_t iv[16];
} aes128ctx;

static const uint8_t armv8_Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

/*
    SubWord via AESE. AESE(state, rk) = ShiftRows(SubBytes(state ^ rk)), so with a
    zero round key it is ShiftRows(SubBytes(state)). Broadcasting the word into all
    four columns makes every row hold four equal bytes, and ShiftRows only rotates
    within a row, so it becomes the identity: each lane of the result is SubWord(x).
    Constant time, like the bitsliced S-box it replaces, but in two instructions.
*/
static inline uint32_t aes128_subword_armv8(uint32_t x) {
	uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(x));
	v = vaeseq_u8(v, vdupq_n_u8(0));
	return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

// Produces exactly the round keys that aes_keysched_no_bitslice does: 11 round keys
// of 4 little-endian words each, laid out for vld1q_u8.
static void aes128_keysched_armv8(uint32_t *skey, const uint8_t *key) {
	for (unsigned i = 0; i < 4; i++) {
		skey[i] = (uint32_t)key[4 * i] | ((uint32_t)key[4 * i + 1] << 8) |
		          ((uint32_t)key[4 * i + 2] << 16) | ((uint32_t)key[4 * i + 3] << 24);
	}
	uint32_t tmp = skey[3];
	for (unsigned i = 4, j = 0, k = 0; i < 44; i++) {
		if (j == 0) {
			tmp = (tmp << 24) | (tmp >> 8);
			tmp = aes128_subword_armv8(tmp) ^ armv8_Rcon[k];
		}
		tmp ^= skey[i - 4];
		skey[i] = tmp;
		if (++j == 4) {
			j = 0;
			k++;
		}
	}
}

void oqs_aes128_load_schedule_armv8(const uint8_t *key, void **_schedule) {
	*_schedule = OQS_MEM_malloc(sizeof(aes128ctx));
	OQS_EXIT_IF_NULLPTR(*_schedule, "AES");
	aes128_keysched_armv8((uint32_t *) ((aes128ctx *) *_schedule)->sk_exp, key);
}

void oqs_aes128_rekey_armv8(const uint8_t *key, void *_schedule) {
	OQS_EXIT_IF_NULLPTR(_schedule, "AES");
	aes128_keysched_armv8((uint32_t *) ((aes128ctx *) _schedule)->sk_exp, key);
}

void oqs_aes128_load_iv_armv8(const uint8_t *iv, size_t iv_len, void *_schedule) {
	aes128ctx *ctx = _schedule;
	if (iv_len == 12) {
		memcpy(ctx->iv, iv, 12);
		memset(&ctx->iv[12], 0, 4);
	} else if (iv_len == 16) {
		memcpy(ctx->iv, iv, 16);
	} else {
		exit(EXIT_FAILURE);
	}
}

// From crypto_core/aes128encrypt/dolbeau/armv8crypto
static inline void aes128_armv8_encrypt(const unsigned char *rkeys, const unsigned char *n, unsigned char *out) {
	uint8x16_t temp = vld1q_u8(n);
	//int i;

	/*
	    In ARMv8+crypto, the AESE instruction does the 'AddRoundKey' first then SubBytes and ShiftRows.
	    The AESMC instruction does the MixColumns.
	    So instead of a single XOR of the first round key before the rounds,
	    we end up having a single XOR of the last round key after the rounds.
	*/

	temp = vaeseq_u8(temp, vld1q_u8(rkeys));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 16));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 32));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 48));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 64));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 80));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 96));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 112));
	temp = vaesmcq_u8(temp);
	temp = vaeseq_u8(temp, vld1q_u8(rkeys + 128));
	temp = vaesmcq_u8(temp);

	temp = vaeseq_u8(temp, vld1q_u8((rkeys + 144)));
	temp = veorq_u8(temp, vld1q_u8((rkeys + 160)));

	vst1q_u8(out, temp);
}

void oqs_aes128_enc_sch_block_armv8(const uint8_t *plaintext, const void *_schedule, uint8_t *ciphertext) {
	const unsigned char *schedule = (const unsigned char *) _schedule;
	aes128_armv8_encrypt(schedule, plaintext, ciphertext);
}

void oqs_aes128_ecb_enc_sch_armv8(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext) {
	assert(plaintext_len % 16 == 0);
	const aes128ctx *ctx = (const aes128ctx *) schedule;

	for (size_t block = 0; block < plaintext_len / 16; block++) {
		oqs_aes128_enc_sch_block_armv8(plaintext + (16 * block), (const void *) ctx->sk_exp, ciphertext + (16 * block));
	}
}

static uint32_t UINT32_TO_BE(const uint32_t x) {
	union {
		uint32_t val;
		uint8_t bytes[4];
	} y;
	y.bytes[0] = (x >> 24) & 0xFF;
	y.bytes[1] = (x >> 16) & 0xFF;
	y.bytes[2] = (x >> 8) & 0xFF;
	y.bytes[3] = x & 0xFF;
	return y.val;
}
#define BE_TO_UINT32(n) (uint32_t)((((uint8_t *) &(n))[0] << 24) | (((uint8_t *) &(n))[1] << 16) | (((uint8_t *) &(n))[2] << 8) | (((uint8_t *) &(n))[3] << 0))


void oqs_aes128_ctr_enc_sch_upd_blks_armv8(void *schedule, uint8_t *out, size_t out_blks) {
	aes128ctx *ctx = (aes128ctx *) schedule;
	uint8_t *block = ctx->iv;
	uint32_t ctr;
	uint32_t ctr_be;
	memcpy(&ctr_be, &block[12], 4);
	ctr = BE_TO_UINT32(ctr_be);
	while (out_blks >= 1) {
		oqs_aes128_enc_sch_block_armv8(block, schedule, out);
		out += 16;
		out_blks--;
		ctr++;
		ctr_be = UINT32_TO_BE(ctr);
		memcpy(&block[12], (uint8_t *) &ctr_be, 4);
	}
}

void oqs_aes128_ctr_enc_sch_armv8(const uint8_t *iv, const size_t iv_len, const void *schedule, uint8_t *out, size_t out_len) {
	uint8_t block[16];
	uint32_t ctr;
	uint32_t ctr_be;
	memcpy(block, iv, 12);
	if (iv_len == 12) {
		ctr = 0;
	} else if (iv_len == 16) {
		memcpy(&ctr_be, &iv[12], 4);
		ctr = BE_TO_UINT32(ctr_be);
	} else {
		exit(EXIT_FAILURE);
	}
	while (out_len >= 16) {
		ctr_be = UINT32_TO_BE(ctr);
		memcpy(&block[12], (uint8_t *) &ctr_be, 4);
		oqs_aes128_enc_sch_block_armv8(block, schedule, out);
		out += 16;
		out_len -= 16;
		ctr++;
	}
	if (out_len > 0) {
		uint8_t tmp[16];
		ctr_be = UINT32_TO_BE(ctr);
		memcpy(&block[12], (uint8_t *) &ctr_be, 4);
		oqs_aes128_enc_sch_block_armv8(block, schedule, tmp);
		memcpy(out, tmp, out_len);
	}
}
