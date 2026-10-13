#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arm_neon.h>
#include <oqs/oqs.h>
#include <oqs/aes.h>

/* liboqs stores AES-128 round keys as 11 * 16 bytes, plain (non-bitsliced),
   ready for vld1q_u8. aes128ctx_nobitslice is { uint32_t sk_exp[44]; uint8_t iv[16]; } */
#define RK_WORDS 44

static const uint8_t Rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

/* SubWord via AESE.
   AESE(state, rk) = ShiftRows(SubBytes(state ^ rk)).
   Broadcast the word into all four columns: every row then holds four equal
   bytes, so ShiftRows (a within-row rotate) is the identity, and every lane
   of the result is SubWord(x). */
static inline uint32_t sub_word_aese(uint32_t x) {
	uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(x));
	v = vaeseq_u8(v, vdupq_n_u8(0));
	return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

static void aes128_keysched_aese(uint32_t *skey, const uint8_t *key) {
	for (int i = 0; i < 4; i++) {
		skey[i] = (uint32_t)key[4 * i] | ((uint32_t)key[4 * i + 1] << 8) |
		          ((uint32_t)key[4 * i + 2] << 16) | ((uint32_t)key[4 * i + 3] << 24);
	}
	uint32_t tmp = skey[3];
	for (int i = 4, j = 0, k = 0; i < RK_WORDS; i++) {
		if (j == 0) {
			tmp = (tmp << 24) | (tmp >> 8);
			tmp = sub_word_aese(tmp) ^ Rcon[k];
		}
		tmp ^= skey[i - 4];
		skey[i] = tmp;
		if (++j == 4) { j = 0; k++; }
	}
}

static double now_s(void) {
	struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + 1e-9 * (double)t.tv_nsec;
}
static int cmpd(const void *a, const void *b) {
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}
#define N 400000
#define TIME(label, body) do { \
	double r[7]; \
	for (int rep = 0; rep < 7; rep++) { \
		double a = now_s(); \
		for (long i = 0; i < N; i++) { body; } \
		r[rep] = (now_s() - a) * 1e9 / (double)N; \
	} \
	qsort(r, 7, sizeof(double), cmpd); \
	printf("  %-46s %8.2f ns\n", label, r[3]); \
} while (0)

int main(void) {
	/* --- correctness: compare against liboqs' own schedule for random keys --- */
	void *sch = NULL;
	uint8_t key[16];
	uint32_t mine[RK_WORDS];
	int bad = 0;
	srandom(1);
	OQS_AES128_ECB_load_schedule(key, &sch);
	for (int t = 0; t < 200000; t++) {
		for (int b = 0; b < 16; b++) { key[b] = (uint8_t)(random() & 0xff); }
		OQS_AES128_ECB_rekey(key, sch);
		aes128_keysched_aese(mine, key);
		if (memcmp(sch, mine, RK_WORDS * 4) != 0) { bad++; if (bad < 3) { printf("  MISMATCH at t=%d\n", t); } }
	}
	printf("round-key mismatches over 200000 random keys: %d\n", bad);

	/* also pin down the FIPS-197 AES-128 vector: key 000102..0f, last round key */
	for (int b = 0; b < 16; b++) { key[b] = (uint8_t)b; }
	aes128_keysched_aese(mine, key);
	printf("FIPS-197 key 000102..0f, round key 10 = ");
	for (int b = 40; b < 44; b++) { printf("%08x ", mine[b]); }
	printf("\n");

	/* --- cost --- */
	printf("\nkey schedule cost, AES-128:\n");
	TIME("liboqs rekey (bitsliced sub_word x10)", { key[0] = (uint8_t)i; OQS_AES128_ECB_rekey(key, sch); });
	TIME("aese-based schedule (this prototype)", { key[0] = (uint8_t)i; aes128_keysched_aese(mine, key); });
	OQS_AES128_free_schedule(sch);
	return 0;
}
