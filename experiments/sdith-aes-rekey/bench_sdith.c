#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

static double now_s(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + 1e-9 * (double)t.tv_nsec;
}

static int cmpd(const void *a, const void *b) {
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

int main(int argc, char **argv) {
	if (argc < 4) { fprintf(stderr, "usage: %s <alg> <op:sign|verify> <iters>\n", argv[0]); return 2; }
	const char *alg = argv[1];
	int do_sign = strcmp(argv[2], "sign") == 0;
	int iters = atoi(argv[3]);

	OQS_SIG *sig = OQS_SIG_new(alg);
	if (!sig) { fprintf(stderr, "alg %s unavailable\n", alg); return 1; }
	uint8_t *pk = malloc(sig->length_public_key), *sk = malloc(sig->length_secret_key);
	uint8_t *s = malloc(sig->length_signature);
	size_t slen = 0;
	uint8_t msg[32] = {0};
	if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) return 1;
	if (OQS_SIG_sign(sig, s, &slen, msg, sizeof msg, sk) != OQS_SUCCESS) return 1;
	if (OQS_SIG_verify(sig, msg, sizeof msg, s, slen, pk) != OQS_SUCCESS) { fprintf(stderr, "verify failed\n"); return 1; }

	double *t = malloc((size_t)iters * sizeof(double));
	/* warmup */
	for (int i = 0; i < 3; i++) {
		if (do_sign) { size_t l; OQS_SIG_sign(sig, s, &l, msg, sizeof msg, sk); }
		else OQS_SIG_verify(sig, msg, sizeof msg, s, slen, pk);
	}
	for (int i = 0; i < iters; i++) {
		double a = now_s();
		if (do_sign) { size_t l; OQS_SIG_sign(sig, s, &l, msg, sizeof msg, sk); }
		else OQS_SIG_verify(sig, msg, sizeof msg, s, slen, pk);
		t[i] = (now_s() - a) * 1e3; /* ms */
	}
	qsort(t, (size_t)iters, sizeof(double), cmpd);
	printf("%.4f %.4f %.4f\n", t[iters / 2], t[0], t[iters - 1]); /* median min max, ms */
	return 0;
}
