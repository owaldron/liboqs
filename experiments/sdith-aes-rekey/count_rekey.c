#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <oqs/oqs.h>

extern unsigned long sdith_rekey_calls;
extern unsigned long sdith_loadsched_calls;

static void run(const char *alg) {
	OQS_SIG *sig = OQS_SIG_new(alg);
	if (!sig) { printf("%-28s UNAVAILABLE\n", alg); return; }
	uint8_t *pk = malloc(sig->length_public_key), *sk = malloc(sig->length_secret_key);
	uint8_t *s  = malloc(sig->length_signature);
	size_t slen = 0;
	uint8_t msg[32] = {0};
	OQS_SIG_keypair(sig, pk, sk);
	sdith_rekey_calls = 0; sdith_loadsched_calls = 0;
	OQS_SIG_sign(sig, s, &slen, msg, sizeof msg, sk);
	unsigned long r_sign = sdith_rekey_calls, l_sign = sdith_loadsched_calls;
	sdith_rekey_calls = 0; sdith_loadsched_calls = 0;
	OQS_SIG_verify(sig, msg, sizeof msg, s, slen, pk);
	printf("%-30s sign: rekey=%-8lu load=%-6lu | verify: rekey=%-8lu load=%-6lu\n",
	       alg, r_sign, l_sign, sdith_rekey_calls, sdith_loadsched_calls);
	free(pk); free(sk); free(s); OQS_SIG_free(sig);
}
int main(void) {
	run("SDitH3-L1-gf2-short");
	run("SDitH3-L1-gf2-fast");
	return 0;
}
