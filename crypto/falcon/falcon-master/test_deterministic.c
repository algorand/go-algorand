#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "falcon.h"
#include "deterministic.h"



int run_test_deterministic() {
	uint8_t pubkey[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t privkey[FALCON_DET1024_PRIVKEY_SIZE];
	uint8_t sig[FALCON_DET1024_SIG_SIZE];

	memset(privkey, 0, FALCON_DET1024_PRIVKEY_SIZE);
	memset(pubkey, 0, FALCON_DET1024_PUBKEY_SIZE);

	shake256_context rng;
	shake256_init_prng_from_seed(&rng, "seed", 4);

	int r = falcon_det1024_keygen(&rng, privkey, pubkey);
	if (r != 0) {
		fprintf(stderr, "keygen failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	memset(sig, 0, FALCON_DET1024_SIG_SIZE);
	r = falcon_det1024_sign(sig, privkey, "data1", 5);
	if (r != 0) {
		fprintf(stderr, "sign_det1024 failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_verify(sig, pubkey, "data1", 5);
	if (r != 0) {
		fprintf(stderr, "verify failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	for (unsigned int i = 0; i < FALCON_DET1024_SIG_SIZE; i++) {
		printf("%02x", sig[i]);
	}
	printf("\n");
	return 0;
}


// int main(){
// 	return run_test();
// }
