#include <stdint.h>
#include <string.h>

#include "falcon.h"
#include "deterministic.h"


#define TMPSIZE_KEYGEN FALCON_TMPSIZE_KEYGEN(FALCON_DET1024_LOGN)
#define TMPSIZE_SIG FALCON_TMPSIZE_SIGNDYN(FALCON_DET1024_LOGN)
#define TMPSIZE_VERIFIY FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN)
#define PADDISG FALCON_SIG_PADDED_SIZE(FALCON_DET1024_LOGN)



int falcon_det1024_keygen_with_seed(void *privkey, void *pubkey, const void * seed, size_t seed_size) {
	shake256_context rng;
	
	shake256_init(&rng);
	shake256_inject(&rng, seed, seed_size);
	shake256_flip(&rng);

	return falcon_det1024_keygen(&rng, privkey, pubkey);
}


int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey) {
	uint8_t tmpkg[TMPSIZE_KEYGEN];

	return falcon_keygen_make(rng, FALCON_DET1024_LOGN, privkey, FALCON_DET1024_PRIVKEY_SIZE, pubkey, FALCON_DET1024_PUBKEY_SIZE, tmpkg, TMPSIZE_KEYGEN);
}

uint8_t falcon_det1024_nonce[40] = {"FALCON_DET1024"};

int falcon_det1024_sign(void *sig, const void *privkey, const void *data, size_t data_len) {
	shake256_context detrng;
	shake256_context hd;
	
	uint8_t tmpsd[TMPSIZE_SIG];
	uint8_t domain[1], logn[1];

	size_t siglen = PADDISG;
	uint8_t fullsig[PADDISG];

	domain[0] = 0;
	shake256_init(&detrng);
	shake256_inject(&detrng, domain, 1);
	logn[0] = FALCON_DET1024_LOGN;
	shake256_inject(&detrng, logn, 1);
	shake256_inject(&detrng, privkey, FALCON_DET1024_PRIVKEY_SIZE);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	shake256_init(&hd);
	shake256_inject(&hd, falcon_det1024_nonce, 40);
	shake256_inject(&hd, data, data_len);

	int r = falcon_sign_dyn_finish(&detrng, fullsig, &siglen, FALCON_SIG_PADDED, privkey, FALCON_DET1024_PRIVKEY_SIZE, &hd, falcon_det1024_nonce, tmpsd, TMPSIZE_SIG);
	if (r != 0) {
		return r;
	}

	uint8_t *sigbytes = sig;
	sigbytes[0] = FALCON_DET1024_SIG_PREFIX;
	sigbytes[1] = fullsig[0];
	memcpy(sigbytes+2, fullsig+41, siglen-41);

	return 0;
}

int falcon_det1024_verify(const void *sig, const void *pubkey, const void *data, size_t data_len) {
	uint8_t tmpvv[TMPSIZE_VERIFIY];

	size_t siglen = PADDISG;
	uint8_t fullsig[PADDISG];

	const uint8_t *sigbytes = sig;
	if (sigbytes[0] != FALCON_DET1024_SIG_PREFIX) {
		return FALCON_ERR_BADSIG;
	}

	fullsig[0] = sigbytes[1];
	memcpy(fullsig+1, falcon_det1024_nonce, 40);
	memcpy(fullsig+41, sigbytes+2, siglen-41);

	return falcon_verify(fullsig, siglen, FALCON_SIG_PADDED, pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len, tmpvv, TMPSIZE_VERIFIY);
}
