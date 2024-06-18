#include "sodium.h"
int ed25519_batch_wrapper(const unsigned char **messages2D,
                          const unsigned char **publicKeys2D,
                          const unsigned char **signatures2D,
                          const unsigned char *messages1D,
                          const unsigned long long *mlen,
                          const unsigned char *publicKeys1D,
                          const unsigned char *signatures1D,
                          size_t num,
                          int *valid) {
    // fill 2-D arrays for messages, pks, sigs from provided 1-D arrays
    unsigned long long mpos = 0;
    for (size_t i = 0; i < num; i++) {
        messages2D[i] = &messages1D[mpos];
        mpos += mlen[i];
        publicKeys2D[i] = &publicKeys1D[i*crypto_sign_ed25519_PUBLICKEYBYTES];
        signatures2D[i] = &signatures1D[i*crypto_sign_ed25519_BYTES];
    }
    return crypto_sign_ed25519_open_batch(messages2D, mlen, publicKeys2D, signatures2D, num, valid);
}
