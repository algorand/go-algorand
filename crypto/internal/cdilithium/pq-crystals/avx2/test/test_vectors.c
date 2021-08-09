#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../randombytes.h"
#include "../fips202.h"
#include "../params.h"
#include "../sign.h"
#include "../poly.h"
#include "../polyvec.h"
#include "../packing.h"

#define MLEN 32
#define NVECTORS 10000

static unsigned int nttidx(unsigned int k) {
  unsigned int r;
  r  = k/64*64;
  k %= 64;
  r += k/8;
  k %= 8;
  r += k*8;
  return r;
}

void randombytes(uint8_t *out, size_t outlen) {
  unsigned int i;
  uint8_t buf[8];
  static uint64_t ctr = 0;

  for(i = 0; i < 8; ++i)
    buf[i] = ctr >> 8*i;

  ctr++;
  shake128(out, outlen, buf, 8);
}

int main(void) {
  unsigned int i, j, k, l;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  uint8_t m[MLEN];
  uint8_t seed[CRHBYTES];
  uint8_t buf[CRYPTO_SECRETKEYBYTES];
  size_t siglen;
  poly c, tmp;
  polyvecl s, y, mat[K];
  polyveck w, w1, w0, t1, t0;

  for(i = 0; i < NVECTORS; ++i) {
    printf("count = %u\n", i);

    randombytes(m, MLEN);
    printf("m = ");
    for(j = 0; j < MLEN; ++j)
      printf("%02x", m[j]);
    printf("\n");

    crypto_sign_keypair(pk, sk);
    shake256(buf, 32, pk, CRYPTO_PUBLICKEYBYTES);
    printf("pk = ");
    for(j = 0; j < 32; ++j)
      printf("%02x", buf[j]);
    printf("\n");
    shake256(buf, 32, sk, CRYPTO_SECRETKEYBYTES);
    printf("sk = ");
    for(j = 0; j < 32; ++j)
      printf("%02x", buf[j]);
    printf("\n");

    crypto_sign_signature(sig, &siglen, m, MLEN, sk);
    shake256(buf, 32, sig, CRYPTO_BYTES);
    printf("sig = ");
    for(j = 0; j < 32; ++j)
      printf("%02x", buf[j]);
    printf("\n");

    if(crypto_sign_verify(sig, siglen, m, MLEN, pk))
      fprintf(stderr,"Signature verification failed!\n");

    randombytes(seed, sizeof(seed));
    printf("seed = ");
    for(j = 0; j < sizeof(seed); ++j)
      printf("%02X", seed[j]);
    printf("\n");

    polyvec_matrix_expand(mat, seed);
    printf("A = ([");
    for(j = 0; j < K; ++j) {
      for(k = 0; k < L; ++k) {
        for(l = 0; l < N; ++l) {
          printf("%8d", mat[j].vec[k].coeffs[nttidx(l)]);
          if(l < N-1) printf(", ");
          else if(k < L-1) printf("], [");
          else if(j < K-1) printf("];\n     [");
          else printf("])\n");
        }
      }
    }

#ifdef DILITHIUM_USE_AES
    uint64_t nonce = 0;
    aes256ctr_ctx state;
    aes256ctr_init(&state, seed, nonce++);
    for(j = 0; j < L; ++j) {
      poly_uniform_eta_preinit(&s.vec[j], &state);
      state.n = _mm_loadl_epi64((__m128i *)&nonce);
      nonce++;
    }
#elif L == 4
    poly_uniform_eta_4x(&s.vec[0], &s.vec[1], &s.vec[2], &s.vec[3], seed, 0, 1, 2, 3);
#elif L == 5
    poly_uniform_eta_4x(&s.vec[0], &s.vec[1], &s.vec[2], &s.vec[3], seed, 0, 1, 2, 3);
    poly_uniform_eta(&s.vec[4], seed, 4);
#elif L == 7
    poly_uniform_eta_4x(&s.vec[0], &s.vec[1], &s.vec[2], &s.vec[3], seed, 0, 1, 2, 3);
    poly_uniform_eta_4x(&s.vec[4], &s.vec[5], &s.vec[6], &tmp, seed, 4, 5, 6, 7);
#else
#error
#endif

    polyeta_pack(buf, &s.vec[0]);
    polyeta_unpack(&tmp, buf);
    for(j = 0; j < N; ++j)
      if(tmp.coeffs[j] != s.vec[0].coeffs[j])
        fprintf(stderr, "ERROR in polyeta_(un)pack!\n");

    if(polyvecl_chknorm(&s, ETA+1))
      fprintf(stderr, "ERROR in polyvecl_chknorm(&s ,ETA+1)!\n");

    printf("s = ([");
    for(j = 0; j < L; ++j) {
      for(k = 0; k < N; ++k) {
        printf("%3d", s.vec[j].coeffs[k]);
        if(k < N-1) printf(", ");
        else if(j < L-1) printf("],\n     [");
        else printf("])\n");
      }
    }

#ifdef DILITHIUM_USE_AES
    nonce = 0;
    aes256ctr_init(&state, seed, nonce++);
    for(j = 0; j < L; ++j) {
      poly_uniform_gamma1_preinit(&y.vec[j], &state);
      state.n = _mm_loadl_epi64((__m128i *)&nonce);
      nonce++;
    }
#elif L == 4
    poly_uniform_gamma1_4x(&y.vec[0], &y.vec[1], &y.vec[2], &y.vec[3], seed, 0, 1, 2, 3);
#elif L == 5
    poly_uniform_gamma1_4x(&y.vec[0], &y.vec[1], &y.vec[2], &y.vec[3], seed, 0, 1, 2, 3);
    poly_uniform_gamma1(&y.vec[4], seed, 4);
#elif L == 7
    poly_uniform_gamma1_4x(&y.vec[0], &y.vec[1], &y.vec[2], &y.vec[3], seed, 0, 1, 2, 3);
    poly_uniform_gamma1_4x(&y.vec[4], &y.vec[5], &y.vec[6], &tmp, seed, 4, 5, 6, 7);
#else
#error
#endif

    polyz_pack(buf, &y.vec[0]);
    polyz_unpack(&tmp, buf);
    for(j = 0; j < N; ++j)
      if(tmp.coeffs[j] != y.vec[0].coeffs[j])
        fprintf(stderr, "ERROR in polyz_(un)pack!\n");

    if(polyvecl_chknorm(&y, GAMMA1+1))
      fprintf(stderr, "ERROR in polyvecl_chknorm(&y, GAMMA1)!\n");

    printf("y = ([");
    for(j = 0; j < L; ++j) {
      for(k = 0; k < N; ++k) {
        printf("%8d", y.vec[j].coeffs[k]);
        if(k < N-1) printf(", ");
        else if(j < L-1) printf("],\n     [");
        else printf("])\n");
      }
    }

    polyvecl_ntt(&y);
    polyvec_matrix_pointwise_montgomery(&w, mat, &y);
    polyveck_invntt_tomont(&w);
    polyveck_caddq(&w);
    polyveck_decompose(&w1, &w0, &w);

    for(j = 0; j < N; ++j) {
      tmp.coeffs[j] = w1.vec[0].coeffs[j]*2*GAMMA2 + w0.vec[0].coeffs[j];
      if(tmp.coeffs[j] < 0) tmp.coeffs[j] += Q;
      if(tmp.coeffs[j] != w.vec[0].coeffs[j])
        fprintf(stderr, "ERROR in poly_decompose!\n");
    }

    polyw1_pack(buf, &w1.vec[0]);
#if GAMMA2 == (Q-1)/32
    for(j = 0; j < N/2; ++j) {
      tmp.coeffs[2*j+0] = buf[j] & 0xF;
      tmp.coeffs[2*j+1] = buf[j] >> 4;
      if(tmp.coeffs[2*j+0] != w1.vec[0].coeffs[2*j+0]
         || tmp.coeffs[2*j+1] != w1.vec[0].coeffs[2*j+1])
        fprintf(stderr, "ERROR in polyw1_pack!\n");
    }
#endif

#if GAMMA2 == (Q-1)/32
    if(polyveck_chknorm(&w1, 16))
      fprintf(stderr, "ERROR in polyveck_chknorm(&w1, 16)!\n");
#elif GAMMA2 == (Q-1)/88
    if(polyveck_chknorm(&w1, 44))
      fprintf(stderr, "ERROR in polyveck_chknorm(&w1, 4)!\n");
#endif
    if(polyveck_chknorm(&w0, GAMMA2 + 1))
      fprintf(stderr, "ERROR in polyveck_chknorm(&w0, GAMMA2+1)!\n");

    printf("w1 = ([");
    for(j = 0; j < K; ++j) {
      for(k = 0; k < N; ++k) {
        printf("%2d", w1.vec[j].coeffs[k]);
        if(k < N-1) printf(", ");
        else if(j < K-1) printf("],\n      [");
        else printf("])\n");
      }
    }
    printf("w0 = ([");
    for(j = 0; j < K; ++j) {
      for(k = 0; k < N; ++k) {
        printf("%8d", w0.vec[j].coeffs[k]);
        if(k < N-1) printf(", ");
        else if(j < K-1) printf("],\n      [");
        else printf("])\n");
      }
    }

    polyveck_power2round(&t1, &t0, &w);

    for(j = 0; j < N; ++j) {
      tmp.coeffs[j] = (t1.vec[0].coeffs[j] << D) + t0.vec[0].coeffs[j];
      if(tmp.coeffs[j] != w.vec[0].coeffs[j])
        fprintf(stderr, "ERROR in poly_power2round!\n");
    }

    polyt1_pack(buf, &t1.vec[0]);
    polyt1_unpack(&tmp, buf);
    for(j = 0; j < N; ++j) {
      if(tmp.coeffs[j] != t1.vec[0].coeffs[j])
        fprintf(stderr, "ERROR in polyt1_(un)pack!\n");
    }
    polyt0_pack(buf, &t0.vec[0]);
    polyt0_unpack(&tmp, buf);
    for(j = 0; j < N; ++j) {
      if(tmp.coeffs[j] != t0.vec[0].coeffs[j])
        fprintf(stderr, "ERROR in polyt0_(un)pack!\n");
    }

    if(polyveck_chknorm(&t1, 1024))
      fprintf(stderr, "ERROR in polyveck_chknorm(&t1, 1024)!\n");
    if(polyveck_chknorm(&t0, (1U << (D-1)) + 1))
      fprintf(stderr, "ERROR in polyveck_chknorm(&t0, (1 << (D-1)) + 1)!\n");

    printf("t1 = ([");
    for(j = 0; j < K; ++j) {
      for(k = 0; k < N; ++k) {
        printf("%3d", t1.vec[j].coeffs[k]);
        if(k < N-1) printf(", ");
        else if(j < K-1) printf("],\n      [");
        else printf("])\n");
      }
    }
    printf("t0 = ([");
    for(j = 0; j < K; ++j) {
      for(k = 0; k < N; ++k) {
        printf("%5d", t0.vec[j].coeffs[k]);
        if(k < N-1) printf(", ");
        else if(j < K-1) printf("],\n      [");
        else printf("])\n");
      }
    }

    poly_challenge(&c, seed);
    printf("c = [");
    for(j = 0; j < N; ++j) {
      printf("%2d", c.coeffs[j]);
      if(j < N-1) printf(", ");
      else printf("]\n");
    }

    printf("\n");
  }

  return 0;
}
