
#ifndef ed25519_ref10_sc_51_H
#define ed25519_ref10_sc_51_H

#include <stddef.h>
#include <stdint.h>

/*
 The set of scalars is \Z/l
 where l = 2^252 + 27742317777372353535851937790883648493.
 */

typedef uint64_t sc25519_element_t;
typedef sc25519_element_t sc25519[5];

#define SC25519_BITS_PER_LIMB 56
#define SC25519_LIMB_SIZE 5

typedef unsigned __int128 uint128_t;
#define mul64x64_128(out,a,b) out = (uint128_t)a * b;
#define shr128_pair(out,hi,lo,shift) out = (uint64_t)((((uint128_t)hi << 64) | lo) >> (shift));
#define shl128_pair(out,hi,lo,shift) out = (uint64_t)(((((uint128_t)hi << 64) | lo) << (shift)) >> 64);
#define shr128(out,in,shift) out = (uint64_t)(in >> (shift));
#define shl128(out,in,shift) out = (uint64_t)((in << shift) >> 64);
#define add128(a,b) a += b;
#define add128_64(a,b) a += (uint64_t)b;
#define lo128(a) ((uint64_t)a)
#define hi128(a) ((uint64_t)(a >> 64))


	


static inline uint64_t U8TO64_LE(const unsigned char *p) {
	return
	(((uint64_t)(p[0])      ) |
	 ((uint64_t)(p[1]) <<  8) |
	 ((uint64_t)(p[2]) << 16) |
	 ((uint64_t)(p[3]) << 24) |
	 ((uint64_t)(p[4]) << 32) |
	 ((uint64_t)(p[5]) << 40) |
	 ((uint64_t)(p[6]) << 48) |
	 ((uint64_t)(p[7]) << 56));
}

static inline void U64TO8_LE(unsigned char *p, const uint64_t v) {
	p[0] = (unsigned char)(v      );
	p[1] = (unsigned char)(v >>  8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
	p[4] = (unsigned char)(v >> 32);
	p[5] = (unsigned char)(v >> 40);
	p[6] = (unsigned char)(v >> 48);
	p[7] = (unsigned char)(v >> 56);
}



static const sc25519 modm_m = {
	0x12631a5cf5d3ed, 
	0xf9dea2f79cd658, 
	0x000000000014de, 
	0x00000000000000, 
	0x00000010000000
};


static const sc25519 modm_mu = {
	0x9ce5a30a2c131b,
	0x215d086329a7ed,
	0xffffffffeb2106,
	0xffffffffffffff,
	0x00000fffffffff
};

static sc25519_element_t lt_modm(sc25519_element_t a, sc25519_element_t b) {
	return (a - b) >> 63;
}

static void reduce256_modm(sc25519 r) 
{
	sc25519 t;
	sc25519_element_t b = 0, pb, mask;

	/* t = r - m */
	pb = 0;
	pb += modm_m[0]; b = lt_modm(r[0], pb); t[0] = (r[0] - pb + (b << 56)); pb = b;
	pb += modm_m[1]; b = lt_modm(r[1], pb); t[1] = (r[1] - pb + (b << 56)); pb = b;
	pb += modm_m[2]; b = lt_modm(r[2], pb); t[2] = (r[2] - pb + (b << 56)); pb = b;
	pb += modm_m[3]; b = lt_modm(r[3], pb); t[3] = (r[3] - pb + (b << 56)); pb = b;
	pb += modm_m[4]; b = lt_modm(r[4], pb); t[4] = (r[4] - pb + (b << 32)); 

	/* keep r if r was smaller than m */
	mask = b - 1;

	r[0] ^= mask & (r[0] ^ t[0]);
	r[1] ^= mask & (r[1] ^ t[1]);
	r[2] ^= mask & (r[2] ^ t[2]);
	r[3] ^= mask & (r[3] ^ t[3]);
	r[4] ^= mask & (r[4] ^ t[4]);
}

static void barrett_reduce256_modm(sc25519 r, const sc25519 q1, const sc25519 r1)
{
	sc25519 q3, r2;
	uint128_t c, mul;
	sc25519_element_t f, b, pb;

	/* q1 = x >> 248 = 264 bits = 5 56 bit elements
	   q2 = mu * q1
	   q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264 */
	mul64x64_128(c, modm_mu[0], q1[3])                 mul64x64_128(mul, modm_mu[3], q1[0]) add128(c, mul) mul64x64_128(mul, modm_mu[1], q1[2]) add128(c, mul) mul64x64_128(mul, modm_mu[2], q1[1]) add128(c, mul) shr128(f, c, 56);
	mul64x64_128(c, modm_mu[0], q1[4]) add128_64(c, f) mul64x64_128(mul, modm_mu[4], q1[0]) add128(c, mul) mul64x64_128(mul, modm_mu[3], q1[1]) add128(c, mul) mul64x64_128(mul, modm_mu[1], q1[3]) add128(c, mul) mul64x64_128(mul, modm_mu[2], q1[2]) add128(c, mul)
	f = lo128(c); q3[0] = (f >> 40) & 0xffff; shr128(f, c, 56);
	mul64x64_128(c, modm_mu[4], q1[1]) add128_64(c, f) mul64x64_128(mul, modm_mu[1], q1[4]) add128(c, mul) mul64x64_128(mul, modm_mu[2], q1[3]) add128(c, mul) mul64x64_128(mul, modm_mu[3], q1[2]) add128(c, mul)
	f = lo128(c); q3[0] |= (f << 16) & 0xffffffffffffff; q3[1] = (f >> 40) & 0xffff; shr128(f, c, 56);
	mul64x64_128(c, modm_mu[4], q1[2]) add128_64(c, f) mul64x64_128(mul, modm_mu[2], q1[4]) add128(c, mul) mul64x64_128(mul, modm_mu[3], q1[3]) add128(c, mul)
	f = lo128(c); q3[1] |= (f << 16) & 0xffffffffffffff; q3[2] = (f >> 40) & 0xffff; shr128(f, c, 56);
	mul64x64_128(c, modm_mu[4], q1[3]) add128_64(c, f) mul64x64_128(mul, modm_mu[3], q1[4]) add128(c, mul)
	f = lo128(c); q3[2] |= (f << 16) & 0xffffffffffffff; q3[3] = (f >> 40) & 0xffff; shr128(f, c, 56);
	mul64x64_128(c, modm_mu[4], q1[4]) add128_64(c, f)
	f = lo128(c); q3[3] |= (f << 16) & 0xffffffffffffff; q3[4] = (f >> 40) & 0xffff; shr128(f, c, 56);
	q3[4] |= (f << 16);

	mul64x64_128(c, modm_m[0], q3[0]) 
	r2[0] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, modm_m[0], q3[1]) add128_64(c, f) mul64x64_128(mul, modm_m[1], q3[0]) add128(c, mul)
	r2[1] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, modm_m[0], q3[2]) add128_64(c, f) mul64x64_128(mul, modm_m[2], q3[0]) add128(c, mul) mul64x64_128(mul, modm_m[1], q3[1]) add128(c, mul)
	r2[2] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, modm_m[0], q3[3]) add128_64(c, f) mul64x64_128(mul, modm_m[3], q3[0]) add128(c, mul) mul64x64_128(mul, modm_m[1], q3[2]) add128(c, mul) mul64x64_128(mul, modm_m[2], q3[1]) add128(c, mul)
	r2[3] = lo128(c) & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, modm_m[0], q3[4]) add128_64(c, f) mul64x64_128(mul, modm_m[4], q3[0]) add128(c, mul) mul64x64_128(mul, modm_m[3], q3[1]) add128(c, mul) mul64x64_128(mul, modm_m[1], q3[3]) add128(c, mul) mul64x64_128(mul, modm_m[2], q3[2]) add128(c, mul)
	r2[4] = lo128(c) & 0x0000ffffffffff;

	pb = 0;
	pb += r2[0]; b = lt_modm(r1[0], pb); r[0] = (r1[0] - pb + (b << 56)); pb = b;
	pb += r2[1]; b = lt_modm(r1[1], pb); r[1] = (r1[1] - pb + (b << 56)); pb = b;
	pb += r2[2]; b = lt_modm(r1[2], pb); r[2] = (r1[2] - pb + (b << 56)); pb = b;
	pb += r2[3]; b = lt_modm(r1[3], pb); r[3] = (r1[3] - pb + (b << 56)); pb = b;
	pb += r2[4]; b = lt_modm(r1[4], pb); r[4] = (r1[4] - pb + (b << 40)); 

	reduce256_modm(r);
	reduce256_modm(r);
}


/*
 Input:
 s[0]+256*s[1]+...+256^63*s[63] = s
 *
 Output:
 s[0]+256*s[1]+...+256^31*s[31] = s mod l
 where l = 2^252 + 27742317777372353535851937790883648493.
 the output returns in sc25519 presentation 
 */
static void expand256_modm64(sc25519 out, const unsigned char *in)
{
	sc25519_element_t x[8];
	sc25519 q1;

	x[0] = U8TO64_LE(in +  0);
	x[1] = U8TO64_LE(in +  8);
	x[2] = U8TO64_LE(in + 16);
	x[3] = U8TO64_LE(in + 24);
	x[4] = U8TO64_LE(in + 32);
	x[5] = U8TO64_LE(in + 40);
	x[6] = U8TO64_LE(in + 48);
	x[7] = U8TO64_LE(in + 56);

	/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
	out[0] = (                         x[0]) & 0xffffffffffffff;
	out[1] = ((x[ 0] >> 56) | (x[ 1] <<  8)) & 0xffffffffffffff;
	out[2] = ((x[ 1] >> 48) | (x[ 2] << 16)) & 0xffffffffffffff;
	out[3] = ((x[ 2] >> 40) | (x[ 3] << 24)) & 0xffffffffffffff;
	out[4] = ((x[ 3] >> 32) | (x[ 4] << 32)) & 0x0000ffffffffff;

	/* q1 = x >> 248 = 264 bits */
	q1[0] = ((x[ 3] >> 56) | (x[ 4] <<  8)) & 0xffffffffffffff;
	q1[1] = ((x[ 4] >> 48) | (x[ 5] << 16)) & 0xffffffffffffff;
	q1[2] = ((x[ 5] >> 40) | (x[ 6] << 24)) & 0xffffffffffffff;
	q1[3] = ((x[ 6] >> 32) | (x[ 7] << 32)) & 0xffffffffffffff;
	q1[4] = ((x[ 7] >> 24)                );

	barrett_reduce256_modm(out, q1, out);
}

/*
 Input:
 s[0]+256*s[1]+...+256^32*s[32] = s
 *
 Output:
 s[0]+256*s[1]+...+256^31*s[31] = s mod l
 where l = 2^252 + 27742317777372353535851937790883648493.
 the output returns in sc25519 presentation 
 */
static void expand256_modm32(sc25519 out, const unsigned char *in)
{
	sc25519_element_t x[4];
	sc25519 q1;

	x[0] = U8TO64_LE(in +  0);
	x[1] = U8TO64_LE(in +  8);
	x[2] = U8TO64_LE(in + 16);
	x[3] = U8TO64_LE(in + 24);

	/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
	out[0] = (                         x[0]) & 0xffffffffffffff;
	out[1] = ((x[ 0] >> 56) | (x[ 1] <<  8)) & 0xffffffffffffff;
	out[2] = ((x[ 1] >> 48) | (x[ 2] << 16)) & 0xffffffffffffff;
	out[3] = ((x[ 2] >> 40) | (x[ 3] << 24)) & 0xffffffffffffff;
	out[4] = ((x[ 3] >> 32) 			   ) & 0x0000ffffffffff;

	/* q1 = x >> 248 = 264 bits */
	q1[0] = ((x[ 3] >> 56)) & 0xffffffffffffff;
	q1[1] = 0;
	q1[2] = 0;
	q1[3] = 0;
	q1[4] = 0;

	barrett_reduce256_modm(out, q1, out);
}


/*
 Input:
 s[0]+256*s[1]+...+256^16*s[16] = s
 *
 Output:
 s[0]+256*s[1]+...+256^31*s[31] = s mod l
 where l = 2^252 + 27742317777372353535851937790883648493.
 the output returns in sc25519 presentation 
 */
static void expand256_modm16(sc25519 out, const unsigned char *in)
{
	sc25519_element_t x[2];
	sc25519 q1;

	x[0] = U8TO64_LE(in +  0);
	x[1] = U8TO64_LE(in +  8);

	/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
	out[0] = (                         x[0]) & 0xffffffffffffff;
	out[1] = ((x[ 0] >> 56) | (x[ 1] <<  8)) & 0xffffffffffffff;
	out[2] = ((x[ 1] >> 48) 			   ) & 0xffffffffffffff;
	out[3] = 0;
	out[4] = 0;

}

static void add256_modm(sc25519 r, const sc25519 x, const sc25519 y) 
{
	sc25519_element_t c;

	c  = x[0] + y[0]; r[0] = c & 0xffffffffffffff; c >>= 56;
	c += x[1] + y[1]; r[1] = c & 0xffffffffffffff; c >>= 56;
	c += x[2] + y[2]; r[2] = c & 0xffffffffffffff; c >>= 56;
	c += x[3] + y[3]; r[3] = c & 0xffffffffffffff; c >>= 56;
	c += x[4] + y[4]; r[4] = c;

	reduce256_modm(r);
}

static void mul256_modm(sc25519 r, const sc25519 x, const sc25519 y) 
{
	sc25519 q1, r1;
	uint128_t c, mul;
	sc25519_element_t f;

	mul64x64_128(c, x[0], y[0])
	f = lo128(c); r1[0] = f & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[0], y[1]) add128_64(c, f) mul64x64_128(mul, x[1], y[0]) add128(c, mul) 
	f = lo128(c); r1[1] = f & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[0], y[2]) add128_64(c, f) mul64x64_128(mul, x[2], y[0]) add128(c, mul) mul64x64_128(mul, x[1], y[1]) add128(c, mul) 
	f = lo128(c); r1[2] = f & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[0], y[3]) add128_64(c, f) mul64x64_128(mul, x[3], y[0]) add128(c, mul) mul64x64_128(mul, x[1], y[2]) add128(c, mul) mul64x64_128(mul, x[2], y[1]) add128(c, mul) 
	f = lo128(c); r1[3] = f & 0xffffffffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[0], y[4]) add128_64(c, f) mul64x64_128(mul, x[4], y[0]) add128(c, mul) mul64x64_128(mul, x[3], y[1]) add128(c, mul) mul64x64_128(mul, x[1], y[3]) add128(c, mul) mul64x64_128(mul, x[2], y[2]) add128(c, mul) 
	f = lo128(c); r1[4] = f & 0x0000ffffffffff; q1[0] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[4], y[1]) add128_64(c, f) mul64x64_128(mul, x[1], y[4]) add128(c, mul) mul64x64_128(mul, x[2], y[3]) add128(c, mul) mul64x64_128(mul, x[3], y[2]) add128(c, mul) 
	f = lo128(c); q1[0] |= (f << 32) & 0xffffffffffffff; q1[1] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[4], y[2]) add128_64(c, f) mul64x64_128(mul, x[2], y[4]) add128(c, mul) mul64x64_128(mul, x[3], y[3]) add128(c, mul) 
	f = lo128(c); q1[1] |= (f << 32) & 0xffffffffffffff; q1[2] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[4], y[3]) add128_64(c, f) mul64x64_128(mul, x[3], y[4]) add128(c, mul) 
	f = lo128(c); q1[2] |= (f << 32) & 0xffffffffffffff; q1[3] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
	mul64x64_128(c, x[4], y[4]) add128_64(c, f)
	f = lo128(c); q1[3] |= (f << 32) & 0xffffffffffffff; q1[4] = (f >> 24) & 0xffffffff; shr128(f, c, 56);
	q1[4] |= (f << 32);

	barrett_reduce256_modm(r, q1, r1);
}

/*
	helpers for batch verifcation, are allowed to be vartime
*/

/* out = a - b, a must be larger than b */
static void sub256_modm_batch(sc25519 out, const sc25519 a, const sc25519 b, size_t limbsize) {
	size_t i = 0;
	sc25519_element_t carry = 0;
	switch (limbsize) {
		case 4: out[i] = (a[i] - b[i])        ; carry = (out[i] >> 63); out[i] &= 0xffffffffffffff; i++;
		case 3: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 63); out[i] &= 0xffffffffffffff; i++;
		case 2: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 63); out[i] &= 0xffffffffffffff; i++;
		case 1: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 63); out[i] &= 0xffffffffffffff; i++;
		case 0: 
		default: out[i] = (a[i] - b[i]) - carry;
	}
}


/* is a < b */
static int lt256_modm_batch(const sc25519 a, const sc25519 b, size_t limbsize) {
	size_t i = 0;
	sc25519_element_t t, carry = 0;
	switch (limbsize) {
		case 4: t = (a[i] - b[i])        ; carry = (t >> 63); i++;
		case 3: t = (a[i] - b[i]) - carry; carry = (t >> 63); i++;
		case 2: t = (a[i] - b[i]) - carry; carry = (t >> 63); i++;
		case 1: t = (a[i] - b[i]) - carry; carry = (t >> 63); i++;
		case 0: t = (a[i] - b[i]) - carry; carry = (t >> 63);
	}
	return (int)carry;
}

/* is a <= b */
static int lte256_modm_batch(const sc25519 a, const sc25519 b, size_t limbsize) {
	size_t i = 0;
	sc25519_element_t t, carry = 0;
	switch (limbsize) {
		case 4: t = (b[i] - a[i])        ; carry = (t >> 63); i++;
		case 3: t = (b[i] - a[i]) - carry; carry = (t >> 63); i++;
		case 2: t = (b[i] - a[i]) - carry; carry = (t >> 63); i++;
		case 1: t = (b[i] - a[i]) - carry; carry = (t >> 63); i++;
		case 0: t = (b[i] - a[i]) - carry; carry = (t >> 63);
	}
	return (int)!carry;
}

/* is a == 0 */
static int iszero256_modm_batch(const sc25519 a) {
	sc25519_element_t result = a[0];
	result |= a[1];
	result |= a[2];
	result |= a[3];
	result |= a[4];

	return (result == 0);
}

/* is a == 1 */
static int isone256_modm_batch(const sc25519 a) {
	sc25519_element_t result = a[0] ^ 1;
	result |= a[1];
	result |= a[2];
	result |= a[3];
	result |= a[4];

	return (result == 0);
}

/* can a fit in to (at most) 128 bits */
static int isatmost128bits256_modm_batch(const sc25519 a) {
	uint64_t mask =
		((a[4]                   )  | /*  32 */
		 (a[3]                   )  | /*  88 */
		 (a[2] & 0xffffffffff0000));

	return (mask == 0);
}




#endif
