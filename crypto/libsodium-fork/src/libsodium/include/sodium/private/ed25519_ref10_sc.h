
#ifndef ed25519_ref10_sc_H
#define ed25519_ref10_sc_H

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


static void barrett_reduce256_modm(sc25519 r, const sc25519 q1, const sc25519 r1);
static void reduce256_modm(sc25519 r);
void expand256_modm(sc25519 out, const unsigned char *in, size_t len);
void add256_modm(sc25519 r, const sc25519 x, const sc25519 y);
void mul256_modm(sc25519 r, const sc25519 x, const sc25519 y);

void sub256_modm_batch(sc25519 out, const sc25519 a, const sc25519 b, size_t limbsize);
int lt256_modm_batch(const sc25519 a, const sc25519 b, size_t limbsize);
int lte256_modm_batch(const sc25519 a, const sc25519 b, size_t limbsize);
int iszero256_modm_batch(const sc25519 a);
int isone256_modm_batch(const sc25519 a);
int isatmost128bits256_modm_batch(const sc25519 a);

#endif