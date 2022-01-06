#include "crypto_hash_sha512.h"
#include "sign_ed25519_ref10.h"
#include "private/ed25519_ref10.h"
#include "crypto_sign.h"


#include <limits.h>
#include <stdint.h>
#include <string.h>


void ed25519_randombytes_unsafe(void *p, size_t len);

#define MAX_BATCH_SIZE 64 
#define HEAP_BATCH_SIZE ((MAX_BATCH_SIZE * 2) + 1)

/* which limb is the 128th bit in? */
static const size_t limb128bits = (128 + SC25519_BITS_PER_LIMB - 1) / SC25519_BITS_PER_LIMB;

typedef size_t heap_index_t;


typedef struct batch_heap_t {
    unsigned char r[HEAP_BATCH_SIZE][16]; /* 128 bit random values */
    ge25519_p3 points[HEAP_BATCH_SIZE];
    sc25519 scalars[HEAP_BATCH_SIZE];
    heap_index_t heap[HEAP_BATCH_SIZE];
    size_t size;
} batch_heap;




/* swap two values in the heap */
static void
heap_swap(heap_index_t *heap, size_t a, size_t b) {
    heap_index_t temp;
    temp = heap[a];
    heap[a] = heap[b];
    heap[b] = temp;
}

/* add the scalar at the end of the list to the heap */
static void
heap_insert_next(batch_heap *heap) {
    size_t node = heap->size, parent;
    heap_index_t *pheap = heap->heap;
    sc25519 *scalars = heap->scalars;

    /* insert at the bottom */
    pheap[node] = (heap_index_t)node;

    /* shift node up to its sorted spot */
    parent = (node - 1) / 2;
    while (node && lt256_modm_batch(scalars[pheap[parent]], scalars[pheap[node]], SC25519_LIMB_SIZE - 1)) {
        heap_swap(pheap, parent, node);
        node = parent;
        parent = (node - 1) / 2;
    }
    heap->size++;
}

/* update the heap when the root element is updated */
static void
heap_updated_root(batch_heap *heap, size_t limbsize) {
    size_t node, parent, childr, childl;
    heap_index_t *pheap = heap->heap;
    sc25519 *scalars = heap->scalars;

    /* shift root to the bottom */
    parent = 0;
    node = 1;
    childl = 1;
    childr = 2;
    while ((childr < heap->size)) {
        node = lt256_modm_batch(scalars[pheap[childl]], scalars[pheap[childr]], limbsize) ? childr : childl;
        heap_swap(pheap, parent, node);
        parent = node;
        childl = (parent * 2) + 1;
        childr = childl + 1;
    }

    /* shift root back up to its sorted spot */
    parent = (node - 1) / 2;
    while (node && lte256_modm_batch(scalars[pheap[parent]], scalars[pheap[node]], limbsize)) {
        heap_swap(pheap, parent, node);
        node = parent;
        parent = (node - 1) / 2;
    }
}

/* build the heap with count elements, count must be >= 3 */
static void
heap_build(batch_heap *heap, size_t count) {
    heap->heap[0] = 0;
    heap->size = 0;
    while (heap->size < count)
        heap_insert_next(heap);
}

/* extend the heap to contain new_count elements */
static void
heap_extend(batch_heap *heap, size_t new_count) {
    while (heap->size < new_count)
        heap_insert_next(heap);
}

/* get the top 2 elements of the heap */
static void
heap_get_top2(batch_heap *heap, heap_index_t *max1, heap_index_t *max2, size_t limbsize) {
    heap_index_t h0 = heap->heap[0], h1 = heap->heap[1], h2 = heap->heap[2];
    if (lt256_modm_batch(heap->scalars[h1], heap->scalars[h2], limbsize))
        h1 = h2;
    *max1 = h0;
    *max2 = h1;
}


/* */
void ge25519_multi_scalarmult_vartime_final(ge25519_p3 *r, ge25519_p3 *point, sc25519 scalar) { 
    const sc25519_element_t topbit = ((sc25519_element_t)1 << (SC25519_LIMB_SIZE - 1));
    size_t limb = limb128bits;
    sc25519_element_t flag;
    ge25519_p1p1 p1p1_r;
    ge25519_cached cache_r;

    if (isone256_modm_batch(scalar)) {
        /* this will happen most of the time after bos-carter */
        *r = *point;
        return;
    } else if (iszero256_modm_batch(scalar)) {
        /* this will only happen if all scalars == 0 */
        memset(r, 0, sizeof(*r));
        r->Y[0] = 1;
        r->Z[0] = 1;
        return;
    }

    *r = *point;

    /* find the limb where first bit is set */
    while (!scalar[limb])
        limb--;

    /* find the first bit */
    flag = topbit;
    while ((scalar[limb] & flag) == 0)
        flag >>= 1;

    
    ge25519_p3_to_cached(&cache_r, point);
    /* exponentiate */
    for (;;) {
        ge25519_p3_dbl(&p1p1_r, r);
        ge25519_p1p1_to_p3(r, &p1p1_r);
        if (scalar[limb] & flag) 
        {
            ge25519_add(&p1p1_r, r, &cache_r);
            ge25519_p1p1_to_p3(r,&p1p1_r);
        }


        flag >>= 1;
        if (!flag) {
            if (!limb--)
                break;
            flag = topbit;
        }
    }
}


/* count must be >= 5 */
static void
ge25519_multi_scalarmult_vartime(ge25519_p3 *r, batch_heap *heap, size_t count) {
    heap_index_t max1, max2;
    ge25519_cached cached_p;
    ge25519_p1p1 p_as_p1p1;

    /* start with the full limb size */
    size_t limbsize = SC25519_LIMB_SIZE - 1;

    /* whether the heap has been extended to include the 128 bit scalars */
    int extended = 0;

    /* grab an odd number of scalars to build the heap, unknown limb sizes */
    heap_build(heap, ((count + 1) / 2) | 1);

    for (;;) {
        heap_get_top2(heap, &max1, &max2, limbsize);

        /* only one scalar remaining, we're done */
        if (iszero256_modm_batch(heap->scalars[max2]))
            break;

        /* exhausted another limb? */
        if (!heap->scalars[max1][limbsize])
            limbsize -= 1;

        /* can we extend to the 128 bit scalars? */
        if (!extended && isatmost128bits256_modm_batch(heap->scalars[max1])) {
            heap_extend(heap, count);
            heap_get_top2(heap, &max1, &max2, limbsize);
            extended = 1;
        }

        sub256_modm_batch(heap->scalars[max1], heap->scalars[max1], heap->scalars[max2], limbsize);
        ge25519_p3_to_cached(&cached_p,&heap->points[max1]);

        ge25519_add(&p_as_p1p1, &heap->points[max2], &cached_p);
        ge25519_p1p1_to_p3(&heap->points[max2], &p_as_p1p1);
        heap_updated_root(heap, limbsize);
    }

    ge25519_multi_scalarmult_vartime_final(r, &heap->points[max1], heap->scalars[max1]);
}

/*
* verifies ed25519 signatures in  batch. The algorithm is based on https://github.com/floodyberry/ed25519-donna 
* implemention. we changed the algorithm according to https://eprint.iacr.org/2020/1244.pdf .
* the batch size is between 2 and 64 signatures per batch. 
* When the batch fails the function falls back to check signature one at a time.
* the function returns 0 on success and fills and array of "valid" ints. 
* 1 - for signature i passed verification
* 0 - for signature i failed verification
*/
int crypto_sign_ed25519_open_batch(const unsigned char **m, const unsigned long long *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid_p)
{
    batch_heap batch;
    ge25519_p3  p;
    ge25519_p3  p_mul;
    sc25519 *r_scalars;
    size_t i, batchsize;
    unsigned char hram[64];
    unsigned char batchsum[32];
    int ret = 0;

    for (i = 0; i < num; i++)
        valid_p[i] = 1;

    while (num >= 2) {
        batchsize = (num > MAX_BATCH_SIZE) ? MAX_BATCH_SIZE : num;

        /* validate the public key and signature */
        for (i=0; i < batchsize; i++) {
            if (validate_ed25519_pk_and_sig(RS[i], pk[i]) != 0)
                goto fallback;
        }

        /* generate r (scalars[batchsize+1]..scalars[2*batchsize] */
        ed25519_randombytes_unsafe (batch.r, batchsize * 16);
        r_scalars = &batch.scalars[batchsize + 1];

        /* compute  r0s0, r1s1, r2s2, ...) */
        for (i = 0; i < batchsize; i++){
            expand256_modm16(r_scalars[i], batch.r[i]);
            /* compute scalars[0] = ((r1s1 + r2s2 + ...)) */
            expand256_modm32(batch.scalars[i], RS[i] + 32);
            mul256_modm(batch.scalars[i], batch.scalars[i], r_scalars[i]);
        }
        /* compute scalars[0] = ((r0s0 + r1s1 + r2s2 + ...)) */
        for (i = 1; i < batchsize; i++)
            add256_modm(batch.scalars[0], batch.scalars[0], batch.scalars[i]);

        /* compute scalars[1]..scalars[batchsize] as r[i]*H(R[i],A[i],m[i]) */
        for (i = 0; i < batchsize; i++) {
            crypto_hash_sha512_state hs;   
            crypto_hash_sha512_init(&hs);         
            crypto_hash_sha512_update(&hs, RS[i], 32);
            crypto_hash_sha512_update(&hs, pk[i], 32);
            crypto_hash_sha512_update(&hs, m[i], mlen[i]);
            crypto_hash_sha512_final(&hs, hram);


            expand256_modm64(batch.scalars[i+1], hram);
            mul256_modm(batch.scalars[i+1], batch.scalars[i+1], r_scalars[i]);
        }
        /* compute points */
        batch.points[0] = ge25519_basepoint;
        for (i = 0; i < batchsize; i++)
            if (ge25519_frombytes_negate_vartime(&batch.points[i+1], pk[i]) != 0)
                goto fallback;
        for (i = 0; i < batchsize; i++)
            if (ge25519_frombytes_negate_vartime(&batch.points[batchsize+i+1], RS[i]) != 0)
                goto fallback;

        ge25519_multi_scalarmult_vartime(&p, &batch, (batchsize * 2) + 1);

        ge25519_mul_by_cofactor(&p_mul, &p);
        if (ge25519_is_neutral_vartime(&p_mul) == 0 ) {
            ret |= 2;

            fallback:
            for (i = 0; i < batchsize; i++) {
                valid_p[i] = crypto_sign_bv_compatible_verify_detached(RS[i], m[i], mlen[i], pk[i]) ? 0 : 1;
                ret |= (valid_p[i] ^ 1);
            }
        }
        m += batchsize;
        mlen += batchsize;
        pk += batchsize;
        RS += batchsize;
        num -= batchsize;
        valid_p += batchsize;

    }


    for (i = 0; i < num; i++) {        
        valid_p[i] = crypto_sign_bv_compatible_verify_detached(RS[i], m[i], mlen[i], pk[i]) ? 0 : 1;
        ret |= (valid_p[i] ^ 1);
    }

    return ret;
    
}
