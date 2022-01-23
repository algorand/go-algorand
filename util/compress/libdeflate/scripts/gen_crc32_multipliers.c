/*
 * gen_crc32_multipliers.c
 *
 * Copyright 2016 Eric Biggers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <inttypes.h>
#include <stdio.h>

/* generator polynomial G(x) */
#define CRCPOLY		0xEDB88320 /* G(x) without x^32 term */
#define CRCPOLY_FULL	(((uint64_t)CRCPOLY << 1) | 1) /* G(x) */

/* Compute x^D mod G(x) */
static uint32_t
compute_multiplier(int D)
{
	/* Start with x^0 mod G(x) */
	uint32_t remainder = 0x80000000;

	/* Each iteration, 'remainder' becomes x^i mod G(x) */
	for (int i = 1; i <= D; i++)
		remainder = (remainder >> 1) ^ ((remainder & 1) ? CRCPOLY : 0);

	/* Now 'remainder' is x^D mod G(x) */
	return remainder;
}

/* Compute floor(x^64 / G(x)) */
static uint64_t
compute_barrett_reduction_constant(void)
{
	uint64_t quotient = 0;
	uint64_t dividend = 0x1;

	for (int i = 0; i < 64 - 32 + 1; i++) {
		if ((dividend >> i) & 1) {
			quotient |= (uint64_t)1 << i;
			dividend ^= CRCPOLY_FULL << i;
		}
	}

	return quotient;
}

/*
 * This program computes the constant multipliers needed for carryless
 * multiplication accelerated CRC-32.  It assumes 128-bit vectors divided into
 * two 64-bit halves which are multiplied separately with different 32-bit
 * multipliers, producing two 95-bit products.  For a given number of 128-bit
 * vectors per iteration, the program outputs a pair of multipliers, one for
 * each 64-bit half.
 *
 * Careful: all polynomials are "bit-reversed", meaning that the low-order bits
 * have the highest degree and the high-order bits have the lowest degree!
 */
int
main(void)
{
	printf("\t/* Constants precomputed by gen_crc32_multipliers.c.  "
	       "Do not edit! */\n");

	/* High and low multipliers for each needed vector count */
	for (int order = 2; order >= 0; order--) {
		int vecs_per_iteration = 1 << order;
		int right = (128 * vecs_per_iteration) + 95;
		printf("\tconst __v2di multipliers_%d = (__v2di)"
		       "{ 0x%08"PRIX32", 0x%08"PRIX32" };\n",
		       vecs_per_iteration,
		       compute_multiplier(right - 64) /* higher degree half */,
		       compute_multiplier(right - 128) /* lower degree half */);
	}

	/* Multiplier for final 96 => 64 bit fold */
	printf("\tconst __v2di final_multiplier = (__v2di){ 0x%08"PRIX32" };\n",
	       compute_multiplier(63));

	/* 32-bit mask */
	printf("\tconst __m128i mask32 = (__m128i)(__v4si){ 0xFFFFFFFF };\n");

	/* Constants for final 64 => 32 bit reduction */
	printf("\tconst __v2di barrett_reduction_constants =\n"
	       "\t\t\t(__v2di){ 0x%016"PRIX64", 0x%016"PRIX64" };\n",
	       compute_barrett_reduction_constant(), CRCPOLY_FULL);

	return 0;
}
