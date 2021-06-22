/*
 * arm/adler32_impl.h - ARM implementations of Adler-32 checksum algorithm
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

#ifndef LIB_ARM_ADLER32_IMPL_H
#define LIB_ARM_ADLER32_IMPL_H

#include "cpu_features.h"

/* NEON implementation */
#undef DISPATCH_NEON
#if !defined(DEFAULT_IMPL) &&	\
	(defined(__ARM_NEON) || (ARM_CPU_FEATURES_ENABLED &&	\
				 COMPILER_SUPPORTS_NEON_TARGET_INTRINSICS))
#  define FUNCNAME		adler32_neon
#  define FUNCNAME_CHUNK	adler32_neon_chunk
#  define IMPL_ALIGNMENT	16
#  define IMPL_SEGMENT_SIZE	32
/* Prevent unsigned overflow of the 16-bit precision byte counters */
#  define IMPL_MAX_CHUNK_SIZE	(32 * (0xFFFF / 0xFF))
#  ifdef __ARM_NEON
#    define ATTRIBUTES
#    define DEFAULT_IMPL	adler32_neon
#  else
#    ifdef __arm__
#      define ATTRIBUTES	__attribute__((target("fpu=neon")))
#    else
#      define ATTRIBUTES	__attribute__((target("+simd")))
#    endif
#    define DISPATCH		1
#    define DISPATCH_NEON	1
#  endif
#  include <arm_neon.h>
static forceinline ATTRIBUTES void
adler32_neon_chunk(const uint8x16_t *p, const uint8x16_t * const end,
		   u32 *s1, u32 *s2)
{
	uint32x4_t v_s1 = (uint32x4_t) { 0, 0, 0, 0 };
	uint32x4_t v_s2 = (uint32x4_t) { 0, 0, 0, 0 };
	uint16x8_t v_byte_sums_a = (uint16x8_t) { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint16x8_t v_byte_sums_b = (uint16x8_t) { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint16x8_t v_byte_sums_c = (uint16x8_t) { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint16x8_t v_byte_sums_d = (uint16x8_t) { 0, 0, 0, 0, 0, 0, 0, 0 };

	do {
		const uint8x16_t bytes1 = *p++;
		const uint8x16_t bytes2 = *p++;
		uint16x8_t tmp;

		v_s2 += v_s1;

		/* Vector Pairwise Add Long (u8 => u16) */
		tmp = vpaddlq_u8(bytes1);

		/* Vector Pairwise Add and Accumulate Long (u8 => u16) */
		tmp = vpadalq_u8(tmp, bytes2);

		/* Vector Pairwise Add and Accumulate Long (u16 => u32) */
		v_s1 = vpadalq_u16(v_s1, tmp);

		/* Vector Add Wide (u8 => u16) */
		v_byte_sums_a = vaddw_u8(v_byte_sums_a, vget_low_u8(bytes1));
		v_byte_sums_b = vaddw_u8(v_byte_sums_b, vget_high_u8(bytes1));
		v_byte_sums_c = vaddw_u8(v_byte_sums_c, vget_low_u8(bytes2));
		v_byte_sums_d = vaddw_u8(v_byte_sums_d, vget_high_u8(bytes2));

	} while (p != end);

	/* Vector Shift Left (u32) */
	v_s2 = vqshlq_n_u32(v_s2, 5);

	/* Vector Multiply Accumulate Long (u16 => u32) */
	v_s2 = vmlal_u16(v_s2, vget_low_u16(v_byte_sums_a),  (uint16x4_t) { 32, 31, 30, 29 });
	v_s2 = vmlal_u16(v_s2, vget_high_u16(v_byte_sums_a), (uint16x4_t) { 28, 27, 26, 25 });
	v_s2 = vmlal_u16(v_s2, vget_low_u16(v_byte_sums_b),  (uint16x4_t) { 24, 23, 22, 21 });
	v_s2 = vmlal_u16(v_s2, vget_high_u16(v_byte_sums_b), (uint16x4_t) { 20, 19, 18, 17 });
	v_s2 = vmlal_u16(v_s2, vget_low_u16(v_byte_sums_c),  (uint16x4_t) { 16, 15, 14, 13 });
	v_s2 = vmlal_u16(v_s2, vget_high_u16(v_byte_sums_c), (uint16x4_t) { 12, 11, 10,  9 });
	v_s2 = vmlal_u16(v_s2, vget_low_u16 (v_byte_sums_d), (uint16x4_t) {  8,  7,  6,  5 });
	v_s2 = vmlal_u16(v_s2, vget_high_u16(v_byte_sums_d), (uint16x4_t) {  4,  3,  2,  1 });

	*s1 += v_s1[0] + v_s1[1] + v_s1[2] + v_s1[3];
	*s2 += v_s2[0] + v_s2[1] + v_s2[2] + v_s2[3];
}
#  include "../adler32_vec_template.h"
#endif /* NEON implementation */

#ifdef DISPATCH
static inline adler32_func_t
arch_select_adler32_func(void)
{
	u32 features = get_cpu_features();

#ifdef DISPATCH_NEON
	if (features & ARM_CPU_FEATURE_NEON)
		return adler32_neon;
#endif
	return NULL;
}
#endif /* DISPATCH */

#endif /* LIB_ARM_ADLER32_IMPL_H */
