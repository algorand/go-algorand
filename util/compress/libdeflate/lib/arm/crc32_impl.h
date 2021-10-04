/*
 * arm/crc32_impl.h
 *
 * Copyright 2017 Jun He <jun.he@linaro.org>
 * Copyright 2018 Eric Biggers
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

#ifndef LIB_ARM_CRC32_IMPL_H
#define LIB_ARM_CRC32_IMPL_H

#include "cpu_features.h"

/* Implementation using ARM CRC32 instructions */
#undef DISPATCH_ARM
#if !defined(DEFAULT_IMPL) && \
    (defined(__ARM_FEATURE_CRC32) || \
     (ARM_CPU_FEATURES_ENABLED && COMPILER_SUPPORTS_CRC32_TARGET_INTRINSICS))
#  ifdef __ARM_FEATURE_CRC32
#    define ATTRIBUTES
#    define DEFAULT_IMPL	crc32_arm
#  else
#    ifdef __arm__
#      ifdef __clang__
#        define ATTRIBUTES	__attribute__((target("armv8-a,crc")))
#      else
#        define ATTRIBUTES	__attribute__((target("arch=armv8-a+crc")))
#      endif
#    else
#      ifdef __clang__
#        define ATTRIBUTES	__attribute__((target("crc")))
#      else
#        define ATTRIBUTES	__attribute__((target("+crc")))
#      endif
#    endif
#    define DISPATCH		1
#    define DISPATCH_ARM	1
#  endif

/*
 * gcc's (as of 10.1) version of arm_acle.h for arm32, and clang's (as of
 * 10.0.1) version of arm_acle.h for both arm32 and arm64, have a bug where they
 * only define the CRC32 functions like __crc32b() when __ARM_FEATURE_CRC32 is
 * defined.  That prevents them from being used via __attribute__((target)) when
 * the main target doesn't have CRC32 support enabled.  The actual built-ins
 * like __builtin_arm_crc32b() are available and work, however; it's just the
 * wrappers in arm_acle.h like __crc32b() that erroneously don't get defined.
 * Work around this by manually defining __ARM_FEATURE_CRC32.
 */
#ifndef __ARM_FEATURE_CRC32
#  define __ARM_FEATURE_CRC32	1
#endif
#include <arm_acle.h>

static u32 ATTRIBUTES
crc32_arm(u32 remainder, const u8 *p, size_t size)
{
	while (size != 0 && (uintptr_t)p & 7) {
		remainder = __crc32b(remainder, *p++);
		size--;
	}

	while (size >= 32) {
		remainder = __crc32d(remainder, le64_bswap(*((u64 *)p + 0)));
		remainder = __crc32d(remainder, le64_bswap(*((u64 *)p + 1)));
		remainder = __crc32d(remainder, le64_bswap(*((u64 *)p + 2)));
		remainder = __crc32d(remainder, le64_bswap(*((u64 *)p + 3)));
		p += 32;
		size -= 32;
	}

	while (size >= 8) {
		remainder = __crc32d(remainder, le64_bswap(*(u64 *)p));
		p += 8;
		size -= 8;
	}

	while (size != 0) {
		remainder = __crc32b(remainder, *p++);
		size--;
	}

	return remainder;
}
#undef ATTRIBUTES
#endif /* Implementation using ARM CRC32 instructions */

/*
 * CRC-32 folding with ARM Crypto extension-PMULL
 *
 * This works the same way as the x86 PCLMUL version.
 * See x86/crc32_pclmul_template.h for an explanation.
 */
#undef DISPATCH_PMULL
#if !defined(DEFAULT_IMPL) && \
    (defined(__ARM_FEATURE_CRYPTO) ||	\
     (ARM_CPU_FEATURES_ENABLED &&	\
      COMPILER_SUPPORTS_PMULL_TARGET_INTRINSICS)) && \
      /* not yet tested on big endian, probably needs changes to work there */ \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define FUNCNAME		crc32_pmull
#  define FUNCNAME_ALIGNED	crc32_pmull_aligned
#  ifdef __ARM_FEATURE_CRYPTO
#    define ATTRIBUTES
#    define DEFAULT_IMPL	crc32_pmull
#  else
#    ifdef __arm__
#      define ATTRIBUTES	__attribute__((target("fpu=crypto-neon-fp-armv8")))
#    else
#      ifdef __clang__
#        define ATTRIBUTES	__attribute__((target("crypto")))
#      else
#        define ATTRIBUTES	__attribute__((target("+crypto")))
#      endif
#    endif
#    define DISPATCH		1
#    define DISPATCH_PMULL	1
#  endif

#include <arm_neon.h>

static forceinline ATTRIBUTES uint8x16_t
clmul_00(uint8x16_t a, uint8x16_t b)
{
	return (uint8x16_t)vmull_p64((poly64_t)vget_low_u8(a),
				     (poly64_t)vget_low_u8(b));
}

static forceinline ATTRIBUTES uint8x16_t
clmul_10(uint8x16_t a, uint8x16_t b)
{
	return (uint8x16_t)vmull_p64((poly64_t)vget_low_u8(a),
				     (poly64_t)vget_high_u8(b));
}

static forceinline ATTRIBUTES uint8x16_t
clmul_11(uint8x16_t a, uint8x16_t b)
{
	return (uint8x16_t)vmull_high_p64((poly64x2_t)a, (poly64x2_t)b);
}

static forceinline ATTRIBUTES uint8x16_t
fold_128b(uint8x16_t dst, uint8x16_t src, uint8x16_t multipliers)
{
	return dst ^ clmul_00(src, multipliers) ^ clmul_11(src, multipliers);
}

static forceinline ATTRIBUTES u32
crc32_pmull_aligned(u32 remainder, const uint8x16_t *p, size_t nr_segs)
{
	/* Constants precomputed by gen_crc32_multipliers.c.  Do not edit! */
	const uint8x16_t multipliers_4 =
		(uint8x16_t)(uint64x2_t){ 0x8F352D95, 0x1D9513D7 };
	const uint8x16_t multipliers_1 =
		(uint8x16_t)(uint64x2_t){ 0xAE689191, 0xCCAA009E };
	const uint8x16_t final_multiplier =
		(uint8x16_t)(uint64x2_t){ 0xB8BC6765 };
	const uint8x16_t mask32 = (uint8x16_t)(uint32x4_t){ 0xFFFFFFFF };
	const uint8x16_t barrett_reduction_constants =
			(uint8x16_t)(uint64x2_t){ 0x00000001F7011641,
						  0x00000001DB710641 };
	const uint8x16_t zeroes = (uint8x16_t){ 0 };

	const uint8x16_t * const end = p + nr_segs;
	const uint8x16_t * const end512 = p + (nr_segs & ~3);
	uint8x16_t x0, x1, x2, x3;

	x0 = *p++ ^ (uint8x16_t)(uint32x4_t){ remainder };
	if (nr_segs >= 4) {
		x1 = *p++;
		x2 = *p++;
		x3 = *p++;

		/* Fold 512 bits at a time */
		while (p != end512) {
			x0 = fold_128b(*p++, x0, multipliers_4);
			x1 = fold_128b(*p++, x1, multipliers_4);
			x2 = fold_128b(*p++, x2, multipliers_4);
			x3 = fold_128b(*p++, x3, multipliers_4);
		}

		/* Fold 512 bits => 128 bits */
		x1 = fold_128b(x1, x0, multipliers_1);
		x2 = fold_128b(x2, x1, multipliers_1);
		x0 = fold_128b(x3, x2, multipliers_1);
	}

	/* Fold 128 bits at a time */
	while (p != end)
		x0 = fold_128b(*p++, x0, multipliers_1);

	/* Fold 128 => 96 bits, implicitly appending 32 zeroes */
	x0 = vextq_u8(x0, zeroes, 8) ^ clmul_10(x0, multipliers_1);

	/* Fold 96 => 64 bits */
	x0 = vextq_u8(x0, zeroes, 4) ^ clmul_00(x0 & mask32, final_multiplier);

	/* Reduce 64 => 32 bits using Barrett reduction */
	x1 = x0;
	x0 = clmul_00(x0 & mask32, barrett_reduction_constants);
	x0 = clmul_10(x0 & mask32, barrett_reduction_constants);
	return vgetq_lane_u32((uint32x4_t)(x0 ^ x1), 1);
}
#define IMPL_ALIGNMENT		16
#define IMPL_SEGMENT_SIZE	16
#include "../crc32_vec_template.h"
#endif /* PMULL implementation */

#ifdef DISPATCH
static inline crc32_func_t
arch_select_crc32_func(void)
{
	u32 features = get_cpu_features();

#ifdef DISPATCH_ARM
	if (features & ARM_CPU_FEATURE_CRC32)
		return crc32_arm;
#endif
#ifdef DISPATCH_PMULL
	if (features & ARM_CPU_FEATURE_PMULL)
		return crc32_pmull;
#endif
	return NULL;
}
#endif /* DISPATCH */

#endif /* LIB_ARM_CRC32_IMPL_H */
