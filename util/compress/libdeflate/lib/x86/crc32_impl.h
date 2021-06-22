/*
 * x86/crc32_impl.h - x86 implementations of CRC-32 checksum algorithm
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

#ifndef LIB_X86_CRC32_IMPL_H
#define LIB_X86_CRC32_IMPL_H

#include "cpu_features.h"

/*
 * Include the PCLMUL/AVX implementation?  Although our PCLMUL-optimized CRC-32
 * function doesn't use any AVX intrinsics specifically, it can benefit a lot
 * from being compiled for an AVX target: on Skylake, ~16700 MB/s vs. ~10100
 * MB/s.  I expect this is related to the PCLMULQDQ instructions being assembled
 * in the newer three-operand form rather than the older two-operand form.
 *
 * Note: this is only needed if __AVX__ is *not* defined, since otherwise the
 * "regular" PCLMUL implementation would already be AVX enabled.
 */
#undef DISPATCH_PCLMUL_AVX
#if !defined(DEFAULT_IMPL) && !defined(__AVX__) &&	\
	X86_CPU_FEATURES_ENABLED && COMPILER_SUPPORTS_AVX_TARGET &&	\
	(defined(__PCLMUL__) || COMPILER_SUPPORTS_PCLMUL_TARGET_INTRINSICS)
#  define FUNCNAME		crc32_pclmul_avx
#  define FUNCNAME_ALIGNED	crc32_pclmul_avx_aligned
#  define ATTRIBUTES		__attribute__((target("pclmul,avx")))
#  define DISPATCH		1
#  define DISPATCH_PCLMUL_AVX	1
#  include "crc32_pclmul_template.h"
#endif

/* PCLMUL implementation */
#undef DISPATCH_PCLMUL
#if !defined(DEFAULT_IMPL) &&	\
	(defined(__PCLMUL__) || (X86_CPU_FEATURES_ENABLED &&	\
				 COMPILER_SUPPORTS_PCLMUL_TARGET_INTRINSICS))
#  define FUNCNAME		crc32_pclmul
#  define FUNCNAME_ALIGNED	crc32_pclmul_aligned
#  ifdef __PCLMUL__
#    define ATTRIBUTES
#    define DEFAULT_IMPL	crc32_pclmul
#  else
#    define ATTRIBUTES		__attribute__((target("pclmul")))
#    define DISPATCH		1
#    define DISPATCH_PCLMUL	1
#  endif
#  include "crc32_pclmul_template.h"
#endif

#ifdef DISPATCH
static inline crc32_func_t
arch_select_crc32_func(void)
{
	u32 features = get_cpu_features();

#ifdef DISPATCH_PCLMUL_AVX
	if ((features & X86_CPU_FEATURE_PCLMUL) &&
	    (features & X86_CPU_FEATURE_AVX))
		return crc32_pclmul_avx;
#endif
#ifdef DISPATCH_PCLMUL
	if (features & X86_CPU_FEATURE_PCLMUL)
		return crc32_pclmul;
#endif
	return NULL;
}
#endif /* DISPATCH */

#endif /* LIB_X86_CRC32_IMPL_H */
