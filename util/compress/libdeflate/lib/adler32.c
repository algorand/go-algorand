/*
 * adler32.c - Adler-32 checksum algorithm
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

#include "lib_common.h"
#include "libdeflate.h"

/* The Adler-32 divisor, or "base", value. */
#define DIVISOR 65521

/*
 * MAX_CHUNK_SIZE is the most bytes that can be processed without the
 * possibility of s2 overflowing when it is represented as an unsigned 32-bit
 * integer.  This value was computed using the following Python script:
 *
 *	divisor = 65521
 *	count = 0
 *	s1 = divisor - 1
 *	s2 = divisor - 1
 *	while True:
 *		s1 += 0xFF
 *		s2 += s1
 *		if s2 > 0xFFFFFFFF:
 *			break
 *		count += 1
 *	print(count)
 *
 * Note that to get the correct worst-case value, we must assume that every byte
 * has value 0xFF and that s1 and s2 started with the highest possible values
 * modulo the divisor.
 */
#define MAX_CHUNK_SIZE	5552

typedef u32 (*adler32_func_t)(u32, const u8 *, size_t);

/* Include architecture-specific implementations if available */
#undef DEFAULT_IMPL
#undef DISPATCH
#if defined(__arm__) || defined(__aarch64__)
#  include "arm/adler32_impl.h"
#elif defined(__i386__) || defined(__x86_64__)
#  include "x86/adler32_impl.h"
#endif

/* Define a generic implementation if needed */
#ifndef DEFAULT_IMPL
#define DEFAULT_IMPL adler32_generic
static u32 adler32_generic(u32 adler, const u8 *p, size_t size)
{
	u32 s1 = adler & 0xFFFF;
	u32 s2 = adler >> 16;
	const u8 * const end = p + size;

	while (p != end) {
		size_t chunk_size = MIN(end - p, MAX_CHUNK_SIZE);
		const u8 *chunk_end = p + chunk_size;
		size_t num_unrolled_iterations = chunk_size / 4;

		while (num_unrolled_iterations--) {
			s1 += *p++;
			s2 += s1;
			s1 += *p++;
			s2 += s1;
			s1 += *p++;
			s2 += s1;
			s1 += *p++;
			s2 += s1;
		}
		while (p != chunk_end) {
			s1 += *p++;
			s2 += s1;
		}
		s1 %= DIVISOR;
		s2 %= DIVISOR;
	}

	return (s2 << 16) | s1;
}
#endif /* !DEFAULT_IMPL */

#ifdef DISPATCH
static u32 dispatch(u32, const u8 *, size_t);

static volatile adler32_func_t adler32_impl = dispatch;

/* Choose the fastest implementation at runtime */
static u32 dispatch(u32 adler, const u8 *buffer, size_t size)
{
	adler32_func_t f = arch_select_adler32_func();

	if (f == NULL)
		f = DEFAULT_IMPL;

	adler32_impl = f;
	return adler32_impl(adler, buffer, size);
}
#else
#  define adler32_impl DEFAULT_IMPL /* only one implementation, use it */
#endif

LIBDEFLATEEXPORT u32 LIBDEFLATEAPI
libdeflate_adler32(u32 adler, const void *buffer, size_t size)
{
	if (buffer == NULL) /* return initial value */
		return 1;
	return adler32_impl(adler, buffer, size);
}
