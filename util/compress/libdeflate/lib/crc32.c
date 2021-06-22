/*
 * crc32.c - CRC-32 checksum algorithm for the gzip format
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

/*
 * High-level description of CRC
 * =============================
 *
 * Consider a bit sequence 'bits[1...len]'.  Interpret 'bits' as the "message"
 * polynomial M(x) with coefficients in GF(2) (the field of integers modulo 2),
 * where the coefficient of 'x^i' is 'bits[len - i]'.  Then, compute:
 *
 *			R(x) = M(x)*x^n mod G(x)
 *
 * where G(x) is a selected "generator" polynomial of degree 'n'.  The remainder
 * R(x) is a polynomial of max degree 'n - 1'.  The CRC of 'bits' is R(x)
 * interpreted as a bitstring of length 'n'.
 *
 * CRC used in gzip
 * ================
 *
 * In the gzip format (RFC 1952):
 *
 *	- The bitstring to checksum is formed from the bytes of the uncompressed
 *	  data by concatenating the bits from the bytes in order, proceeding
 *	  from the low-order bit to the high-order bit within each byte.
 *
 *	- The generator polynomial G(x) is: x^32 + x^26 + x^23 + x^22 + x^16 +
 *	  x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1.
 *	  Consequently, the CRC length is 32 bits ("CRC-32").
 *
 *	- The highest order 32 coefficients of M(x)*x^n are inverted.
 *
 *	- All 32 coefficients of R(x) are inverted.
 *
 * The two inversions cause added leading and trailing zero bits to affect the
 * resulting CRC, whereas with a regular CRC such bits would have no effect on
 * the CRC.
 *
 * Computation and optimizations
 * =============================
 *
 * We can compute R(x) through "long division", maintaining only 32 bits of
 * state at any given time.  Multiplication by 'x' can be implemented as
 * right-shifting by 1 (assuming the polynomial<=>bitstring mapping where the
 * highest order bit represents the coefficient of x^0), and both addition and
 * subtraction can be implemented as bitwise exclusive OR (since we are working
 * in GF(2)).  Here is an unoptimized implementation:
 *
 *	static u32 crc32_gzip(const u8 *buffer, size_t size)
 *	{
 *		u32 remainder = 0;
 *		const u32 divisor = 0xEDB88320;
 *
 *		for (size_t i = 0; i < size * 8 + 32; i++) {
 *			int bit;
 *			u32 multiple;
 *
 *			if (i < size * 8)
 *				bit = (buffer[i / 8] >> (i % 8)) & 1;
 *			else
 *				bit = 0; // one of the 32 appended 0 bits
 *
 *			if (i < 32) // the first 32 bits are inverted
 *				bit ^= 1;
 *
 *			if (remainder & 1)
 *				multiple = divisor;
 *			else
 *				multiple = 0;
 *
 *			remainder >>= 1;
 *			remainder |= (u32)bit << 31;
 *			remainder ^= multiple;
 *		}
 *
 *		return ~remainder;
 *	}
 *
 * In this implementation, the 32-bit integer 'remainder' maintains the
 * remainder of the currently processed portion of the message (with 32 zero
 * bits appended) when divided by the generator polynomial.  'remainder' is the
 * representation of R(x), and 'divisor' is the representation of G(x) excluding
 * the x^32 coefficient.  For each bit to process, we multiply R(x) by 'x^1',
 * then add 'x^0' if the new bit is a 1.  If this causes R(x) to gain a nonzero
 * x^32 term, then we subtract G(x) from R(x).
 *
 * We can speed this up by taking advantage of the fact that XOR is commutative
 * and associative, so the order in which we combine the inputs into 'remainder'
 * is unimportant.  And since each message bit we add doesn't affect the choice
 * of 'multiple' until 32 bits later, we need not actually add each message bit
 * until that point:
 *
 *	static u32 crc32_gzip(const u8 *buffer, size_t size)
 *	{
 *		u32 remainder = ~0;
 *		const u32 divisor = 0xEDB88320;
 *
 *		for (size_t i = 0; i < size * 8; i++) {
 *			int bit;
 *			u32 multiple;
 *
 *			bit = (buffer[i / 8] >> (i % 8)) & 1;
 *			remainder ^= bit;
 *			if (remainder & 1)
 *				multiple = divisor;
 *			else
 *				multiple = 0;
 *			remainder >>= 1;
 *			remainder ^= multiple;
 *		}
 *
 *		return ~remainder;
 *	}
 *
 * With the above implementation we get the effect of 32 appended 0 bits for
 * free; they never affect the choice of a divisor, nor would they change the
 * value of 'remainder' if they were to be actually XOR'ed in.  And by starting
 * with a remainder of all 1 bits, we get the effect of complementing the first
 * 32 message bits.
 *
 * The next optimization is to process the input in multi-bit units.  Suppose
 * that we insert the next 'n' message bits into the remainder.  Then we get an
 * intermediate remainder of length '32 + n' bits, and the CRC of the extra 'n'
 * bits is the amount by which the low 32 bits of the remainder will change as a
 * result of cancelling out those 'n' bits.  Taking n=8 (one byte) and
 * precomputing a table containing the CRC of each possible byte, we get
 * crc32_slice1() defined below.
 *
 * As a further optimization, we could increase the multi-bit unit size to 16.
 * However, that is inefficient because the table size explodes from 256 entries
 * (1024 bytes) to 65536 entries (262144 bytes), which wastes memory and won't
 * fit in L1 cache on typical processors.
 *
 * However, we can actually process 4 bytes at a time using 4 different tables
 * with 256 entries each.  Logically, we form a 64-bit intermediate remainder
 * and cancel out the high 32 bits in 8-bit chunks.  Bits 32-39 are cancelled
 * out by the CRC of those bits, whereas bits 40-47 are be cancelled out by the
 * CRC of those bits with 8 zero bits appended, and so on.  This method is
 * implemented in crc32_slice4(), defined below.
 *
 * In crc32_slice8(), this method is extended to 8 bytes at a time.  The
 * intermediate remainder (which we never actually store explicitly) is 96 bits.
 *
 * On CPUs that support fast carryless multiplication, CRCs can be computed even
 * more quickly via "folding".  See e.g. the x86 PCLMUL implementation.
 */

#include "lib_common.h"
#include "libdeflate.h"

typedef u32 (*crc32_func_t)(u32, const u8 *, size_t);

/* Include architecture-specific implementations if available */
#undef CRC32_SLICE1
#undef CRC32_SLICE4
#undef CRC32_SLICE8
#undef DEFAULT_IMPL
#undef DISPATCH
#if defined(__arm__) || defined(__aarch64__)
#  include "arm/crc32_impl.h"
#elif defined(__i386__) || defined(__x86_64__)
#  include "x86/crc32_impl.h"
#endif

/*
 * Define a generic implementation (crc32_slice8()) if needed.  crc32_slice1()
 * may also be needed as a fallback for architecture-specific implementations.
 */

#ifndef DEFAULT_IMPL
#  define CRC32_SLICE8	1
#  define DEFAULT_IMPL	crc32_slice8
#endif

#if defined(CRC32_SLICE1) || defined(CRC32_SLICE4) || defined(CRC32_SLICE8)
#include "crc32_table.h"
static forceinline u32
crc32_update_byte(u32 remainder, u8 next_byte)
{
	return (remainder >> 8) ^ crc32_table[(u8)remainder ^ next_byte];
}
#endif

#ifdef CRC32_SLICE1
static u32
crc32_slice1(u32 remainder, const u8 *buffer, size_t size)
{
	size_t i;

	STATIC_ASSERT(ARRAY_LEN(crc32_table) >= 0x100);

	for (i = 0; i < size; i++)
		remainder = crc32_update_byte(remainder, buffer[i]);
	return remainder;
}
#endif /* CRC32_SLICE1 */

#ifdef CRC32_SLICE4
static u32
crc32_slice4(u32 remainder, const u8 *buffer, size_t size)
{
	const u8 *p = buffer;
	const u8 *end = buffer + size;
	const u8 *end32;

	STATIC_ASSERT(ARRAY_LEN(crc32_table) >= 0x400);

	for (; ((uintptr_t)p & 3) && p != end; p++)
		remainder = crc32_update_byte(remainder, *p);

	end32 = p + ((end - p) & ~3);
	for (; p != end32; p += 4) {
		u32 v = le32_bswap(*(const u32 *)p);
		remainder =
		    crc32_table[0x300 + (u8)((remainder ^ v) >>  0)] ^
		    crc32_table[0x200 + (u8)((remainder ^ v) >>  8)] ^
		    crc32_table[0x100 + (u8)((remainder ^ v) >> 16)] ^
		    crc32_table[0x000 + (u8)((remainder ^ v) >> 24)];
	}

	for (; p != end; p++)
		remainder = crc32_update_byte(remainder, *p);

	return remainder;
}
#endif /* CRC32_SLICE4 */

#ifdef CRC32_SLICE8
static u32
crc32_slice8(u32 remainder, const u8 *buffer, size_t size)
{
	const u8 *p = buffer;
	const u8 *end = buffer + size;
	const u8 *end64;

	STATIC_ASSERT(ARRAY_LEN(crc32_table) >= 0x800);

	for (; ((uintptr_t)p & 7) && p != end; p++)
		remainder = crc32_update_byte(remainder, *p);

	end64 = p + ((end - p) & ~7);
	for (; p != end64; p += 8) {
		u32 v1 = le32_bswap(*(const u32 *)(p + 0));
		u32 v2 = le32_bswap(*(const u32 *)(p + 4));
		remainder =
		    crc32_table[0x700 + (u8)((remainder ^ v1) >>  0)] ^
		    crc32_table[0x600 + (u8)((remainder ^ v1) >>  8)] ^
		    crc32_table[0x500 + (u8)((remainder ^ v1) >> 16)] ^
		    crc32_table[0x400 + (u8)((remainder ^ v1) >> 24)] ^
		    crc32_table[0x300 + (u8)(v2 >>  0)] ^
		    crc32_table[0x200 + (u8)(v2 >>  8)] ^
		    crc32_table[0x100 + (u8)(v2 >> 16)] ^
		    crc32_table[0x000 + (u8)(v2 >> 24)];
	}

	for (; p != end; p++)
		remainder = crc32_update_byte(remainder, *p);

	return remainder;
}
#endif /* CRC32_SLICE8 */

#ifdef DISPATCH
static u32 dispatch(u32, const u8 *, size_t);

static volatile crc32_func_t crc32_impl = dispatch;

/* Choose the fastest implementation at runtime */
static u32 dispatch(u32 remainder, const u8 *buffer, size_t size)
{
	crc32_func_t f = arch_select_crc32_func();

	if (f == NULL)
		f = DEFAULT_IMPL;

	crc32_impl = f;
	return crc32_impl(remainder, buffer, size);
}
#else
#  define crc32_impl DEFAULT_IMPL /* only one implementation, use it */
#endif

LIBDEFLATEEXPORT u32 LIBDEFLATEAPI
libdeflate_crc32(u32 remainder, const void *buffer, size_t size)
{
	if (buffer == NULL) /* return initial value */
		return 0;
	return ~crc32_impl(~remainder, buffer, size);
}
