/*
 * crc32_vec_template.h - template for vectorized CRC-32 implementations
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

#define CRC32_SLICE1	1
static u32 crc32_slice1(u32, const u8 *, size_t);

/*
 * Template for vectorized CRC-32 implementations.
 *
 * Note: on unaligned ends of the buffer, we fall back to crc32_slice1() instead
 * of crc32_slice8() because only a few bytes need to be processed, so a smaller
 * table is preferable.
 */
static u32 ATTRIBUTES
FUNCNAME(u32 remainder, const u8 *p, size_t size)
{
	if ((uintptr_t)p % IMPL_ALIGNMENT) {
		size_t n = MIN(size, -(uintptr_t)p % IMPL_ALIGNMENT);

		remainder = crc32_slice1(remainder, p, n);
		p += n;
		size -= n;
	}
	if (size >= IMPL_SEGMENT_SIZE) {
		remainder = FUNCNAME_ALIGNED(remainder, (const void *)p,
					     size / IMPL_SEGMENT_SIZE);
		p += size - (size % IMPL_SEGMENT_SIZE);
		size %= IMPL_SEGMENT_SIZE;
	}
	return crc32_slice1(remainder, p, size);
}

#undef FUNCNAME
#undef FUNCNAME_ALIGNED
#undef ATTRIBUTES
#undef IMPL_ALIGNMENT
#undef IMPL_SEGMENT_SIZE
