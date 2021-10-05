/*
 * decompress_template.h
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
 * This is the actual DEFLATE decompression routine, lifted out of
 * deflate_decompress.c so that it can be compiled multiple times with different
 * target instruction sets.
 */

static enum libdeflate_result ATTRIBUTES
FUNCNAME(struct libdeflate_decompressor * restrict d,
	 const void * restrict in, size_t in_nbytes,
	 void * restrict out, size_t out_nbytes_avail,
	 size_t *actual_in_nbytes_ret, size_t *actual_out_nbytes_ret)
{
	u8 *out_next = out;
	u8 * const out_end = out_next + out_nbytes_avail;
	const u8 *in_next = in;
	const u8 * const in_end = in_next + in_nbytes;
	bitbuf_t bitbuf = 0;
	unsigned bitsleft = 0;
	size_t overrun_count = 0;
	unsigned i;
	unsigned is_final_block;
	unsigned block_type;
	u16 len;
	u16 nlen;
	unsigned num_litlen_syms;
	unsigned num_offset_syms;
	u16 tmp16;
	u32 tmp32;

next_block:
	/* Starting to read the next block.  */
	;

	STATIC_ASSERT(CAN_ENSURE(1 + 2 + 5 + 5 + 4));
	ENSURE_BITS(1 + 2 + 5 + 5 + 4);

	/* BFINAL: 1 bit  */
	is_final_block = POP_BITS(1);

	/* BTYPE: 2 bits  */
	block_type = POP_BITS(2);

	if (block_type == DEFLATE_BLOCKTYPE_DYNAMIC_HUFFMAN) {

		/* Dynamic Huffman block.  */

		/* The order in which precode lengths are stored.  */
		static const u8 deflate_precode_lens_permutation[DEFLATE_NUM_PRECODE_SYMS] = {
			16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
		};

		unsigned num_explicit_precode_lens;

		/* Read the codeword length counts.  */

		STATIC_ASSERT(DEFLATE_NUM_LITLEN_SYMS == ((1 << 5) - 1) + 257);
		num_litlen_syms = POP_BITS(5) + 257;

		STATIC_ASSERT(DEFLATE_NUM_OFFSET_SYMS == ((1 << 5) - 1) + 1);
		num_offset_syms = POP_BITS(5) + 1;

		STATIC_ASSERT(DEFLATE_NUM_PRECODE_SYMS == ((1 << 4) - 1) + 4);
		num_explicit_precode_lens = POP_BITS(4) + 4;

		d->static_codes_loaded = false;

		/* Read the precode codeword lengths.  */
		STATIC_ASSERT(DEFLATE_MAX_PRE_CODEWORD_LEN == (1 << 3) - 1);
		for (i = 0; i < num_explicit_precode_lens; i++) {
			ENSURE_BITS(3);
			d->u.precode_lens[deflate_precode_lens_permutation[i]] = POP_BITS(3);
		}

		for (; i < DEFLATE_NUM_PRECODE_SYMS; i++)
			d->u.precode_lens[deflate_precode_lens_permutation[i]] = 0;

		/* Build the decode table for the precode.  */
		SAFETY_CHECK(build_precode_decode_table(d));

		/* Expand the literal/length and offset codeword lengths.  */
		for (i = 0; i < num_litlen_syms + num_offset_syms; ) {
			u32 entry;
			unsigned presym;
			u8 rep_val;
			unsigned rep_count;

			ENSURE_BITS(DEFLATE_MAX_PRE_CODEWORD_LEN + 7);

			/* (The code below assumes that the precode decode table
			 * does not have any subtables.)  */
			STATIC_ASSERT(PRECODE_TABLEBITS == DEFLATE_MAX_PRE_CODEWORD_LEN);

			/* Read the next precode symbol.  */
			entry = d->u.l.precode_decode_table[BITS(DEFLATE_MAX_PRE_CODEWORD_LEN)];
			REMOVE_BITS(entry & HUFFDEC_LENGTH_MASK);
			presym = entry >> HUFFDEC_RESULT_SHIFT;

			if (presym < 16) {
				/* Explicit codeword length  */
				d->u.l.lens[i++] = presym;
				continue;
			}

			/* Run-length encoded codeword lengths  */

			/* Note: we don't need verify that the repeat count
			 * doesn't overflow the number of elements, since we
			 * have enough extra spaces to allow for the worst-case
			 * overflow (138 zeroes when only 1 length was
			 * remaining).
			 *
			 * In the case of the small repeat counts (presyms 16
			 * and 17), it is fastest to always write the maximum
			 * number of entries.  That gets rid of branches that
			 * would otherwise be required.
			 *
			 * It is not just because of the numerical order that
			 * our checks go in the order 'presym < 16', 'presym ==
			 * 16', and 'presym == 17'.  For typical data this is
			 * ordered from most frequent to least frequent case.
			 */
			STATIC_ASSERT(DEFLATE_MAX_LENS_OVERRUN == 138 - 1);

			if (presym == 16) {
				/* Repeat the previous length 3 - 6 times  */
				SAFETY_CHECK(i != 0);
				rep_val = d->u.l.lens[i - 1];
				STATIC_ASSERT(3 + ((1 << 2) - 1) == 6);
				rep_count = 3 + POP_BITS(2);
				d->u.l.lens[i + 0] = rep_val;
				d->u.l.lens[i + 1] = rep_val;
				d->u.l.lens[i + 2] = rep_val;
				d->u.l.lens[i + 3] = rep_val;
				d->u.l.lens[i + 4] = rep_val;
				d->u.l.lens[i + 5] = rep_val;
				i += rep_count;
			} else if (presym == 17) {
				/* Repeat zero 3 - 10 times  */
				STATIC_ASSERT(3 + ((1 << 3) - 1) == 10);
				rep_count = 3 + POP_BITS(3);
				d->u.l.lens[i + 0] = 0;
				d->u.l.lens[i + 1] = 0;
				d->u.l.lens[i + 2] = 0;
				d->u.l.lens[i + 3] = 0;
				d->u.l.lens[i + 4] = 0;
				d->u.l.lens[i + 5] = 0;
				d->u.l.lens[i + 6] = 0;
				d->u.l.lens[i + 7] = 0;
				d->u.l.lens[i + 8] = 0;
				d->u.l.lens[i + 9] = 0;
				i += rep_count;
			} else {
				/* Repeat zero 11 - 138 times  */
				STATIC_ASSERT(11 + ((1 << 7) - 1) == 138);
				rep_count = 11 + POP_BITS(7);
				memset(&d->u.l.lens[i], 0,
				       rep_count * sizeof(d->u.l.lens[i]));
				i += rep_count;
			}
		}
	} else if (block_type == DEFLATE_BLOCKTYPE_UNCOMPRESSED) {

		/* Uncompressed block: copy 'len' bytes literally from the input
		 * buffer to the output buffer.  */

		ALIGN_INPUT();

		SAFETY_CHECK(in_end - in_next >= 4);

		len = READ_U16();
		nlen = READ_U16();

		SAFETY_CHECK(len == (u16)~nlen);
		if (unlikely(len > out_end - out_next))
			return LIBDEFLATE_INSUFFICIENT_SPACE;
		SAFETY_CHECK(len <= in_end - in_next);

		memcpy(out_next, in_next, len);
		in_next += len;
		out_next += len;

		goto block_done;

	} else {
		SAFETY_CHECK(block_type == DEFLATE_BLOCKTYPE_STATIC_HUFFMAN);

		/*
		 * Static Huffman block: build the decode tables for the static
		 * codes.  Skip doing so if the tables are already set up from
		 * an earlier static block; this speeds up decompression of
		 * degenerate input of many empty or very short static blocks.
		 *
		 * Afterwards, the remainder is the same as decompressing a
		 * dynamic Huffman block.
		 */

		if (d->static_codes_loaded)
			goto have_decode_tables;

		d->static_codes_loaded = true;

		STATIC_ASSERT(DEFLATE_NUM_LITLEN_SYMS == 288);
		STATIC_ASSERT(DEFLATE_NUM_OFFSET_SYMS == 32);

		for (i = 0; i < 144; i++)
			d->u.l.lens[i] = 8;
		for (; i < 256; i++)
			d->u.l.lens[i] = 9;
		for (; i < 280; i++)
			d->u.l.lens[i] = 7;
		for (; i < 288; i++)
			d->u.l.lens[i] = 8;

		for (; i < 288 + 32; i++)
			d->u.l.lens[i] = 5;

		num_litlen_syms = 288;
		num_offset_syms = 32;
	}

	/* Decompressing a Huffman block (either dynamic or static)  */

	SAFETY_CHECK(build_offset_decode_table(d, num_litlen_syms, num_offset_syms));
	SAFETY_CHECK(build_litlen_decode_table(d, num_litlen_syms, num_offset_syms));
have_decode_tables:

	/* The main DEFLATE decode loop  */
	for (;;) {
		u32 entry;
		u32 length;
		u32 offset;
		const u8 *src;
		u8 *dst;

		/* Decode a litlen symbol.  */
		ENSURE_BITS(DEFLATE_MAX_LITLEN_CODEWORD_LEN);
		entry = d->u.litlen_decode_table[BITS(LITLEN_TABLEBITS)];
		if (entry & HUFFDEC_SUBTABLE_POINTER) {
			/* Litlen subtable required (uncommon case)  */
			REMOVE_BITS(LITLEN_TABLEBITS);
			entry = d->u.litlen_decode_table[
				((entry >> HUFFDEC_RESULT_SHIFT) & 0xFFFF) +
				BITS(entry & HUFFDEC_LENGTH_MASK)];
		}
		REMOVE_BITS(entry & HUFFDEC_LENGTH_MASK);
		if (entry & HUFFDEC_LITERAL) {
			/* Literal  */
			if (unlikely(out_next == out_end))
				return LIBDEFLATE_INSUFFICIENT_SPACE;
			*out_next++ = (u8)(entry >> HUFFDEC_RESULT_SHIFT);
			continue;
		}

		/* Match or end-of-block  */

		entry >>= HUFFDEC_RESULT_SHIFT;
		ENSURE_BITS(MAX_ENSURE);

		/* Pop the extra length bits and add them to the length base to
		 * produce the full length.  */
		length = (entry >> HUFFDEC_LENGTH_BASE_SHIFT) +
			 POP_BITS(entry & HUFFDEC_EXTRA_LENGTH_BITS_MASK);

		/* The match destination must not end after the end of the
		 * output buffer.  For efficiency, combine this check with the
		 * end-of-block check.  We're using 0 for the special
		 * end-of-block length, so subtract 1 and it turn it into
		 * SIZE_MAX.  */
		STATIC_ASSERT(HUFFDEC_END_OF_BLOCK_LENGTH == 0);
		if (unlikely((size_t)length - 1 >= out_end - out_next)) {
			if (unlikely(length != HUFFDEC_END_OF_BLOCK_LENGTH))
				return LIBDEFLATE_INSUFFICIENT_SPACE;
			goto block_done;
		}

		/* Decode the match offset.  */

		entry = d->offset_decode_table[BITS(OFFSET_TABLEBITS)];
		if (entry & HUFFDEC_SUBTABLE_POINTER) {
			/* Offset subtable required (uncommon case)  */
			REMOVE_BITS(OFFSET_TABLEBITS);
			entry = d->offset_decode_table[
				((entry >> HUFFDEC_RESULT_SHIFT) & 0xFFFF) +
				BITS(entry & HUFFDEC_LENGTH_MASK)];
		}
		REMOVE_BITS(entry & HUFFDEC_LENGTH_MASK);
		entry >>= HUFFDEC_RESULT_SHIFT;

		STATIC_ASSERT(CAN_ENSURE(DEFLATE_MAX_EXTRA_LENGTH_BITS +
					 DEFLATE_MAX_OFFSET_CODEWORD_LEN) &&
			      CAN_ENSURE(DEFLATE_MAX_EXTRA_OFFSET_BITS));
		if (!CAN_ENSURE(DEFLATE_MAX_EXTRA_LENGTH_BITS +
				DEFLATE_MAX_OFFSET_CODEWORD_LEN +
				DEFLATE_MAX_EXTRA_OFFSET_BITS))
			ENSURE_BITS(DEFLATE_MAX_EXTRA_OFFSET_BITS);

		/* Pop the extra offset bits and add them to the offset base to
		 * produce the full offset.  */
		offset = (entry & HUFFDEC_OFFSET_BASE_MASK) +
			 POP_BITS(entry >> HUFFDEC_EXTRA_OFFSET_BITS_SHIFT);

		/* The match source must not begin before the beginning of the
		 * output buffer.  */
		SAFETY_CHECK(offset <= out_next - (const u8 *)out);

		/*
		 * Copy the match: 'length' bytes at 'out_next - offset' to
		 * 'out_next', possibly overlapping.  If the match doesn't end
		 * too close to the end of the buffer and offset >= WORDBYTES ||
		 * offset == 1, take a fast path which copies a word at a time
		 * -- potentially more than the length of the match, but that's
		 * fine as long as we check for enough extra space.
		 *
		 * The remaining cases are not performance-critical so are
		 * handled by a simple byte-by-byte copy.
		 */

		src = out_next - offset;
		dst = out_next;
		out_next += length;

		if (UNALIGNED_ACCESS_IS_FAST &&
		    /* max overrun is writing 3 words for a min length match */
		    likely(out_end - out_next >=
			   3 * WORDBYTES - DEFLATE_MIN_MATCH_LEN)) {
			if (offset >= WORDBYTES) { /* words don't overlap? */
				copy_word_unaligned(src, dst);
				src += WORDBYTES;
				dst += WORDBYTES;
				copy_word_unaligned(src, dst);
				src += WORDBYTES;
				dst += WORDBYTES;
				do {
					copy_word_unaligned(src, dst);
					src += WORDBYTES;
					dst += WORDBYTES;
				} while (dst < out_next);
			} else if (offset == 1) {
				/* RLE encoding of previous byte, common if the
				 * data contains many repeated bytes */
				machine_word_t v = repeat_byte(*src);

				store_word_unaligned(v, dst);
				dst += WORDBYTES;
				store_word_unaligned(v, dst);
				dst += WORDBYTES;
				do {
					store_word_unaligned(v, dst);
					dst += WORDBYTES;
				} while (dst < out_next);
			} else {
				*dst++ = *src++;
				*dst++ = *src++;
				do {
					*dst++ = *src++;
				} while (dst < out_next);
			}
		} else {
			STATIC_ASSERT(DEFLATE_MIN_MATCH_LEN == 3);
			*dst++ = *src++;
			*dst++ = *src++;
			do {
				*dst++ = *src++;
			} while (dst < out_next);
		}
	}

block_done:
	/* Finished decoding a block.  */

	if (!is_final_block)
		goto next_block;

	/* That was the last block.  */

	/* Discard any readahead bits and check for excessive overread */
	ALIGN_INPUT();

	/* Optionally return the actual number of bytes read */
	if (actual_in_nbytes_ret)
		*actual_in_nbytes_ret = in_next - (u8 *)in;

	/* Optionally return the actual number of bytes written */
	if (actual_out_nbytes_ret) {
		*actual_out_nbytes_ret = out_next - (u8 *)out;
	} else {
		if (out_next != out_end)
			return LIBDEFLATE_SHORT_OUTPUT;
	}
	return LIBDEFLATE_SUCCESS;
}

#undef FUNCNAME
#undef ATTRIBUTES
