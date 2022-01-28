/*
 * test_util.h - utility functions for test programs
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

#ifndef PROGRAMS_TEST_UTIL_H
#define PROGRAMS_TEST_UTIL_H

#include "prog_util.h"

#include <zlib.h> /* for comparison purposes */

#ifdef __GNUC__
# define _noreturn __attribute__((noreturn))
#else
# define _noreturn
#endif

void _noreturn
assertion_failed(const char *expr, const char *file, int line);

#define ASSERT(expr) { if (unlikely(!(expr))) \
	assertion_failed(#expr, __FILE__, __LINE__); }

void begin_performance_test(void);

void alloc_guarded_buffer(size_t size, u8 **start_ret, u8 **end_ret);
void free_guarded_buffer(u8 *start, u8 *end);

u64 timer_ticks(void);
u64 timer_ticks_to_ms(u64 ticks);
u64 timer_MB_per_s(u64 bytes, u64 ticks);
u64 timer_KB_per_s(u64 bytes, u64 ticks);

struct output_bitstream {
	machine_word_t bitbuf;
	int bitcount;
	u8 *next;
	u8 *end;
};

bool put_bits(struct output_bitstream *os, machine_word_t bits, int num_bits);
bool flush_bits(struct output_bitstream *os);

#endif /* PROGRAMS_TEST_UTIL_H */
