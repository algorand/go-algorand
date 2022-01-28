/*
 * test_util.c - utility functions for test programs
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

#ifndef _WIN32
/* for MAP_ANONYMOUS or MAP_ANON, which unfortunately aren't part of POSIX... */
#  undef _POSIX_C_SOURCE
#  ifdef __APPLE__
#    define _DARWIN_C_SOURCE
#  elif defined(__linux__)
#    define _GNU_SOURCE
#  endif
#endif

#include "test_util.h"

#include <fcntl.h>
#include <time.h>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/mman.h>
#  include <sys/time.h>
#endif

#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#endif

/* Abort with an error message */
_noreturn void
assertion_failed(const char *expr, const char *file, int line)
{
	msg("Assertion failed: %s at %s:%d", expr, file, line);
	abort();
}

void
begin_performance_test(void)
{
	/* Skip performance tests by default, since they can be flaky. */
	if (getenv("INCLUDE_PERF_TESTS") == NULL)
		exit(0);
}

static size_t
get_page_size(void)
{
#ifdef _WIN32
	SYSTEM_INFO info;

	GetSystemInfo(&info);
	return info.dwPageSize;
#else
	return sysconf(_SC_PAGESIZE);
#endif
}

/* Allocate a buffer with guard pages */
void
alloc_guarded_buffer(size_t size, u8 **start_ret, u8 **end_ret)
{
	const size_t pagesize = get_page_size();
	const size_t nr_pages = (size + pagesize - 1) / pagesize;
	u8 *base_addr;
	u8 *start, *end;
#ifdef _WIN32
	DWORD oldProtect;
#endif

	*start_ret = NULL;
	*end_ret = NULL;

#ifdef _WIN32
	/* Allocate buffer and guard pages with no access. */
	base_addr = VirtualAlloc(NULL, (nr_pages + 2) * pagesize,
				 MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
	if (!base_addr) {
		msg("Unable to allocate memory (VirtualAlloc): Windows error %u",
		    (unsigned int)GetLastError());
		ASSERT(0);
	}
	start = base_addr + pagesize;
	end = start + (nr_pages * pagesize);

	/* Grant read+write access to just the buffer. */
	if (!VirtualProtect(start, end - start, PAGE_READWRITE, &oldProtect)) {
		msg("Unable to protect memory (VirtualProtect): Windows error %u",
		    (unsigned int)GetLastError());
		VirtualFree(base_addr, 0, MEM_RELEASE);
		ASSERT(0);
	}
#else
	/* Allocate buffer and guard pages. */
	base_addr = mmap(NULL, (nr_pages + 2) * pagesize, PROT_READ|PROT_WRITE,
			 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (base_addr == (u8 *)MAP_FAILED) {
		msg_errno("Unable to allocate memory (anonymous mmap)");
		ASSERT(0);
	}
	start = base_addr + pagesize;
	end = start + (nr_pages * pagesize);

	/* Unmap the guard pages. */
	munmap(base_addr, pagesize);
	munmap(end, pagesize);
#endif
	*start_ret = start;
	*end_ret = end;
}

/* Free a buffer that was allocated by alloc_guarded_buffer() */
void
free_guarded_buffer(u8 *start, u8 *end)
{
	if (!start)
		return;
#ifdef _WIN32
	VirtualFree(start - get_page_size(), 0, MEM_RELEASE);
#else
	munmap(start, end - start);
#endif
}

/*
 * Return the number of timer ticks that have elapsed since some unspecified
 * point fixed at the start of program execution
 */
u64
timer_ticks(void)
{
#ifdef _WIN32
	LARGE_INTEGER count;

	QueryPerformanceCounter(&count);
	return count.QuadPart;
#elif defined(HAVE_CLOCK_GETTIME)
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (1000000000 * (u64)ts.tv_sec) + ts.tv_nsec;
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (1000000 * (u64)tv.tv_sec) + tv.tv_usec;
#endif
}

/*
 * Return the number of timer ticks per second
 */
static u64
timer_frequency(void)
{
#ifdef _WIN32
	LARGE_INTEGER freq;

	QueryPerformanceFrequency(&freq);
	return freq.QuadPart;
#elif defined(HAVE_CLOCK_GETTIME)
	return 1000000000;
#else
	return 1000000;
#endif
}

/*
 * Convert a number of elapsed timer ticks to milliseconds
 */
u64 timer_ticks_to_ms(u64 ticks)
{
	return ticks * 1000 / timer_frequency();
}

/*
 * Convert a byte count and a number of elapsed timer ticks to MB/s
 */
u64 timer_MB_per_s(u64 bytes, u64 ticks)
{
	return bytes * timer_frequency() / ticks / 1000000;
}

/*
 * Convert a byte count and a number of elapsed timer ticks to KB/s
 */
u64 timer_KB_per_s(u64 bytes, u64 ticks)
{
	return bytes * timer_frequency() / ticks / 1000;
}

bool
put_bits(struct output_bitstream *os, machine_word_t bits, int num_bits)
{
	os->bitbuf |= bits << os->bitcount;
	os->bitcount += num_bits;
	while (os->bitcount >= 8) {
		if (os->next == os->end)
			return false;
		*os->next++ = os->bitbuf;
		os->bitcount -= 8;
		os->bitbuf >>= 8;
	}
	return true;
}

bool
flush_bits(struct output_bitstream *os)
{
	while (os->bitcount > 0) {
		if (os->next == os->end)
			return false;
		*os->next++ = os->bitbuf;
		os->bitcount -= 8;
		os->bitbuf >>= 8;
	}
	os->bitcount = 0;
	return true;
}
