/*
 * test_custom_malloc.c
 *
 * Test libdeflate_set_memory_allocator().
 * Also test injecting allocation failures.
 */

#include "test_util.h"

static int malloc_count = 0;
static int free_count = 0;

static void *do_malloc(size_t size)
{
	malloc_count++;
	return malloc(size);
}

static void *do_fail_malloc(size_t size)
{
	malloc_count++;
	return NULL;
}

static void do_free(void *ptr)
{
	free_count++;
	free(ptr);
}

int
tmain(int argc, tchar *argv[])
{
	int level;
	struct libdeflate_compressor *c;
	struct libdeflate_decompressor *d;

	begin_program(argv);

	/* Test that the custom allocator is actually used when requested. */

	libdeflate_set_memory_allocator(do_malloc, do_free);
	ASSERT(malloc_count == 0);
	ASSERT(free_count == 0);

	for (level = 0; level <= 12; level++) {
		malloc_count = free_count = 0;
		c = libdeflate_alloc_compressor(level);
		ASSERT(c != NULL);
		ASSERT(malloc_count == 1);
		ASSERT(free_count == 0);
		libdeflate_free_compressor(c);
		ASSERT(malloc_count == 1);
		ASSERT(free_count == 1);
	}

	malloc_count = free_count = 0;
	d = libdeflate_alloc_decompressor();
	ASSERT(d != NULL);
	ASSERT(malloc_count == 1);
	ASSERT(free_count == 0);
	libdeflate_free_decompressor(d);
	ASSERT(malloc_count == 1);
	ASSERT(free_count == 1);

	/* As long as we're here, also test injecting allocation failures. */

	libdeflate_set_memory_allocator(do_fail_malloc, do_free);

	for (level = 0; level <= 12; level++) {
		malloc_count = free_count = 0;
		c = libdeflate_alloc_compressor(level);
		ASSERT(c == NULL);
		ASSERT(malloc_count == 1);
		ASSERT(free_count == 0);
	}

	malloc_count = free_count = 0;
	d = libdeflate_alloc_decompressor();
	ASSERT(d == NULL);
	ASSERT(malloc_count == 1);
	ASSERT(free_count == 0);

	return 0;
}
