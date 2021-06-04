/*
 * test_checksums.c
 *
 * Verify that libdeflate's Adler-32 and CRC-32 functions produce the same
 * results as their zlib equivalents.
 */

#include <stdlib.h>
#include <time.h>

#include "test_util.h"

static unsigned int rng_seed;

typedef u32 (*cksum_fn_t)(u32, const void *, size_t);

static u32
adler32_libdeflate(u32 adler, const void *buf, size_t len)
{
	return libdeflate_adler32(adler, buf, len);
}

static u32
crc32_libdeflate(u32 crc, const void *buf, size_t len)
{
	return libdeflate_crc32(crc, buf, len);
}

static u32
adler32_zlib(u32 adler, const void *buf, size_t len)
{
	return adler32(adler, buf, len);
}

static u32
crc32_zlib(u32 crc, const void *buf, size_t len)
{
	return crc32(crc, buf, len);
}

static u32
select_initial_crc(void)
{
	if (rand() & 1)
		return 0;
	return ((u32)rand() << 16) | rand();
}

static u32
select_initial_adler(void)
{
	u32 lo, hi;

	if (rand() & 1)
		return 1;

	lo = (rand() % 4 == 0 ? 65520 : rand() % 65521);
	hi = (rand() % 4 == 0 ? 65520 : rand() % 65521);
	return (hi << 16) | lo;
}

static void
test_initial_values(cksum_fn_t cksum, u32 expected)
{
	ASSERT(cksum(0, NULL, 0) == expected);
	if (cksum != adler32_zlib) /* broken */
		ASSERT(cksum(0, NULL, 1) == expected);
	ASSERT(cksum(0, NULL, 1234) == expected);
	ASSERT(cksum(1234, NULL, 0) == expected);
	ASSERT(cksum(1234, NULL, 1234) == expected);
}

static void
test_multipart(const u8 *buffer, size_t size, const char *name,
	       cksum_fn_t cksum, u32 v, u32 expected)
{
	size_t division = rand() % (size + 1);
	v = cksum(v, buffer, division);
	v = cksum(v, buffer + division, size - division);
	if (v != expected) {
		fprintf(stderr, "%s checksum failed multipart test\n", name);
		ASSERT(0);
	}
}

static void
test_checksums(const void *buffer, size_t size, const char *name,
	       cksum_fn_t cksum1, cksum_fn_t cksum2, u32 initial_value)
{
	u32 v1 = cksum1(initial_value, buffer, size);
	u32 v2 = cksum2(initial_value, buffer, size);

	if (v1 != v2) {
		fprintf(stderr, "%s checksum mismatch\n", name);
		fprintf(stderr, "initial_value=0x%08"PRIx32", buffer=%p, "
			"size=%zu, buffer=", initial_value, buffer, size);
		for (size_t i = 0; i < MIN(size, 256); i++)
			fprintf(stderr, "%02x", ((const u8 *)buffer)[i]);
		if (size > 256)
			fprintf(stderr, "...");
		fprintf(stderr, "\n");
		ASSERT(0);
	}

	if ((rand() & 15) == 0) {
		test_multipart(buffer, size, name, cksum1, initial_value, v1);
		test_multipart(buffer, size, name, cksum2, initial_value, v1);
	}
}

static void
test_crc32(const void *buffer, size_t size, u32 initial_value)
{
	test_checksums(buffer, size, "CRC-32",
		       crc32_libdeflate, crc32_zlib, initial_value);
}

static void
test_adler32(const void *buffer, size_t size, u32 initial_value)
{
	test_checksums(buffer, size, "Adler-32",
		       adler32_libdeflate, adler32_zlib, initial_value);
}

static void test_random_buffers(u8 *buffer, u8 *guarded_buf_end,
				size_t limit, u32 num_iter)
{
	for (u32 i = 0; i < num_iter; i++) {
		size_t start = rand() % limit;
		size_t len = rand() % (limit - start);
		u32 a0 = select_initial_adler();
		u32 c0 = select_initial_crc();

		for (size_t j = start; j < start + len; j++)
			buffer[j] = rand();

		/* Test with chosen size and alignment */
		test_adler32(&buffer[start], len, a0);
		test_crc32(&buffer[start], len, c0);

		/* Test with chosen size, with guard page after input buffer */
		memcpy(guarded_buf_end - len, &buffer[start], len);
		test_adler32(guarded_buf_end - len, len, a0);
		test_crc32(guarded_buf_end - len, len, c0);
	}
}

int
tmain(int argc, tchar *argv[])
{
	u8 *buffer = xmalloc(32768);
	u8 *guarded_buf_start, *guarded_buf_end;

	begin_program(argv);

	alloc_guarded_buffer(32768, &guarded_buf_start, &guarded_buf_end);

	rng_seed = time(NULL);
	srand(rng_seed);

	test_initial_values(adler32_libdeflate, 1);
	test_initial_values(adler32_zlib, 1);
	test_initial_values(crc32_libdeflate, 0);
	test_initial_values(crc32_zlib, 0);

	/* Test different buffer sizes and alignments */
	test_random_buffers(buffer, guarded_buf_end, 256, 5000);
	test_random_buffers(buffer, guarded_buf_end, 1024, 500);
	test_random_buffers(buffer, guarded_buf_end, 32768, 50);

	/*
	 * Test Adler-32 overflow cases.  For example, given all 0xFF bytes and
	 * the highest possible initial (s1, s2) of (65520, 65520), then s2 if
	 * stored as a 32-bit unsigned integer will overflow if > 5552 bytes are
	 * processed.  Implementations must make sure to reduce s2 modulo 65521
	 * before that point.  Also, some implementations make use of 16-bit
	 * counters which can overflow earlier.
	 */
	memset(buffer, 0xFF, 32768);
	for (u32 i = 0; i < 20; i++) {
		u32 initial_value;

		if (i == 0)
			initial_value = ((u32)65520 << 16) | 65520;
		else
			initial_value = select_initial_adler();

		test_adler32(buffer, 5553, initial_value);
		test_adler32(buffer, rand() % 32769, initial_value);
		buffer[rand() % 32768] = 0xFE;
	}

	free(buffer);
	free_guarded_buffer(guarded_buf_start, guarded_buf_end);
	return 0;
}
