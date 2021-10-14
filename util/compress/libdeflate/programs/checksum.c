/*
 * checksum.c - Adler-32 and CRC-32 checksumming program
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

#include "test_util.h"

static const tchar *const optstring = T("Ahs:tZ");

static void
show_usage(FILE *fp)
{
	fprintf(fp,
"Usage: %"TS" [-A] [-h] [-s SIZE] [-t] [-Z] [FILE]...\n"
"Calculate Adler-32 or CRC-32 checksums of the specified FILEs.\n"
"\n"
"Options:\n"
"  -A        use Adler-32 (default is CRC-32)\n"
"  -h        print this help\n"
"  -s SIZE   chunk size\n"
"  -t        show checksum speed, excluding I/O\n"
"  -Z        use zlib implementation instead of libdeflate\n",
	prog_invocation_name);
}

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

static int
checksum_stream(struct file_stream *in, cksum_fn_t cksum, u32 *sum,
		void *buf, size_t bufsize, u64 *size_ret, u64 *elapsed_ret)
{
	u64 size = 0;
	u64 elapsed = 0;

	for (;;) {
		ssize_t ret;
		u64 start_time;

		ret = xread(in, buf, bufsize);
		if (ret < 0)
			return ret;
		if (ret == 0)
			break;

		size += ret;
		start_time = timer_ticks();
		*sum = cksum(*sum, buf, ret);
		elapsed += timer_ticks() - start_time;
	}

	if (elapsed == 0)
		elapsed = 1;
	*size_ret = size;
	*elapsed_ret = elapsed;
	return 0;
}

int
tmain(int argc, tchar *argv[])
{
	bool use_adler32 = false;
	bool use_zlib_impl = false;
	bool do_timing = false;
	void *buf;
	size_t bufsize = 131072;
	tchar *default_file_list[] = { NULL };
	cksum_fn_t cksum;
	int opt_char;
	int i;
	int ret;

	begin_program(argv);

	while ((opt_char = tgetopt(argc, argv, optstring)) != -1) {
		switch (opt_char) {
		case 'A':
			use_adler32 = true;
			break;
		case 'h':
			show_usage(stdout);
			return 0;
		case 's':
			bufsize = tstrtoul(toptarg, NULL, 10);
			if (bufsize == 0) {
				msg("invalid chunk size: \"%"TS"\"", toptarg);
				return 1;
			}
			break;
		case 't':
			do_timing = true;
			break;
		case 'Z':
			use_zlib_impl = true;
			break;
		default:
			show_usage(stderr);
			return 1;
		}
	}

	argc -= toptind;
	argv += toptind;

	if (use_adler32) {
		if (use_zlib_impl)
			cksum = adler32_zlib;
		else
			cksum = adler32_libdeflate;
	} else {
		if (use_zlib_impl)
			cksum = crc32_zlib;
		else
			cksum = crc32_libdeflate;
	}

	buf = xmalloc(bufsize);
	if (buf == NULL)
		return 1;

	if (argc == 0) {
		argv = default_file_list;
		argc = ARRAY_LEN(default_file_list);
	} else {
		for (i = 0; i < argc; i++)
			if (argv[i][0] == '-' && argv[i][1] == '\0')
				argv[i] = NULL;
	}

	for (i = 0; i < argc; i++) {
		struct file_stream in;
		u32 sum = cksum(0, NULL, 0);
		u64 size = 0;
		u64 elapsed = 0;

		ret = xopen_for_read(argv[i], true, &in);
		if (ret != 0)
			goto out;

		ret = checksum_stream(&in, cksum, &sum, buf, bufsize,
				      &size, &elapsed);
		if (ret == 0) {
			if (do_timing) {
				printf("%08"PRIx32"\t%"TS"\t"
				       "%"PRIu64" ms\t%"PRIu64" MB/s\n",
				       sum, in.name, timer_ticks_to_ms(elapsed),
				       timer_MB_per_s(size, elapsed));
			} else {
				printf("%08"PRIx32"\t%"TS"\t\n", sum, in.name);
			}
		}

		xclose(&in);

		if (ret != 0)
			goto out;
	}
	ret = 0;
out:
	free(buf);
	return -ret;
}
