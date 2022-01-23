/*
 * benchmark.c - a compression testing and benchmark program
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

static const tchar *const optstring = T("0::1::2::3::4::5::6::7::8::9::C:D:eghs:VYZz");

enum format {
	DEFLATE_FORMAT,
	ZLIB_FORMAT,
	GZIP_FORMAT,
};

struct compressor {
	int level;
	enum format format;
	const struct engine *engine;
	void *private;
};

struct decompressor {
	enum format format;
	const struct engine *engine;
	void *private;
};

struct engine {
	const tchar *name;

	bool (*init_compressor)(struct compressor *);
	size_t (*compress_bound)(struct compressor *, size_t);
	size_t (*compress)(struct compressor *, const void *, size_t,
			   void *, size_t);
	void (*destroy_compressor)(struct compressor *);

	bool (*init_decompressor)(struct decompressor *);
	bool (*decompress)(struct decompressor *, const void *, size_t,
			   void *, size_t);
	void (*destroy_decompressor)(struct decompressor *);
};

/******************************************************************************/

static bool
libdeflate_engine_init_compressor(struct compressor *c)
{
	c->private = alloc_compressor(c->level);
	return c->private != NULL;
}

static size_t
libdeflate_engine_compress_bound(struct compressor *c, size_t in_nbytes)
{
	switch (c->format) {
	case ZLIB_FORMAT:
		return libdeflate_zlib_compress_bound(c->private, in_nbytes);
	case GZIP_FORMAT:
		return libdeflate_gzip_compress_bound(c->private, in_nbytes);
	default:
		return libdeflate_deflate_compress_bound(c->private, in_nbytes);
	}
}

static size_t
libdeflate_engine_compress(struct compressor *c, const void *in,
			   size_t in_nbytes, void *out, size_t out_nbytes_avail)
{
	switch (c->format) {
	case ZLIB_FORMAT:
		return libdeflate_zlib_compress(c->private, in, in_nbytes,
						out, out_nbytes_avail);
	case GZIP_FORMAT:
		return libdeflate_gzip_compress(c->private, in, in_nbytes,
						out, out_nbytes_avail);
	default:
		return libdeflate_deflate_compress(c->private, in, in_nbytes,
						   out, out_nbytes_avail);
	}
}

static void
libdeflate_engine_destroy_compressor(struct compressor *c)
{
	libdeflate_free_compressor(c->private);
}

static bool
libdeflate_engine_init_decompressor(struct decompressor *d)
{
	d->private = alloc_decompressor();
	return d->private != NULL;
}

static bool
libdeflate_engine_decompress(struct decompressor *d, const void *in,
			     size_t in_nbytes, void *out, size_t out_nbytes)
{
	switch (d->format) {
	case ZLIB_FORMAT:
		return !libdeflate_zlib_decompress(d->private, in, in_nbytes,
						   out, out_nbytes, NULL);
	case GZIP_FORMAT:
		return !libdeflate_gzip_decompress(d->private, in, in_nbytes,
						   out, out_nbytes, NULL);
	default:
		return !libdeflate_deflate_decompress(d->private, in, in_nbytes,
						      out, out_nbytes, NULL);
	}
}

static void
libdeflate_engine_destroy_decompressor(struct decompressor *d)
{
	libdeflate_free_decompressor(d->private);
}

static const struct engine libdeflate_engine = {
	.name			= T("libdeflate"),

	.init_compressor	= libdeflate_engine_init_compressor,
	.compress_bound		= libdeflate_engine_compress_bound,
	.compress		= libdeflate_engine_compress,
	.destroy_compressor	= libdeflate_engine_destroy_compressor,

	.init_decompressor	= libdeflate_engine_init_decompressor,
	.decompress		= libdeflate_engine_decompress,
	.destroy_decompressor	= libdeflate_engine_destroy_decompressor,
};

/******************************************************************************/

static int
get_libz_window_bits(enum format format)
{
	const int windowBits = 15;
	switch (format) {
	case ZLIB_FORMAT:
		return windowBits;
	case GZIP_FORMAT:
		return windowBits + 16;
	default:
		return -windowBits;
	}
}

static bool
libz_engine_init_compressor(struct compressor *c)
{
	z_stream *z;

	if (c->level > 9) {
		msg("libz only supports up to compression level 9");
		return false;
	}

	z = xmalloc(sizeof(*z));
	if (z == NULL)
		return false;

	z->next_in = NULL;
	z->avail_in = 0;
	z->zalloc = NULL;
	z->zfree = NULL;
	z->opaque = NULL;
	if (deflateInit2(z, c->level, Z_DEFLATED,
			 get_libz_window_bits(c->format),
			 8, Z_DEFAULT_STRATEGY) != Z_OK)
	{
		msg("unable to initialize deflater");
		free(z);
		return false;
	}

	c->private = z;
	return true;
}

static size_t
libz_engine_compress_bound(struct compressor *c, size_t in_nbytes)
{
	return deflateBound(c->private, in_nbytes);
}

static size_t
libz_engine_compress(struct compressor *c, const void *in, size_t in_nbytes,
		     void *out, size_t out_nbytes_avail)
{
	z_stream *z = c->private;

	deflateReset(z);

	z->next_in = (void *)in;
	z->avail_in = in_nbytes;
	z->next_out = out;
	z->avail_out = out_nbytes_avail;

	if (deflate(z, Z_FINISH) != Z_STREAM_END)
		return 0;

	return out_nbytes_avail - z->avail_out;
}

static void
libz_engine_destroy_compressor(struct compressor *c)
{
	z_stream *z = c->private;

	deflateEnd(z);
	free(z);
}

static bool
libz_engine_init_decompressor(struct decompressor *d)
{
	z_stream *z;

	z = xmalloc(sizeof(*z));
	if (z == NULL)
		return false;

	z->next_in = NULL;
	z->avail_in = 0;
	z->zalloc = NULL;
	z->zfree = NULL;
	z->opaque = NULL;
	if (inflateInit2(z, get_libz_window_bits(d->format)) != Z_OK) {
		msg("unable to initialize inflater");
		free(z);
		return false;
	}

	d->private = z;
	return true;
}

static bool
libz_engine_decompress(struct decompressor *d, const void *in, size_t in_nbytes,
		       void *out, size_t out_nbytes)
{
	z_stream *z = d->private;

	inflateReset(z);

	z->next_in = (void *)in;
	z->avail_in = in_nbytes;
	z->next_out = out;
	z->avail_out = out_nbytes;

	return inflate(z, Z_FINISH) == Z_STREAM_END && z->avail_out == 0;
}

static void
libz_engine_destroy_decompressor(struct decompressor *d)
{
	z_stream *z = d->private;

	inflateEnd(z);
	free(z);
}

static const struct engine libz_engine = {
	.name			= T("libz"),

	.init_compressor	= libz_engine_init_compressor,
	.compress_bound		= libz_engine_compress_bound,
	.compress		= libz_engine_compress,
	.destroy_compressor	= libz_engine_destroy_compressor,

	.init_decompressor	= libz_engine_init_decompressor,
	.decompress		= libz_engine_decompress,
	.destroy_decompressor	= libz_engine_destroy_decompressor,
};

/******************************************************************************/

static const struct engine * const all_engines[] = {
	&libdeflate_engine,
	&libz_engine,
};

#define DEFAULT_ENGINE libdeflate_engine

static const struct engine *
name_to_engine(const tchar *name)
{
	size_t i;

	for (i = 0; i < ARRAY_LEN(all_engines); i++)
		if (tstrcmp(all_engines[i]->name, name) == 0)
			return all_engines[i];
	return NULL;
}

/******************************************************************************/

static bool
compressor_init(struct compressor *c, int level, enum format format,
		const struct engine *engine)
{
	c->level = level;
	c->format = format;
	c->engine = engine;
	return engine->init_compressor(c);
}

static size_t
compress_bound(struct compressor *c, size_t in_nbytes)
{
	return c->engine->compress_bound(c, in_nbytes);
}

static size_t
do_compress(struct compressor *c, const void *in, size_t in_nbytes,
	    void *out, size_t out_nbytes_avail)
{
	return c->engine->compress(c, in, in_nbytes, out, out_nbytes_avail);
}

static void
compressor_destroy(struct compressor *c)
{
	if (c->engine != NULL)
		c->engine->destroy_compressor(c);
}

static bool
decompressor_init(struct decompressor *d, enum format format,
		  const struct engine *engine)
{
	d->format = format;
	d->engine = engine;
	return engine->init_decompressor(d);
}

static bool
do_decompress(struct decompressor *d, const void *in, size_t in_nbytes,
	      void *out, size_t out_nbytes)
{
	return d->engine->decompress(d, in, in_nbytes, out, out_nbytes);
}

static void
decompressor_destroy(struct decompressor *d)
{
	if (d->engine != NULL)
		d->engine->destroy_decompressor(d);
}

/******************************************************************************/

static void
show_available_engines(FILE *fp)
{
	size_t i;

	fprintf(fp, "Available ENGINEs are: ");
	for (i = 0; i < ARRAY_LEN(all_engines); i++) {
		fprintf(fp, "%"TS, all_engines[i]->name);
		if (i < ARRAY_LEN(all_engines) - 1)
			fprintf(fp, ", ");
	}
	fprintf(fp, ".  Default is %"TS"\n", DEFAULT_ENGINE.name);
}

static void
show_usage(FILE *fp)
{
	fprintf(fp,
"Usage: %"TS" [-LVL] [-C ENGINE] [-D ENGINE] [-ghVz] [-s SIZE] [FILE]...\n"
"Benchmark DEFLATE compression and decompression on the specified FILEs.\n"
"\n"
"Options:\n"
"  -0        no compression\n"
"  -1        fastest (worst) compression\n"
"  -6        medium compression (default)\n"
"  -12       slowest (best) compression\n"
"  -C ENGINE compression engine\n"
"  -D ENGINE decompression engine\n"
"  -e        allow chunks to be expanded (implied by -0)\n"
"  -g        use gzip format instead of raw DEFLATE\n"
"  -h        print this help\n"
"  -s SIZE   chunk size\n"
"  -V        show version and legal information\n"
"  -z        use zlib format instead of raw DEFLATE\n"
"\n", prog_invocation_name);

	show_available_engines(fp);
}

static void
show_version(void)
{
	printf(
"libdeflate compression benchmark program v" LIBDEFLATE_VERSION_STRING "\n"
"Copyright 2016 Eric Biggers\n"
"\n"
"This program is free software which may be modified and/or redistributed\n"
"under the terms of the MIT license.  There is NO WARRANTY, to the extent\n"
"permitted by law.  See the COPYING file for details.\n"
	);
}


/******************************************************************************/

static int
do_benchmark(struct file_stream *in, void *original_buf, void *compressed_buf,
	     void *decompressed_buf, u32 chunk_size,
	     bool allow_expansion, size_t compressed_buf_size,
	     struct compressor *compressor,
	     struct decompressor *decompressor)
{
	u64 total_uncompressed_size = 0;
	u64 total_compressed_size = 0;
	u64 total_compress_time = 0;
	u64 total_decompress_time = 0;
	ssize_t ret;

	while ((ret = xread(in, original_buf, chunk_size)) > 0) {
		u32 original_size = ret;
		size_t out_nbytes_avail;
		u32 compressed_size;
		u64 start_time;
		bool ok;

		total_uncompressed_size += original_size;

		if (allow_expansion) {
			out_nbytes_avail = compress_bound(compressor,
							  original_size);
			if (out_nbytes_avail > compressed_buf_size) {
				msg("%"TS": bug in compress_bound()", in->name);
				return -1;
			}
		} else {
			out_nbytes_avail = original_size - 1;
		}

		/* Compress the chunk of data. */
		start_time = timer_ticks();
		compressed_size = do_compress(compressor,
					      original_buf,
					      original_size,
					      compressed_buf,
					      out_nbytes_avail);
		total_compress_time += timer_ticks() - start_time;

		if (compressed_size) {
			/* Successfully compressed the chunk of data. */

			/* Decompress the data we just compressed and compare
			 * the result with the original. */
			start_time = timer_ticks();
			ok = do_decompress(decompressor,
					   compressed_buf, compressed_size,
					   decompressed_buf, original_size);
			total_decompress_time += timer_ticks() - start_time;

			if (!ok) {
				msg("%"TS": failed to decompress data",
				    in->name);
				return -1;
			}

			if (memcmp(original_buf, decompressed_buf,
				   original_size) != 0)
			{
				msg("%"TS": data did not decompress to "
				    "original", in->name);
				return -1;
			}

			total_compressed_size += compressed_size;
		} else {
			/*
			 * The chunk would have compressed to more than
			 * out_nbytes_avail bytes.
			 */
			if (allow_expansion) {
				msg("%"TS": bug in compress_bound()", in->name);
				return -1;
			}
			total_compressed_size += original_size;
		}
	}

	if (ret < 0)
		return ret;

	if (total_uncompressed_size == 0) {
		printf("\tFile was empty.\n");
		return 0;
	}

	if (total_compress_time == 0)
		total_compress_time = 1;
	if (total_decompress_time == 0)
		total_decompress_time = 1;

	printf("\tCompressed %"PRIu64 " => %"PRIu64" bytes (%u.%03u%%)\n",
	       total_uncompressed_size, total_compressed_size,
	       (unsigned int)(total_compressed_size * 100 /
				total_uncompressed_size),
	       (unsigned int)(total_compressed_size * 100000 /
				total_uncompressed_size % 1000));
	printf("\tCompression time: %"PRIu64" ms (%"PRIu64" MB/s)\n",
	       timer_ticks_to_ms(total_compress_time),
	       timer_MB_per_s(total_uncompressed_size, total_compress_time));
	printf("\tDecompression time: %"PRIu64" ms (%"PRIu64" MB/s)\n",
	       timer_ticks_to_ms(total_decompress_time),
	       timer_MB_per_s(total_uncompressed_size, total_decompress_time));

	return 0;
}

int
tmain(int argc, tchar *argv[])
{
	u32 chunk_size = 1048576;
	int level = 6;
	enum format format = DEFLATE_FORMAT;
	const struct engine *compress_engine = &DEFAULT_ENGINE;
	const struct engine *decompress_engine = &DEFAULT_ENGINE;
	bool allow_expansion = false;
	struct compressor compressor = { 0 };
	struct decompressor decompressor = { 0 };
	size_t compressed_buf_size;
	void *original_buf = NULL;
	void *compressed_buf = NULL;
	void *decompressed_buf = NULL;
	tchar *default_file_list[] = { NULL };
	int opt_char;
	int i;
	int ret;

	begin_program(argv);

	while ((opt_char = tgetopt(argc, argv, optstring)) != -1) {
		switch (opt_char) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			level = parse_compression_level(opt_char, toptarg);
			if (level < 0)
				return 1;
			break;
		case 'C':
			compress_engine = name_to_engine(toptarg);
			if (compress_engine == NULL) {
				msg("invalid compression engine: \"%"TS"\"", toptarg);
				show_available_engines(stderr);
				return 1;
			}
			break;
		case 'D':
			decompress_engine = name_to_engine(toptarg);
			if (decompress_engine == NULL) {
				msg("invalid decompression engine: \"%"TS"\"", toptarg);
				show_available_engines(stderr);
				return 1;
			}
			break;
		case 'e':
			allow_expansion = true;
			break;
		case 'g':
			format = GZIP_FORMAT;
			break;
		case 'h':
			show_usage(stdout);
			return 0;
		case 's':
			chunk_size = tstrtoul(toptarg, NULL, 10);
			if (chunk_size == 0) {
				msg("invalid chunk size: \"%"TS"\"", toptarg);
				return 1;
			}
			break;
		case 'V':
			show_version();
			return 0;
		case 'Y': /* deprecated, use '-C libz' instead */
			compress_engine = &libz_engine;
			break;
		case 'Z': /* deprecated, use '-D libz' instead */
			decompress_engine = &libz_engine;
			break;
		case 'z':
			format = ZLIB_FORMAT;
			break;
		default:
			show_usage(stderr);
			return 1;
		}
	}

	argc -= toptind;
	argv += toptind;

	if (level == 0)
		allow_expansion = true;

	ret = -1;
	if (!compressor_init(&compressor, level, format, compress_engine))
		goto out;
	if (!decompressor_init(&decompressor, format, decompress_engine))
		goto out;

	if (allow_expansion)
		compressed_buf_size = compress_bound(&compressor, chunk_size);
	else
		compressed_buf_size = chunk_size - 1;

	original_buf = xmalloc(chunk_size);
	compressed_buf = xmalloc(compressed_buf_size);
	decompressed_buf = xmalloc(chunk_size);

	ret = -1;
	if (original_buf == NULL || compressed_buf == NULL ||
	    decompressed_buf == NULL)
		goto out;

	if (argc == 0) {
		argv = default_file_list;
		argc = ARRAY_LEN(default_file_list);
	} else {
		for (i = 0; i < argc; i++)
			if (argv[i][0] == '-' && argv[i][1] == '\0')
				argv[i] = NULL;
	}

	printf("Benchmarking %s compression:\n",
	       format == DEFLATE_FORMAT ? "DEFLATE" :
	       format == ZLIB_FORMAT ? "zlib" : "gzip");
	printf("\tCompression level: %d\n", level);
	printf("\tChunk size: %"PRIu32"\n", chunk_size);
	printf("\tCompression engine: %"TS"\n", compress_engine->name);
	printf("\tDecompression engine: %"TS"\n", decompress_engine->name);

	for (i = 0; i < argc; i++) {
		struct file_stream in;

		ret = xopen_for_read(argv[i], true, &in);
		if (ret != 0)
			goto out;

		printf("Processing %"TS"...\n", in.name);

		ret = do_benchmark(&in, original_buf, compressed_buf,
				   decompressed_buf, chunk_size,
				   allow_expansion, compressed_buf_size,
				   &compressor, &decompressor);
		xclose(&in);
		if (ret != 0)
			goto out;
	}
	ret = 0;
out:
	free(decompressed_buf);
	free(compressed_buf);
	free(original_buf);
	decompressor_destroy(&decompressor);
	compressor_destroy(&compressor);
	return -ret;
}
