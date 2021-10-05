/*
 * test_trailing_bytes.c
 *
 * Test that decompression correctly stops at the end of the first DEFLATE,
 * zlib, or gzip stream, and doesn't process any additional trailing bytes.
 */

#include "test_util.h"

static const struct {
	size_t (LIBDEFLATEAPI *compress)(
			struct libdeflate_compressor *compressor,
			const void *in, size_t in_nbytes,
			void *out, size_t out_nbytes_avail);
	enum libdeflate_result (LIBDEFLATEAPI *decompress)(
			struct libdeflate_decompressor *decompressor,
			const void *in, size_t in_nbytes,
			void *out, size_t out_nbytes_avail,
			size_t *actual_out_nbytes_ret);
	enum libdeflate_result (LIBDEFLATEAPI *decompress_ex)(
			struct libdeflate_decompressor *decompressor,
			const void *in, size_t in_nbytes,
			void *out, size_t out_nbytes_avail,
			size_t *actual_in_nbytes_ret,
			size_t *actual_out_nbytes_ret);
} codecs[] = {
	{
		.compress = libdeflate_deflate_compress,
		.decompress = libdeflate_deflate_decompress,
		.decompress_ex = libdeflate_deflate_decompress_ex,
	}, {
		.compress = libdeflate_zlib_compress,
		.decompress = libdeflate_zlib_decompress,
		.decompress_ex = libdeflate_zlib_decompress_ex,
	}, {
		.compress = libdeflate_gzip_compress,
		.decompress = libdeflate_gzip_decompress,
		.decompress_ex = libdeflate_gzip_decompress_ex,
	}
};

int
tmain(int argc, tchar *argv[])
{
	const size_t original_nbytes = 32768;
	const size_t compressed_nbytes_total = 32768;
	/*
	 * Don't use the full buffer for compressed data, because we want to
	 * test whether decompression can deal with additional trailing bytes.
	 *
	 * Note: we can't use a guarded buffer (i.e. a buffer where the byte
	 * after compressed_nbytes is unmapped) because the decompressor may
	 * read a few bytes beyond the end of the stream (but ultimately not
	 * actually use those bytes) as long as they are within the buffer.
	 */
	const size_t compressed_nbytes_avail = 30000;
	size_t i;
	u8 *original;
	u8 *compressed;
	u8 *decompressed;
	struct libdeflate_compressor *c;
	struct libdeflate_decompressor *d;
	size_t compressed_nbytes;
	enum libdeflate_result res;
	size_t actual_compressed_nbytes;
	size_t actual_decompressed_nbytes;

	begin_program(argv);

	ASSERT(compressed_nbytes_avail < compressed_nbytes_total);

	/* Prepare some dummy data to compress */
	original = xmalloc(original_nbytes);
	ASSERT(original != NULL);
	for (i = 0; i < original_nbytes; i++)
		original[i] = (i % 123) + (i % 1023);

	compressed = xmalloc(compressed_nbytes_total);
	ASSERT(compressed != NULL);
	memset(compressed, 0, compressed_nbytes_total);

	decompressed = xmalloc(original_nbytes);
	ASSERT(decompressed != NULL);

	c = libdeflate_alloc_compressor(6);
	ASSERT(c != NULL);

	d = libdeflate_alloc_decompressor();
	ASSERT(d != NULL);

	for (i = 0; i < ARRAY_LEN(codecs); i++) {
		compressed_nbytes = codecs[i].compress(c, original,
						       original_nbytes,
						       compressed,
						       compressed_nbytes_avail);
		ASSERT(compressed_nbytes > 0);
		ASSERT(compressed_nbytes <= compressed_nbytes_avail);

		/* Test decompress() of stream that fills the whole buffer */
		actual_decompressed_nbytes = 0;
		memset(decompressed, 0, original_nbytes);
		res = codecs[i].decompress(d, compressed, compressed_nbytes,
					   decompressed, original_nbytes,
					   &actual_decompressed_nbytes);
		ASSERT(res == LIBDEFLATE_SUCCESS);
		ASSERT(actual_decompressed_nbytes == original_nbytes);
		ASSERT(memcmp(decompressed, original, original_nbytes) == 0);

		/* Test decompress_ex() of stream that fills the whole buffer */
		actual_compressed_nbytes = actual_decompressed_nbytes = 0;
		memset(decompressed, 0, original_nbytes);
		res = codecs[i].decompress_ex(d, compressed, compressed_nbytes,
					      decompressed, original_nbytes,
					      &actual_compressed_nbytes,
					      &actual_decompressed_nbytes);
		ASSERT(res == LIBDEFLATE_SUCCESS);
		ASSERT(actual_compressed_nbytes == compressed_nbytes);
		ASSERT(actual_decompressed_nbytes == original_nbytes);
		ASSERT(memcmp(decompressed, original, original_nbytes) == 0);

		/* Test decompress() of stream with trailing bytes */
		actual_decompressed_nbytes = 0;
		memset(decompressed, 0, original_nbytes);
		res = codecs[i].decompress(d, compressed,
					   compressed_nbytes_total,
					   decompressed, original_nbytes,
					   &actual_decompressed_nbytes);
		ASSERT(res == LIBDEFLATE_SUCCESS);
		ASSERT(actual_decompressed_nbytes == original_nbytes);
		ASSERT(memcmp(decompressed, original, original_nbytes) == 0);

		/* Test decompress_ex() of stream with trailing bytes */
		actual_compressed_nbytes = actual_decompressed_nbytes = 0;
		memset(decompressed, 0, original_nbytes);
		res = codecs[i].decompress_ex(d, compressed,
					      compressed_nbytes_total,
					      decompressed, original_nbytes,
					      &actual_compressed_nbytes,
					      &actual_decompressed_nbytes);
		ASSERT(res == LIBDEFLATE_SUCCESS);
		ASSERT(actual_compressed_nbytes == compressed_nbytes);
		ASSERT(actual_decompressed_nbytes == original_nbytes);
		ASSERT(memcmp(decompressed, original, original_nbytes) == 0);
	}

	free(original);
	free(compressed);
	free(decompressed);
	libdeflate_free_compressor(c);
	libdeflate_free_decompressor(d);
	return 0;
}
