/*
 * gzip.c - a file compression and decompression program
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

#include "prog_util.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#  include <sys/utime.h>
#else
#  include <sys/time.h>
#  include <unistd.h>
#  include <utime.h>
#endif

struct options {
	bool to_stdout;
	bool decompress;
	bool force;
	bool keep;
	bool test;
	int compression_level;
	const tchar *suffix;
};

static const tchar *const optstring = T("1::2::3::4::5::6::7::8::9::cdfhknS:tV");

static void
show_usage(FILE *fp)
{
	fprintf(fp,
"Usage: %"TS" [-LEVEL] [-cdfhkV] [-S SUF] FILE...\n"
"Compress or decompress the specified FILEs.\n"
"\n"
"Options:\n"
"  -1        fastest (worst) compression\n"
"  -6        medium compression (default)\n"
"  -12       slowest (best) compression\n"
"  -c        write to standard output\n"
"  -d        decompress\n"
"  -f        overwrite existing output files\n"
"  -h        print this help\n"
"  -k        don't delete input files\n"
"  -S SUF    use suffix SUF instead of .gz\n"
"  -t        test file integrity\n"
"  -V        show version and legal information\n",
	prog_invocation_name);
}

static void
show_version(void)
{
	printf(
"gzip compression program v" LIBDEFLATE_VERSION_STRING "\n"
"Copyright 2016 Eric Biggers\n"
"\n"
"This program is free software which may be modified and/or redistributed\n"
"under the terms of the MIT license.  There is NO WARRANTY, to the extent\n"
"permitted by law.  See the COPYING file for details.\n"
	);
}

/* Was the program invoked in decompression mode? */
static bool
is_gunzip(void)
{
	if (tstrxcmp(prog_invocation_name, T("gunzip")) == 0)
		return true;
	if (tstrxcmp(prog_invocation_name, T("libdeflate-gunzip")) == 0)
		return true;
#ifdef _WIN32
	if (tstrxcmp(prog_invocation_name, T("gunzip.exe")) == 0)
		return true;
	if (tstrxcmp(prog_invocation_name, T("libdeflate-gunzip.exe")) == 0)
		return true;
#endif
	return false;
}

static const tchar *
get_suffix(const tchar *path, const tchar *suffix)
{
	size_t path_len = tstrlen(path);
	size_t suffix_len = tstrlen(suffix);
	const tchar *p;

	if (path_len <= suffix_len)
		return NULL;
	p = &path[path_len - suffix_len];
	if (tstrxcmp(p, suffix) == 0)
		return p;
	return NULL;
}

static bool
has_suffix(const tchar *path, const tchar *suffix)
{
	return get_suffix(path, suffix) != NULL;
}

static tchar *
append_suffix(const tchar *path, const tchar *suffix)
{
	size_t path_len = tstrlen(path);
	size_t suffix_len = tstrlen(suffix);
	tchar *suffixed_path;

	suffixed_path = xmalloc((path_len + suffix_len + 1) * sizeof(tchar));
	if (suffixed_path == NULL)
		return NULL;
	tmemcpy(suffixed_path, path, path_len);
	tmemcpy(&suffixed_path[path_len], suffix, suffix_len + 1);
	return suffixed_path;
}

static int
do_compress(struct libdeflate_compressor *compressor,
	    struct file_stream *in, struct file_stream *out)
{
	const void *uncompressed_data = in->mmap_mem;
	size_t uncompressed_size = in->mmap_size;
	void *compressed_data;
	size_t actual_compressed_size;
	size_t max_compressed_size;
	int ret;

	max_compressed_size = libdeflate_gzip_compress_bound(compressor,
							     uncompressed_size);
	compressed_data = xmalloc(max_compressed_size);
	if (compressed_data == NULL) {
		msg("%"TS": file is probably too large to be processed by this "
		    "program", in->name);
		ret = -1;
		goto out;
	}

	actual_compressed_size = libdeflate_gzip_compress(compressor,
							  uncompressed_data,
							  uncompressed_size,
							  compressed_data,
							  max_compressed_size);
	if (actual_compressed_size == 0) {
		msg("Bug in libdeflate_gzip_compress_bound()!");
		ret = -1;
		goto out;
	}

	ret = full_write(out, compressed_data, actual_compressed_size);
out:
	free(compressed_data);
	return ret;
}

static u32
load_u32_gzip(const u8 *p)
{
	return ((u32)p[0] << 0) | ((u32)p[1] << 8) |
		((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static int
do_decompress(struct libdeflate_decompressor *decompressor,
	      struct file_stream *in, struct file_stream *out,
	      const struct options *options)
{
	const u8 *compressed_data = in->mmap_mem;
	size_t compressed_size = in->mmap_size;
	void *uncompressed_data = NULL;
	size_t uncompressed_size;
	size_t actual_in_nbytes;
	size_t actual_out_nbytes;
	enum libdeflate_result result;
	int ret = 0;

	if (compressed_size < sizeof(u32)) {
	       msg("%"TS": not in gzip format", in->name);
	       ret = -1;
	       goto out;
	}

	/*
	 * Use the ISIZE field as a hint for the decompressed data size.  It may
	 * need to be increased later, however, because the file may contain
	 * multiple gzip members and the particular ISIZE we happen to use may
	 * not be the largest; or the real size may be >= 4 GiB, causing ISIZE
	 * to overflow.  In any case, make sure to allocate at least one byte.
	 */
	uncompressed_size = load_u32_gzip(&compressed_data[compressed_size - 4]);
	if (uncompressed_size == 0)
		uncompressed_size = 1;

	do {
		if (uncompressed_data == NULL) {
			uncompressed_data = xmalloc(uncompressed_size);
			if (uncompressed_data == NULL) {
				msg("%"TS": file is probably too large to be "
				    "processed by this program", in->name);
				ret = -1;
				goto out;
			}
		}

		result = libdeflate_gzip_decompress_ex(decompressor,
						       compressed_data,
						       compressed_size,
						       uncompressed_data,
						       uncompressed_size,
						       &actual_in_nbytes,
						       &actual_out_nbytes);

		if (result == LIBDEFLATE_INSUFFICIENT_SPACE) {
			if (uncompressed_size * 2 <= uncompressed_size) {
				msg("%"TS": file corrupt or too large to be "
				    "processed by this program", in->name);
				ret = -1;
				goto out;
			}
			uncompressed_size *= 2;
			free(uncompressed_data);
			uncompressed_data = NULL;
			continue;
		}

		if (result != LIBDEFLATE_SUCCESS) {
			msg("%"TS": file corrupt or not in gzip format",
			    in->name);
			ret = -1;
			goto out;
		}

		if (actual_in_nbytes == 0 ||
		    actual_in_nbytes > compressed_size ||
		    actual_out_nbytes > uncompressed_size) {
			msg("Bug in libdeflate_gzip_decompress_ex()!");
			ret = -1;
			goto out;
		}

		if (!options->test) {
			ret = full_write(out, uncompressed_data, actual_out_nbytes);
			if (ret != 0)
				goto out;
		}

		compressed_data += actual_in_nbytes;
		compressed_size -= actual_in_nbytes;

	} while (compressed_size != 0);
out:
	free(uncompressed_data);
	return ret;
}

static int
stat_file(struct file_stream *in, stat_t *stbuf, bool allow_hard_links)
{
	if (tfstat(in->fd, stbuf) != 0) {
		msg("%"TS": unable to stat file", in->name);
		return -1;
	}

	if (!S_ISREG(stbuf->st_mode) && !in->is_standard_stream) {
		msg("%"TS" is %s -- skipping",
		    in->name, S_ISDIR(stbuf->st_mode) ? "a directory" :
							"not a regular file");
		return -2;
	}

	if (stbuf->st_nlink > 1 && !allow_hard_links) {
		msg("%"TS" has multiple hard links -- skipping "
		    "(use -f to process anyway)", in->name);
		return -2;
	}

	return 0;
}

static void
restore_mode(struct file_stream *out, const stat_t *stbuf)
{
#ifndef _WIN32
	if (fchmod(out->fd, stbuf->st_mode) != 0)
		msg_errno("%"TS": unable to preserve mode", out->name);
#endif
}

static void
restore_owner_and_group(struct file_stream *out, const stat_t *stbuf)
{
#ifndef _WIN32
	if (fchown(out->fd, stbuf->st_uid, stbuf->st_gid) != 0) {
		msg_errno("%"TS": unable to preserve owner and group",
			  out->name);
	}
#endif
}

static void
restore_timestamps(struct file_stream *out, const tchar *newpath,
		   const stat_t *stbuf)
{
	int ret;
#if defined(HAVE_FUTIMENS) && defined(HAVE_STAT_NANOSECOND_PRECISION)
	struct timespec times[2] = {
		stbuf->st_atim, stbuf->st_mtim,
	};
	ret = futimens(out->fd, times);
#elif defined(HAVE_FUTIMES) && defined(HAVE_STAT_NANOSECOND_PRECISION)
	struct timeval times[2] = {
		{ stbuf->st_atim.tv_sec, stbuf->st_atim.tv_nsec / 1000, },
		{ stbuf->st_mtim.tv_sec, stbuf->st_mtim.tv_nsec / 1000, },
	};
	ret = futimes(out->fd, times);
#else
	struct tutimbuf times = {
		stbuf->st_atime, stbuf->st_mtime,
	};
	ret = tutime(newpath, &times);
#endif
	if (ret != 0)
		msg_errno("%"TS": unable to preserve timestamps", out->name);
}

static void
restore_metadata(struct file_stream *out, const tchar *newpath,
		 const stat_t *stbuf)
{
	restore_mode(out, stbuf);
	restore_owner_and_group(out, stbuf);
	restore_timestamps(out, newpath, stbuf);
}

static int
decompress_file(struct libdeflate_decompressor *decompressor, const tchar *path,
		const struct options *options)
{
	tchar *oldpath = (tchar *)path;
	tchar *newpath = NULL;
	struct file_stream in;
	struct file_stream out;
	stat_t stbuf;
	int ret;
	int ret2;

	if (path != NULL) {
		const tchar *suffix = get_suffix(path, options->suffix);
		if (suffix == NULL) {
			/*
			 * Input file is unsuffixed.  If the file doesn't exist,
			 * then try it suffixed.  Otherwise, if we're not
			 * writing to stdout, skip the file with warning status.
			 * Otherwise, go ahead and try to open the file anyway
			 * (which will very likely fail).
			 */
			if (tstat(path, &stbuf) != 0 && errno == ENOENT) {
				oldpath = append_suffix(path, options->suffix);
				if (oldpath == NULL)
					return -1;
				if (!options->to_stdout)
					newpath = (tchar *)path;
			} else if (!options->to_stdout) {
				msg("\"%"TS"\" does not end with the %"TS" "
				    "suffix -- skipping",
				    path, options->suffix);
				return -2;
			}
		} else if (!options->to_stdout) {
			/*
			 * Input file is suffixed, and we're not writing to
			 * stdout.  Strip the suffix to get the path to the
			 * output file.
			 */
			newpath = xmalloc((suffix - oldpath + 1) *
					  sizeof(tchar));
			if (newpath == NULL)
				return -1;
			tmemcpy(newpath, oldpath, suffix - oldpath);
			newpath[suffix - oldpath] = '\0';
		}
	}

	ret = xopen_for_read(oldpath, options->force || options->to_stdout,
			     &in);
	if (ret != 0)
		goto out_free_paths;

	if (!options->force && isatty(in.fd)) {
		msg("Refusing to read compressed data from terminal.  "
		    "Use -f to override.\nFor help, use -h.");
		ret = -1;
		goto out_close_in;
	}

	ret = stat_file(&in, &stbuf, options->force || options->keep ||
			oldpath == NULL || newpath == NULL);
	if (ret != 0)
		goto out_close_in;

	ret = xopen_for_write(newpath, options->force, &out);
	if (ret != 0)
		goto out_close_in;

	/* TODO: need a streaming-friendly solution */
	ret = map_file_contents(&in, stbuf.st_size);
	if (ret != 0)
		goto out_close_out;

	ret = do_decompress(decompressor, &in, &out, options);
	if (ret != 0)
		goto out_close_out;

	if (oldpath != NULL && newpath != NULL)
		restore_metadata(&out, newpath, &stbuf);
	ret = 0;
out_close_out:
	ret2 = xclose(&out);
	if (ret == 0)
		ret = ret2;
	if (ret != 0 && newpath != NULL)
		tunlink(newpath);
out_close_in:
	xclose(&in);
	if (ret == 0 && oldpath != NULL && newpath != NULL && !options->keep)
		tunlink(oldpath);
out_free_paths:
	if (newpath != path)
		free(newpath);
	if (oldpath != path)
		free(oldpath);
	return ret;
}

static int
compress_file(struct libdeflate_compressor *compressor, const tchar *path,
	      const struct options *options)
{
	tchar *newpath = NULL;
	struct file_stream in;
	struct file_stream out;
	stat_t stbuf;
	int ret;
	int ret2;

	if (path != NULL && !options->to_stdout) {
		if (!options->force && has_suffix(path, options->suffix)) {
			msg("%"TS": already has %"TS" suffix -- skipping",
			    path, options->suffix);
			return 0;
		}
		newpath = append_suffix(path, options->suffix);
		if (newpath == NULL)
			return -1;
	}

	ret = xopen_for_read(path, options->force || options->to_stdout, &in);
	if (ret != 0)
		goto out_free_newpath;

	ret = stat_file(&in, &stbuf, options->force || options->keep ||
			path == NULL || newpath == NULL);
	if (ret != 0)
		goto out_close_in;

	ret = xopen_for_write(newpath, options->force, &out);
	if (ret != 0)
		goto out_close_in;

	if (!options->force && isatty(out.fd)) {
		msg("Refusing to write compressed data to terminal. "
		    "Use -f to override.\nFor help, use -h.");
		ret = -1;
		goto out_close_out;
	}

	/* TODO: need a streaming-friendly solution */
	ret = map_file_contents(&in, stbuf.st_size);
	if (ret != 0)
		goto out_close_out;

	ret = do_compress(compressor, &in, &out);
	if (ret != 0)
		goto out_close_out;

	if (path != NULL && newpath != NULL)
		restore_metadata(&out, newpath, &stbuf);
	ret = 0;
out_close_out:
	ret2 = xclose(&out);
	if (ret == 0)
		ret = ret2;
	if (ret != 0 && newpath != NULL)
		tunlink(newpath);
out_close_in:
	xclose(&in);
	if (ret == 0 && path != NULL && newpath != NULL && !options->keep)
		tunlink(path);
out_free_newpath:
	free(newpath);
	return ret;
}

int
tmain(int argc, tchar *argv[])
{
	tchar *default_file_list[] = { NULL };
	struct options options;
	int opt_char;
	int i;
	int ret;

	begin_program(argv);

	options.to_stdout = false;
	options.decompress = is_gunzip();
	options.force = false;
	options.keep = false;
	options.test = false;
	options.compression_level = 6;
	options.suffix = T(".gz");

	while ((opt_char = tgetopt(argc, argv, optstring)) != -1) {
		switch (opt_char) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			options.compression_level =
				parse_compression_level(opt_char, toptarg);
			if (options.compression_level < 0)
				return 1;
			break;
		case 'c':
			options.to_stdout = true;
			break;
		case 'd':
			options.decompress = true;
			break;
		case 'f':
			options.force = true;
			break;
		case 'h':
			show_usage(stdout);
			return 0;
		case 'k':
			options.keep = true;
			break;
		case 'n':
			/*
			 * -n means don't save or restore the original filename
			 *  in the gzip header.  Currently this implementation
			 *  already behaves this way by default, so accept the
			 *  option as a no-op.
			 */
			break;
		case 'S':
			options.suffix = toptarg;
			if (options.suffix[0] == T('\0')) {
				msg("invalid suffix");
				return 1;
			}
			break;
		case 't':
			options.test = true;
			options.decompress = true;
			options.to_stdout = true;
			/*
			 * -t behaves just like the more commonly used -c
			 * option, except that -t doesn't actually write
			 * anything.  For ease of implementation, just pretend
			 * that -c was specified too.
			 */
			break;
		case 'V':
			show_version();
			return 0;
		default:
			show_usage(stderr);
			return 1;
		}
	}

	argv += toptind;
	argc -= toptind;

	if (argc == 0) {
		argv = default_file_list;
		argc = ARRAY_LEN(default_file_list);
	} else {
		for (i = 0; i < argc; i++)
			if (argv[i][0] == '-' && argv[i][1] == '\0')
				argv[i] = NULL;
	}

	ret = 0;
	if (options.decompress) {
		struct libdeflate_decompressor *d;

		d = alloc_decompressor();
		if (d == NULL)
			return 1;

		for (i = 0; i < argc; i++)
			ret |= -decompress_file(d, argv[i], &options);

		libdeflate_free_decompressor(d);
	} else {
		struct libdeflate_compressor *c;

		c = alloc_compressor(options.compression_level);
		if (c == NULL)
			return 1;

		for (i = 0; i < argc; i++)
			ret |= -compress_file(c, argv[i], &options);

		libdeflate_free_compressor(c);
	}

	/*
	 * If ret=0, there were no warnings or errors.  Exit with status 0.
	 * If ret=2, there was at least one warning.  Exit with status 2.
	 * Else, there was at least one error.  Exit with status 1.
	 */
	if (ret != 0 && ret != 2)
		ret = 1;

	return ret;
}
