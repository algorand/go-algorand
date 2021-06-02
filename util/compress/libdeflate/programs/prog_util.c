/*
 * prog_util.c - utility functions for programs
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
#include <fcntl.h>
#include <stdarg.h>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/mman.h>
#endif

#ifndef O_BINARY
#  define O_BINARY 0
#endif
#ifndef O_SEQUENTIAL
#  define O_SEQUENTIAL 0
#endif
#ifndef O_NOFOLLOW
#  define O_NOFOLLOW 0
#endif
#ifndef O_NONBLOCK
#  define O_NONBLOCK 0
#endif
#ifndef O_NOCTTY
#  define O_NOCTTY 0
#endif

/* The invocation name of the program (filename component only) */
const tchar *prog_invocation_name;

static void
do_msg(const char *format, bool with_errno, va_list va)
{
	int saved_errno = errno;

	fprintf(stderr, "%"TS": ", prog_invocation_name);
	vfprintf(stderr, format, va);
	if (with_errno)
		fprintf(stderr, ": %s\n", strerror(saved_errno));
	else
		fprintf(stderr, "\n");

	errno = saved_errno;
}

/* Print a message to standard error */
void
msg(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	do_msg(format, false, va);
	va_end(va);
}

/* Print a message to standard error, including a description of errno */
void
msg_errno(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	do_msg(format, true, va);
	va_end(va);
}

/* malloc() wrapper */
void *
xmalloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL && size == 0)
		p = malloc(1);
	if (p == NULL)
		msg("Out of memory");
	return p;
}

/*
 * Retrieve a pointer to the filename component of the specified path.
 *
 * Note: this does not modify the path.  Therefore, it is not guaranteed to work
 * properly for directories, since a path to a directory might have trailing
 * slashes.
 */
static const tchar *
get_filename(const tchar *path)
{
	const tchar *slash = tstrrchr(path, '/');
#ifdef _WIN32
	const tchar *backslash = tstrrchr(path, '\\');
	if (backslash != NULL && (slash == NULL || backslash > slash))
		slash = backslash;
#endif
	if (slash != NULL)
		return slash + 1;
	return path;
}

void
begin_program(tchar *argv[])
{
	prog_invocation_name = get_filename(argv[0]);

#ifdef FREESTANDING
	/* This allows testing freestanding library builds. */
	libdeflate_set_memory_allocator(malloc, free);
#endif
}

/* Create a copy of 'path' surrounded by double quotes */
static tchar *
quote_path(const tchar *path)
{
	size_t len = tstrlen(path);
	tchar *result;

	result = xmalloc((1 + len + 1 + 1) * sizeof(tchar));
	if (result == NULL)
		return NULL;
	result[0] = '"';
	tmemcpy(&result[1], path, len);
	result[1 + len] = '"';
	result[1 + len + 1] = '\0';
	return result;
}

/* Open a file for reading, or set up standard input for reading */
int
xopen_for_read(const tchar *path, bool symlink_ok, struct file_stream *strm)
{
	strm->mmap_token = NULL;
	strm->mmap_mem = NULL;

	if (path == NULL) {
		strm->is_standard_stream = true;
		strm->name = T("standard input");
		strm->fd = STDIN_FILENO;
	#ifdef _WIN32
		_setmode(strm->fd, O_BINARY);
	#endif
		return 0;
	}

	strm->is_standard_stream = false;

	strm->name = quote_path(path);
	if (strm->name == NULL)
		return -1;

	strm->fd = topen(path, O_RDONLY | O_BINARY | O_NONBLOCK | O_NOCTTY |
			 (symlink_ok ? 0 : O_NOFOLLOW) | O_SEQUENTIAL);
	if (strm->fd < 0) {
		msg_errno("Can't open %"TS" for reading", strm->name);
		free(strm->name);
		return -1;
	}

#if defined(HAVE_POSIX_FADVISE) && (O_SEQUENTIAL == 0)
	(void)posix_fadvise(strm->fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

	return 0;
}

/* Open a file for writing, or set up standard output for writing */
int
xopen_for_write(const tchar *path, bool overwrite, struct file_stream *strm)
{
	int ret = -1;

	strm->mmap_token = NULL;
	strm->mmap_mem = NULL;

	if (path == NULL) {
		strm->is_standard_stream = true;
		strm->name = T("standard output");
		strm->fd = STDOUT_FILENO;
	#ifdef _WIN32
		_setmode(strm->fd, O_BINARY);
	#endif
		return 0;
	}

	strm->is_standard_stream = false;

	strm->name = quote_path(path);
	if (strm->name == NULL)
		goto err;
retry:
	strm->fd = topen(path, O_WRONLY | O_BINARY | O_NOFOLLOW |
				O_CREAT | O_EXCL, 0644);
	if (strm->fd < 0) {
		if (errno != EEXIST) {
			msg_errno("Can't open %"TS" for writing", strm->name);
			goto err;
		}
		if (!overwrite) {
			if (!isatty(STDERR_FILENO) || !isatty(STDIN_FILENO)) {
				msg("%"TS" already exists; use -f to overwrite",
				    strm->name);
				ret = -2; /* warning only */
				goto err;
			}
			fprintf(stderr, "%"TS": %"TS" already exists; "
				"overwrite? (y/n) ",
				prog_invocation_name, strm->name);
			if (getchar() != 'y') {
				msg("Not overwriting.");
				goto err;
			}
		}
		if (tunlink(path) != 0) {
			msg_errno("Unable to delete %"TS, strm->name);
			goto err;
		}
		goto retry;
	}

	return 0;

err:
	free(strm->name);
	return ret;
}

/* Read the full contents of a file into memory */
static int
read_full_contents(struct file_stream *strm)
{
	size_t filled = 0;
	size_t capacity = 4096;
	char *buf;
	int ret;

	buf = xmalloc(capacity);
	if (buf == NULL)
		return -1;
	do {
		if (filled == capacity) {
			char *newbuf;

			if (capacity == SIZE_MAX)
				goto oom;
			capacity += MIN(SIZE_MAX - capacity, capacity);
			newbuf = realloc(buf, capacity);
			if (newbuf == NULL)
				goto oom;
			buf = newbuf;
		}
		ret = xread(strm, &buf[filled], capacity - filled);
		if (ret < 0)
			goto err;
		filled += ret;
	} while (ret != 0);

	strm->mmap_mem = buf;
	strm->mmap_size = filled;
	return 0;

err:
	free(buf);
	return ret;
oom:
	msg("Out of memory!  %"TS" is too large to be processed by "
	    "this program as currently implemented.", strm->name);
	ret = -1;
	goto err;
}

/* Map the contents of a file into memory */
int
map_file_contents(struct file_stream *strm, u64 size)
{
	if (size == 0) /* mmap isn't supported on empty files */
		return read_full_contents(strm);

	if (size > SIZE_MAX) {
		msg("%"TS" is too large to be processed by this program",
		    strm->name);
		return -1;
	}
#ifdef _WIN32
	strm->mmap_token = CreateFileMapping(
				(HANDLE)(intptr_t)_get_osfhandle(strm->fd),
				NULL, PAGE_READONLY, 0, 0, NULL);
	if (strm->mmap_token == NULL) {
		DWORD err = GetLastError();
		if (err == ERROR_BAD_EXE_FORMAT) /* mmap unsupported */
			return read_full_contents(strm);
		msg("Unable create file mapping for %"TS": Windows error %u",
		    strm->name, (unsigned int)err);
		return -1;
	}

	strm->mmap_mem = MapViewOfFile((HANDLE)strm->mmap_token,
				       FILE_MAP_READ, 0, 0, size);
	if (strm->mmap_mem == NULL) {
		msg("Unable to map %"TS" into memory: Windows error %u",
		    strm->name, (unsigned int)GetLastError());
		CloseHandle((HANDLE)strm->mmap_token);
		return -1;
	}
#else /* _WIN32 */
	strm->mmap_mem = mmap(NULL, size, PROT_READ, MAP_SHARED, strm->fd, 0);
	if (strm->mmap_mem == MAP_FAILED) {
		strm->mmap_mem = NULL;
		if (errno == ENODEV) /* mmap isn't supported on this file */
			return read_full_contents(strm);
		if (errno == ENOMEM) {
			msg("%"TS" is too large to be processed by this "
			    "program", strm->name);
		} else {
			msg_errno("Unable to map %"TS" into memory",
				  strm->name);
		}
		return -1;
	}

#ifdef HAVE_POSIX_MADVISE
	(void)posix_madvise(strm->mmap_mem, size, POSIX_MADV_SEQUENTIAL);
#endif
	strm->mmap_token = strm; /* anything that's not NULL */

#endif /* !_WIN32 */
	strm->mmap_size = size;
	return 0;
}

/*
 * Read from a file, returning the full count to indicate all bytes were read, a
 * short count (possibly 0) to indicate EOF, or -1 to indicate error.
 */
ssize_t
xread(struct file_stream *strm, void *buf, size_t count)
{
	char *p = buf;
	size_t orig_count = count;

	while (count != 0) {
		ssize_t res = read(strm->fd, p, MIN(count, INT_MAX));
		if (res == 0)
			break;
		if (res < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			msg_errno("Error reading from %"TS, strm->name);
			return -1;
		}
		p += res;
		count -= res;
	}
	return orig_count - count;
}

/* Write to a file, returning 0 if all bytes were written or -1 on error */
int
full_write(struct file_stream *strm, const void *buf, size_t count)
{
	const char *p = buf;

	while (count != 0) {
		ssize_t res = write(strm->fd, p, MIN(count, INT_MAX));
		if (res <= 0) {
			msg_errno("Error writing to %"TS, strm->name);
			return -1;
		}
		p += res;
		count -= res;
	}
	return 0;
}

/* Close a file, returning 0 on success or -1 on error */
int
xclose(struct file_stream *strm)
{
	int ret = 0;

	if (!strm->is_standard_stream) {
		if (close(strm->fd) != 0) {
			msg_errno("Error closing %"TS, strm->name);
			ret = -1;
		}
		free(strm->name);
	}

	if (strm->mmap_token != NULL) {
#ifdef _WIN32
		UnmapViewOfFile(strm->mmap_mem);
		CloseHandle((HANDLE)strm->mmap_token);
#else
		munmap(strm->mmap_mem, strm->mmap_size);
#endif
		strm->mmap_token = NULL;
	} else {
		free(strm->mmap_mem);
	}
	strm->mmap_mem = NULL;
	strm->fd = -1;
	strm->name = NULL;
	return ret;
}

/*
 * Parse the compression level given on the command line, returning the
 * compression level on success or -1 on error
 */
int
parse_compression_level(tchar opt_char, const tchar *arg)
{
	int level;

	if (arg == NULL)
		arg = T("");

	if (opt_char < '0' || opt_char > '9')
		goto invalid;
	level = opt_char - '0';

	if (arg[0] != '\0') {
		if (arg[0] < '0' || arg[0] > '9')
			goto invalid;
		if (arg[1] != '\0')	/* Levels are at most 2 digits */
			goto invalid;
		if (level == 0)		/* Don't allow arguments like "-01" */
			goto invalid;
		level = (level * 10) + (arg[0] - '0');
	}

	if (level < 0 || level > 12)
		goto invalid;

	return level;

invalid:
	msg("Invalid compression level: \"%"TC"%"TS"\".  "
	    "Must be an integer in the range [0, 12].", opt_char, arg);
	return -1;
}

/* Allocate a new DEFLATE compressor */
struct libdeflate_compressor *
alloc_compressor(int level)
{
	struct libdeflate_compressor *c;

	c = libdeflate_alloc_compressor(level);
	if (c == NULL) {
		msg_errno("Unable to allocate compressor with "
			  "compression level %d", level);
	}
	return c;
}

/* Allocate a new DEFLATE decompressor */
struct libdeflate_decompressor *
alloc_decompressor(void)
{
	struct libdeflate_decompressor *d;

	d = libdeflate_alloc_decompressor();
	if (d == NULL)
		msg_errno("Unable to allocate decompressor");

	return d;
}
