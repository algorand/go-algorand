/*
 * tgetopt.c - portable replacement for GNU getopt()
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

tchar *toptarg;
int toptind = 1, topterr = 1, toptopt;

/*
 * This is a simple implementation of getopt().  It can be compiled with either
 * 'char' or 'wchar_t' as the character type.
 *
 * Do *not* use this implementation if you need any of the following features,
 * as they are not supported:
 *	- Long options
 *	- Option-related arguments retained in argv, not nulled out
 *	- '+' and '-' characters in optstring
 */
int
tgetopt(int argc, tchar *argv[], const tchar *optstring)
{
	static tchar empty[1];
	static tchar *nextchar;
	static bool done;

	if (toptind == 1) {
		/* Starting to scan a new argument vector */
		nextchar = NULL;
		done = false;
	}

	while (!done && (nextchar != NULL || toptind < argc)) {
		if (nextchar == NULL) {
			/* Scanning a new argument */
			tchar *arg = argv[toptind++];
			if (arg[0] == '-' && arg[1] != '\0') {
				if (arg[1] == '-' && arg[2] == '\0') {
					/* All args after "--" are nonoptions */
					argv[toptind - 1] = NULL;
					done = true;
				} else {
					/* Start of short option characters */
					nextchar = &arg[1];
				}
			}
		} else {
			/* More short options in previous arg */
			tchar opt = *nextchar;
			tchar *p = tstrchr(optstring, opt);
			if (p == NULL) {
				if (topterr)
					msg("invalid option -- '%"TC"'", opt);
				toptopt = opt;
				return '?';
			}
			/* 'opt' is a valid short option character */
			nextchar++;
			toptarg = NULL;
			if (*(p + 1) == ':') {
				/* 'opt' can take an argument */
				if (*nextchar != '\0') {
					/* Optarg is in same argv argument */
					toptarg = nextchar;
					nextchar = empty;
				} else if (toptind < argc && *(p + 2) != ':') {
					/* Optarg is next argv argument */
					argv[toptind - 1] = NULL;
					toptarg = argv[toptind++];
				} else if (*(p + 2) != ':') {
					if (topterr && *optstring != ':') {
						msg("option requires an "
						    "argument -- '%"TC"'", opt);
					}
					toptopt = opt;
					opt = (*optstring == ':') ? ':' : '?';
				}
			}
			if (*nextchar == '\0') {
				argv[toptind - 1] = NULL;
				nextchar = NULL;
			}
			return opt;
		}
	}

	/* Done scanning.  Move all nonoptions to the end, set optind to the
	 * index of the first nonoption, and return -1. */
	toptind = argc;
	while (--argc > 0)
		if (argv[argc] != NULL)
			argv[--toptind] = argv[argc];
	done = true;
	return -1;
}
