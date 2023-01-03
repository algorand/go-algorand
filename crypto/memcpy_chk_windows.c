// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

// +build gc

#include "_cgo_export.h"
#include <string.h>

extern void crosscall2(void (*fn)(void *, int), void *, int);
extern void _cgo_panic(void *, int);

void * __memcpy_chk (void *dstpp, const void *srcpp, size_t len, size_t dstlen)
{
	if (dstlen < len) {
		struct { const char *p; } a;

		a.p = "panic from __memcpy_chk";
		crosscall2(_cgo_panic, &a, sizeof a);
	}
	return memcpy (dstpp, srcpp, len);
}
