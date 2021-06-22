// Copyright (C) 2019-2021 Algorand, Inc.
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

package compress

// #cgo CFLAGS: -Wall -std=c99 -I${SRCDIR}/libdeflate
// #cgo amd64 CFLAGS: -DX86 -D__x86_64__ -D__i386__
// #cgo arm64 CFLAGS: -DARM
// #cgo arm CFLAGS: -DARM
// #cgo linux,amd64 CFLAGS: -march=sandybridge
// #cgo darwin,amd64 CFLAGS: -march=tremont
// #include <stdint.h>
// int isNull(void * c) {
// 	if(!c) {
//		return 1;
//	}
//	return 0;
// };
//
// #ifdef X86
// #include "lib/x86/cpu_features.c"
// #endif
// #ifdef ARM
// #include "lib/arm/cpu_features.c"
// #endif
// #define dispatch crc32_dispatch
// #include "lib/crc32.c"
// #undef dispatch
// #define dispatch compress_dispatch
// #define bitbuf_t compress_bitbuf_t
// #include "lib/deflate_compress.c"
// #undef bitbuf_t
// #undef dispatch
// #undef BITBUF_NBITS
// #include "lib/deflate_decompress.c"
// #include "lib/gzip_compress.c"
// #include "lib/gzip_decompress.c"
// #include "lib/utils.c"
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

var (
	// ErrOutOfMemory is returned when we fail to allocate the compressor/decompressor
	ErrOutOfMemory = errors.New("out of memory")
	// ErrShortBuffer is returned when the output buffer is too small to fit the compressed/decompressed data
	ErrShortBuffer = errors.New("short buffer")
	// ErrNoInput is returned when no input buffer data is provided
	ErrNoInput = errors.New("empty input")
	// ErrBadData is returned when the compressed data is corrupted
	ErrBadData = errors.New("data was corrupted, invalid or unsupported")
	// ErrInsufficientSpace is returned when the provided output buffer is found to be too small during the decompression
	ErrInsufficientSpace = errors.New("decompression failed: buffer too short. Retry with larger buffer")
	// ErrShortOutput should not be generated using the current libdeflate usage, but remain here for compatibility
	ErrShortOutput = errors.New("buffer too long: decompressed to fewer bytes than expected, indicating possible error in decompression. Make sure your out buffer has the exact length of the decompressed data or pass nil for out")
	// ErrPartiallyConsumedData is returned if only a subset of the input data was consumed during the decompression
	ErrPartiallyConsumedData = errors.New("partially consumed data")

	// ErrUnknown returned when the libdeflate returns unexpected enum error
	ErrUnknown = errors.New("unknown error code from decompressor library")
)

// Compress the input buffer into the output buffer.
func Compress(in, out []byte, compressLevel int) (int, []byte, error) {
	if len(in) == 0 {
		return 0, out, ErrNoInput
	}
	if cap(out) == 0 {
		return 0, out, ErrShortBuffer
	}

	if compressLevel < 1 {
		compressLevel = 1
	} else if compressLevel > 12 {
		compressLevel = 12
	}

	c := C.libdeflate_alloc_compressor(C.int(compressLevel))
	if C.isNull(unsafe.Pointer(c)) == 1 {
		return 0, out, ErrOutOfMemory
	}
	defer func() {
		C.libdeflate_free_compressor(c)
	}()
	inAddr := startMemAddr(in)
	outAddr := startMemAddr(out)

	written := int(C.libdeflate_gzip_compress(c, unsafe.Pointer(inAddr), C.size_t(len(in)), unsafe.Pointer(outAddr), C.size_t(cap(out))))

	if written == 0 {
		return written, out, ErrShortBuffer
	}
	return written, out[:written], nil
}

// Decompress decompresses the input buffer data into the output buffer.
func Decompress(in, out []byte) ([]byte, error) {
	if len(in) == 0 {
		return out, ErrNoInput
	}
	if cap(out) == 0 {
		return out, ErrShortBuffer
	}
	dc := C.libdeflate_alloc_decompressor()
	if C.isNull(unsafe.Pointer(dc)) == 1 {
		return out, ErrOutOfMemory
	}
	defer func() {
		C.libdeflate_free_decompressor(dc)
	}()

	inAddr := startMemAddr(in)
	outAddr := startMemAddr(out)

	var actualInBytes C.size_t
	var actualOutBytes C.size_t
	r := C.libdeflate_gzip_decompress_ex(dc, unsafe.Pointer(inAddr), C.size_t(len(in)), unsafe.Pointer(outAddr), C.size_t(cap(out)), &actualInBytes, &actualOutBytes)

	runtime.KeepAlive(&actualInBytes)
	runtime.KeepAlive(&actualOutBytes)
	switch r {
	case C.LIBDEFLATE_SUCCESS:
		if actualInBytes != C.size_t(len(in)) {
			// return an error if not all the data was consumed.
			return out, ErrPartiallyConsumedData
		}
		return out[:actualOutBytes], nil
	case C.LIBDEFLATE_BAD_DATA:
		return out, ErrBadData
	case C.LIBDEFLATE_SHORT_OUTPUT:
		return out, ErrShortOutput
	case C.LIBDEFLATE_INSUFFICIENT_SPACE:
		return out, ErrInsufficientSpace
	default:
		return out, ErrUnknown
	}
}

func startMemAddr(b []byte) *byte {
	if len(b) > 0 {
		return &b[0]
	}

	b = append(b, 0)
	ptr := &b[0]
	b = b[0:0]

	return ptr
}

func init() {
	// initialize dispatch tables. This is important since we want to avoid race conditions when running the dispatch over multiple cores.
	decompressedBuffer := []byte{1, 2, 3, 4}
	compressedBuffer := make([]byte, 128)
	_, compressedOutput, _ := Compress(decompressedBuffer, compressedBuffer, 9)
	decompressedBuffer = make([]byte, 128)
	Decompress(compressedOutput, decompressedBuffer)
}
