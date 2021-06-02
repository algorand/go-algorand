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

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrivialCompression(t *testing.T) {
	bufLen := 10240
	buffer := make([]byte, bufLen)
	for i := range buffer {
		buffer[i] = byte(i % 256)
	}

	compressedBuffer := make([]byte, 0, bufLen)
	len, compressedOutput, err := Compress(buffer, compressedBuffer, 9)
	require.NoError(t, err)
	require.NotZero(t, len)
	require.Equal(t, compressedBuffer[:len], compressedOutput)

	decompressedBuffer := make([]byte, 0, bufLen)
	decompressedOutput, err := Decompress(compressedOutput, decompressedBuffer)
	require.NoError(t, err)
	require.Equal(t, decompressedOutput, buffer)
}

func BenchmarkCompression(b *testing.B) {
	bufLen := 1024000
	buffer := make([]byte, bufLen)
	outBuffer := make([]byte, 0, bufLen)
	for i := range buffer {
		buffer[i] = byte(i % 256)
	}
	var targetLength int
	b.Run("compress/gzip", func(b *testing.B) {
		for k := 0; k < b.N; k++ {
			outBuffer := bytes.NewBuffer(outBuffer)
			writer := gzip.NewWriter(outBuffer)
			writer.Write(buffer)
			writer.Close()
			targetLength = outBuffer.Len()
		}
	})
	// figure out desired compression level.
	compressionLevel := 1
	for {
		len, _, _ := Compress(buffer, outBuffer, compressionLevel)
		if len <= targetLength+128 || compressionLevel > 11 {
			break
		}
		compressionLevel++
	}
	b.Run("deflateCompression", func(b *testing.B) {
		for k := 0; k < b.N; k++ {
			Compress(buffer, outBuffer[:cap(outBuffer)], compressionLevel)
		}
	})
}

func BenchmarkDecompression(b *testing.B) {
	bufLen := 1024000
	decompressedBuffer := make([]byte, bufLen)
	for i := range decompressedBuffer {
		decompressedBuffer[i] = byte(i % 256)
	}

	// create the compress/gzip compressed buffer.
	gzipCompressedBuffer := bytes.NewBuffer([]byte{})
	writer := gzip.NewWriter(gzipCompressedBuffer)
	writer.Write(decompressedBuffer)
	writer.Close()
	gzipCompressedBytes := gzipCompressedBuffer.Bytes()

	// create the deflate compressed buffer.
	deflateCompressedBuffer := make([]byte, 0, bufLen)
	_, deflateCompressedBuffer, _ = Compress(decompressedBuffer, deflateCompressedBuffer, 1)

	b.Run("compress/gzip", func(b *testing.B) {
		for k := 0; k < b.N; k++ {
			stage := make([]byte, 1024)
			reader, err := gzip.NewReader(bytes.NewBuffer(gzipCompressedBytes))
			require.NoError(b, err)
			for {
				n, err := reader.Read(stage[:])
				if n == 0 || err != nil {
					break
				}
			}
			reader.Close()
			gzipCompressedBuffer.Reset()
		}
	})

	b.Run("deflateCompression", func(b *testing.B) {
		outBuffer := make([]byte, 0, bufLen)
		for k := 0; k < b.N; k++ {
			Decompress(deflateCompressedBuffer, outBuffer[:cap(outBuffer)])
		}
	})
}
