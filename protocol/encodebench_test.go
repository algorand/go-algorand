// Copyright (C) 2019 Algorand, Inc.
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

package protocol

import (
	"testing"

	"github.com/algorand/go-codec/codec"
)

type s struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	X [32]byte `codec:"x"`
}

func BenchmarkCodecEncoder(b *testing.B) {
	var s s
	for i := 0; i < 32; i++ {
		s.X[i] = byte(i)
	}

	b.Run("Nil", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Encode(nil)
		}
	})

	b.Run("NilLen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EncodeLen(nil)
		}
	})

	b.Run("NilReset", func(b *testing.B) {
		enc := codec.NewEncoderBytes(nil, CodecHandle)
		for i := 0; i < b.N; i++ {
			var b []byte
			enc.ResetBytes(&b)
			enc.MustEncode(nil)
		}
	})

	b.Run("NilResetPrealloc", func(b *testing.B) {
		enc := codec.NewEncoderBytes(nil, CodecHandle)
		for i := 0; i < b.N; i++ {
			b := make([]byte, 256)
			enc.ResetBytes(&b)
			enc.MustEncode(nil)
		}
	})

	b.Run("NilCount", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var n CountingWriter
			enc := codec.NewEncoder(&n, CodecHandle)
			enc.MustEncode(nil)
		}
	})

	b.Run("NilCountReset", func(b *testing.B) {
		enc := codec.NewEncoder(nil, CodecHandle)
		var n CountingWriter
		for i := 0; i < b.N; i++ {
			enc.Reset(&n)
			enc.MustEncode(nil)
		}
	})

	b.Run("Encode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Encode(s)
		}
	})

	b.Run("EncodeStream", func(b *testing.B) {
		var n CountingWriter
		for i := 0; i < b.N; i++ {
			EncodeStream(&n, s)
		}
	})

	b.Run("EncodeStreamReuse", func(b *testing.B) {
		var n CountingWriter
		enc := codec.NewEncoder(&n, CodecHandle)
		for i := 0; i < b.N; i++ {
			enc.MustEncode(s)
		}
	})
}
