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
	"io"
	"sync"

	"github.com/algorand/go-codec/codec"
)

// CodecHandle is used to instantiate msgpack encoders and decoders
// with our settings (canonical, paranoid about decoding errors)
var CodecHandle *codec.MsgpackHandle

// JSONHandle is used to instantiate JSON encoders and decoders
// with our settings (canonical, paranoid about decoding errors)
var JSONHandle *codec.JsonHandle

// Decoder is our interface for a thing that can decode objects.
type Decoder interface {
	Decode(objptr interface{}) error
}

func init() {
	CodecHandle = new(codec.MsgpackHandle)
	CodecHandle.ErrorIfNoField = true
	CodecHandle.ErrorIfNoArrayExpand = true
	CodecHandle.Canonical = true
	CodecHandle.RecursiveEmptyCheck = true
	CodecHandle.WriteExt = true
	CodecHandle.PositiveIntUnsigned = true
	CodecHandle.Raw = true

	JSONHandle = new(codec.JsonHandle)
	JSONHandle.ErrorIfNoField = true
	JSONHandle.ErrorIfNoArrayExpand = true
	JSONHandle.Canonical = true
	JSONHandle.RecursiveEmptyCheck = true
	JSONHandle.Indent = 2
	JSONHandle.HTMLCharsAsIs = true
}

type codecBytes struct {
	enc *codec.Encoder

	// Reuse this slice variable so that we don't have to allocate a fresh
	// slice object (runtime.newobject), separate from allocating the slice
	// payload (runtime.makeslice).
	buf []byte
}

var codecBytesPool = sync.Pool{
	New: func() interface{} {
		return &codecBytes{
			enc: codec.NewEncoderBytes(nil, CodecHandle),
		}
	},
}

var codecStreamPool = sync.Pool{
	New: func() interface{} {
		return codec.NewEncoder(nil, CodecHandle)
	},
}

const initEncodeBufSize = 256

// Encode returns a msgpack-encoded byte buffer for a given object
func Encode(obj interface{}) []byte {
	codecBytes := codecBytesPool.Get().(*codecBytes)
	codecBytes.buf = make([]byte, initEncodeBufSize)
	codecBytes.enc.ResetBytes(&codecBytes.buf)
	codecBytes.enc.MustEncode(obj)
	res := codecBytes.buf
	// Don't use defer because it incurs a non-trivial overhead
	// for encoding small objects.  If MustEncode panics, we will
	// let the GC deal with the codecBytes object.
	codecBytesPool.Put(codecBytes)
	return res
}

// CountingWriter is an implementation of io.Writer that tracks the number
// of bytes written (but discards the actual bytes).
type CountingWriter struct {
	N int
}

func (cw *CountingWriter) Write(b []byte) (int, error) {
	blen := len(b)
	cw.N += blen
	return blen, nil
}

// EncodeLen returns len(Encode(obj))
func EncodeLen(obj interface{}) int {
	var cw CountingWriter
	EncodeStream(&cw, obj)
	return cw.N
}

// EncodeStream is like Encode but writes to an io.Writer instead.
func EncodeStream(w io.Writer, obj interface{}) {
	enc := codecStreamPool.Get().(*codec.Encoder)
	enc.Reset(w)
	enc.MustEncode(obj)
	// Don't use defer because it incurs a non-trivial overhead
	// for encoding small objects.  If MustEncode panics, we will
	// let the GC deal with the enc object.
	codecStreamPool.Put(enc)
}

// EncodeJSON returns a JSON-encoded byte buffer for a given object
func EncodeJSON(obj interface{}) []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, JSONHandle)
	enc.MustEncode(obj)
	return b
}

// Decode attempts to decode a msgpack-encoded byte buffer into an
// object instance pointed to by objptr
func Decode(b []byte, objptr interface{}) error {
	dec := codec.NewDecoderBytes(b, CodecHandle)
	return dec.Decode(objptr)
}

// DecodeStream is like Decode but reads from an io.Reader instead.
func DecodeStream(r io.Reader, objptr interface{}) error {
	dec := codec.NewDecoder(r, CodecHandle)
	return dec.Decode(objptr)
}

// DecodeJSON attempts to decode a JSON-encoded byte buffer into an
// object instance pointed to by objptr
func DecodeJSON(b []byte, objptr interface{}) error {
	dec := codec.NewDecoderBytes(b, JSONHandle)
	return dec.Decode(objptr)
}

// NewEncoder returns an encoder object writing bytes into [w].
func NewEncoder(w io.Writer) *codec.Encoder {
	return codec.NewEncoder(w, CodecHandle)
}

// NewDecoder returns a decoder object reading bytes from [r].
func NewDecoder(r io.Reader) Decoder {
	return codec.NewDecoder(r, CodecHandle)
}

// NewJSONDecoder returns a json decoder object reading bytes from [r].
func NewJSONDecoder(r io.Reader) Decoder {
	return codec.NewDecoder(r, JSONHandle)
}

// NewDecoderBytes returns a decoder object reading bytes from [b].
func NewDecoderBytes(b []byte) Decoder {
	return codec.NewDecoderBytes(b, CodecHandle)
}
