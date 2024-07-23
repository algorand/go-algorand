// Copyright (C) 2019-2024 Algorand, Inc.
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
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/algorand/go-codec/codec"
	"github.com/algorand/msgp/msgp"
)

// ErrInvalidObject is used to state that an object decoding has failed because it's invalid.
var ErrInvalidObject = errors.New("unmarshalled object is invalid")

// CodecHandle is used to instantiate msgpack encoders and decoders
// with our settings (canonical, paranoid about decoding errors)
var CodecHandle *codec.MsgpackHandle

// JSONHandle is used to instantiate JSON encoders and decoders
// with our settings (canonical, paranoid about decoding errors)
var JSONHandle *codec.JsonHandle

// JSONStrictHandle is the same as JSONHandle but with MapKeyAsString=true
// for correct maps[int]interface{} encoding
var JSONStrictHandle *codec.JsonHandle

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

	JSONStrictHandle = new(codec.JsonHandle)
	JSONStrictHandle.ErrorIfNoField = JSONHandle.ErrorIfNoField
	JSONStrictHandle.ErrorIfNoArrayExpand = JSONHandle.ErrorIfNoArrayExpand
	JSONStrictHandle.Canonical = JSONHandle.Canonical
	JSONStrictHandle.RecursiveEmptyCheck = JSONHandle.RecursiveEmptyCheck
	JSONStrictHandle.Indent = JSONHandle.Indent
	JSONStrictHandle.HTMLCharsAsIs = JSONHandle.HTMLCharsAsIs
	JSONStrictHandle.MapKeyAsString = true
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

// EncodeReflect returns a msgpack-encoded byte buffer for a given object,
// using reflection.
func EncodeReflect(obj interface{}) []byte {
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

// EncodeMsgp returns a msgpack-encoded byte buffer, requiring
// that we pre-generated the code for doing so using msgp.
func EncodeMsgp(obj msgp.Marshaler) []byte {
	return obj.MarshalMsg(nil)
}

// Encode returns a msgpack-encoded byte buffer for a given object.
func Encode(obj msgp.Marshaler) []byte {
	if obj.CanMarshalMsg(obj) {
		return EncodeMsgp(obj)
	}

	// Use fmt instead of logging to avoid import loops;
	// the expectation is that this should never happen.
	fmt.Fprintf(os.Stderr, "Encoding %T using go-codec; stray embedded field?\n", obj)
	return EncodeReflect(obj)
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

// EncodeJSONStrict returns a JSON-encoded byte buffer for a given object
// It is the same EncodeJSON but encodes map's int keys as strings
func EncodeJSONStrict(obj interface{}) []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, JSONStrictHandle)
	enc.MustEncode(obj)
	return b
}

// DecodeReflect attempts to decode a msgpack-encoded byte buffer
// into an object instance pointed to by objptr, using reflection.
func DecodeReflect(b []byte, objptr interface{}) error {
	dec := codec.NewDecoderBytes(b, CodecHandle)
	return dec.Decode(objptr)
}

// DecodeMsgp attempts to decode a msgpack-encoded byte buffer into
// an object instance pointed to by objptr, requiring that we pre-
// generated the code for doing so using msgp.
func DecodeMsgp(b []byte, objptr msgp.Unmarshaler) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("DecodeMsgp: %v", x)
		}
	}()

	var rem []byte
	rem, err = objptr.UnmarshalMsg(b)
	if err != nil {
		return err
	}

	// go-codec compat: allow remaining bytes, because go-codec allows it too
	if false {
		if len(rem) != 0 {
			return fmt.Errorf("decoding left %d remaining bytes", len(rem))
		}
	}

	return nil
}

// Decode attempts to decode a msgpack-encoded byte buffer
// into an object instance pointed to by objptr.
func Decode(b []byte, objptr msgp.Unmarshaler) error {
	if objptr.CanUnmarshalMsg(objptr) {
		return DecodeMsgp(b, objptr)
	}

	// Use fmt instead of logging to avoid import loops;
	// the expectation is that this should never happen.
	fmt.Fprintf(os.Stderr, "Decoding %T using go-codec; stray embedded field?\n", objptr)

	return DecodeReflect(b, objptr)
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

// NewJSONEncoder returns an encoder object writing bytes into [w].
func NewJSONEncoder(w io.Writer) *codec.Encoder {
	return codec.NewEncoder(w, JSONHandle)
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

// NewMsgpDecoderBytes returns a decoder object reading bytes from [b].
// that works with msgp-serialized objects
func NewMsgpDecoderBytes(b []byte) *MsgpDecoderBytes {
	return &MsgpDecoderBytes{b: b, pos: 0}
}

// MsgpDecoderBytes is a []byte decoder into msgp-encoded objects
type MsgpDecoderBytes struct {
	b   []byte
	pos int
}

// Decode an objptr from from a byte stream
func (d *MsgpDecoderBytes) Decode(objptr msgp.Unmarshaler) error {
	if !objptr.CanUnmarshalMsg(objptr) {
		return fmt.Errorf("object %T cannot be msgp-unmashalled", objptr)
	}
	if d.pos >= len(d.b) {
		return io.EOF
	}

	rem, err := objptr.UnmarshalMsg(d.b[d.pos:])
	if err != nil {
		return err
	}
	d.pos = (len(d.b) - len(rem))
	return nil
}

// Consumed returns number of bytes consumed so far.
func (d *MsgpDecoderBytes) Consumed() int {
	return d.pos
}

// Remaining returns number of bytes remained in the input buffer.
func (d *MsgpDecoderBytes) Remaining() int {
	return len(d.b) - d.pos
}

// encodingPool holds temporary byte slice buffers used for encoding messages.
var encodingPool = sync.Pool{
	New: func() interface{} {
		return &EncodingBuf{b: make([]byte, 0)}
	},
}

// EncodingBuf is a wrapper for a byte slice that can be used for encoding
type EncodingBuf struct {
	b []byte
}

// Bytes returns the underlying byte slice
func (eb *EncodingBuf) Bytes() []byte {
	return eb.b
}

// Update updates the underlying byte slice to the given one if its capacity exceeds the current one.
func (eb *EncodingBuf) Update(v []byte) *EncodingBuf {
	if cap(eb.b) < cap(v) {
		eb.b = v
	}
	return eb
}

// GetEncodingBuf returns a byte slice that can be used for encoding a
// temporary message.  The byte slice has zero length but potentially
// non-zero capacity.  The caller gets full ownership of the byte slice,
// but is encouraged to return it using PutEncodingBuf().
func GetEncodingBuf() *EncodingBuf {
	buf := encodingPool.Get().(*EncodingBuf)
	buf.b = buf.b[:0]
	return buf
}

// PutEncodingBuf places a byte slice into the pool of temporary buffers
// for encoding.  The caller gives up ownership of the byte slice when
// passing it to PutEncodingBuf().
func PutEncodingBuf(buf *EncodingBuf) {
	encodingPool.Put(buf)
}
