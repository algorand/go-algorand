// Copyright (C) 2019-2020 Algorand, Inc.
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

package binary

import (
	"encoding/binary"
	"io"
)

type MarshalerTo interface {
	MarshalBinaryTo(w io.Writer) (int, error)
}

type SilentWriter struct {
	writer io.Writer
	count  int
	err    error
}

func NewSilentWriter(w io.Writer) *SilentWriter {
	return &SilentWriter{writer: w}
}

func (sw *SilentWriter) Count() int {
	return sw.count
}

func (sw *SilentWriter) Error() error {
	return sw.err
}

func (sw *SilentWriter) WriteUInt(ui uint64) {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, ui)
	sw.SilentWriteBytes(buf[:n])
}

func (sw *SilentWriter) SilentWriteMarshaler(m MarshalerTo) {
	if sw.err != nil {
		return
	}
	n, e := m.MarshalBinaryTo(sw.writer)
	sw.err = e
	sw.count += n
}

func (sw *SilentWriter) SilentWriteBytes(b []byte) {
	if sw.err != nil {
		return
	}
	n, e := sw.writer.Write(b)
	sw.err = e
	sw.count += n
}

func ReadUInt(r io.ByteReader) (uint64, error) {
	return binary.ReadUvarint(r)
}

// DecodingError
type DecodingError struct {
	ComponentName string
	Position      int
	Err           error
}

func NewSimpleDecodingErr(componentName string, err error) *DecodingError {
	return &DecodingError{ComponentName: componentName, Err: err}
}

func (de *DecodingError) Error() string {
	return "error while decoding '" + de.FullName() + "': " + de.Cause().Error()
}

func (de *DecodingError) Cause() error {
	if e, ok := de.Err.(*DecodingError); ok {
		return e.Cause()
	}
	return de.Err
}

func (de *DecodingError) Unwrap() error {
	return de.Err
}

func (de *DecodingError) FullName() string {
	if e, ok := de.Err.(*DecodingError); ok {
		return de.ComponentName + "." + e.ComponentName
	}
	return de.ComponentName
}

func (de *DecodingError) FinalPosition() int {
	if e, ok := de.Err.(*DecodingError); ok {
		return de.Position + e.Position
	}
	return de.Position
}
