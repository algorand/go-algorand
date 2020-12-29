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

// Package teal provides essential data types and tools for executing TEAL scripts.
// currently it supports following data types:
//
// UInt				representing an uint64
// ConstByteArray	representing an immutable fixed size []byte
// ByteArray		representing a fixed size []byte
package teal

import (
	"bytes"
	"fmt"
	"github.com/algorand/go-algorand/data/basics/newpkg/binary"
	"github.com/algorand/go-algorand/data/basics/newpkg/memory"
	"io"
	"log"
)

// TODO: add documentation

const MaxArrayLength = 256 * 1024

const (
	UintID = iota + 1
	ConstByteArrayID
	ByteArrayID
)

func init() {
	memory.RegisterReader(UintID, ReadUInt)
	memory.RegisterReader(ConstByteArrayID, ReadConstByteArray)
	memory.RegisterReader(ByteArrayID, ReadByteArray)
}

type UInt struct {
	value uint64
}

func NewUInt(value uint64) *UInt {
	return &UInt{value: value}
}

func ReadUInt(r io.ByteReader) (memory.DataType, error) {
	ui, err := binary.ReadUInt(r)
	if err != nil {
		return nil, &binary.DecodingError{ComponentName: "UInt.value", Err: err}
	}
	return NewUInt(ui), nil
}

func (i *UInt) MarshalBinaryTo(w io.Writer) (int, error) {
	sw := binary.NewSilentWriter(w)
	sw.WriteUInt(i.value)
	return sw.Count(), sw.Error()
}

func (i *UInt) Cost() int {
	return 8
}

func (i *UInt) Value() uint64 {
	return i.value
}

func (i *UInt) TypeID() uint8 {
	return UintID
}

// SetValue sets the specified 'value' for this UInt. If the UInt is stored in a MemorySegment container must be
// a pointer to the MemorySegment which contains that UInt. if the UInt is not stored in any MemorySegment the
// container must be nil. Passing wrong value for the container can result in unexpected behaviour.
func (i *UInt) SetValue(value uint64, container *memory.Segment) {
	if container != nil {
		container.NotifyUpdate(&i.value, i.value)
	}
	i.value = value
}

func (i *UInt) String() string {
	return fmt.Sprint(i.value)
}

type ConstByteArray struct {
	values []byte
}

func NewConstByteArray(b []byte, useInput bool) *ConstByteArray {
	if len(b) > MaxArrayLength {
		log.Panicf("%d exceeds max allowed array length: %d", len(b), MaxArrayLength)
	}
	if useInput {
		return &ConstByteArray{values: b}
	}
	temp := make([]byte, len(b))
	copy(temp, b)
	return &ConstByteArray{values: temp}
}

func ReadConstByteArray(r io.ByteReader) (memory.DataType, error) {
	l, err := binary.ReadUInt(r)
	if err != nil {
		return nil, binary.NewSimpleDecodingErr("ByteArray.length", err)
	}
	if l > MaxArrayLength {
		return nil, binary.NewSimpleDecodingErr("ByteArray.length", memory.ErrValueTooBig)
	}
	buf := make([]byte, l)
	for i := 0; i < len(buf); i++ {
		buf[i], err = r.ReadByte()
		if err != nil {
			return nil, binary.NewSimpleDecodingErr("ByteArray.values", err)
		}
	}
	return NewConstByteArray(buf, true), nil
}

func (cba *ConstByteArray) MarshalBinaryTo(w io.Writer) (int, error) {
	sw := binary.NewSilentWriter(w)
	l := len(cba.values)
	sw.WriteUInt(uint64(l))
	sw.SilentWriteBytes(cba.values)
	return sw.Count(), sw.Error()
}

func (cba *ConstByteArray) Cost() int {
	return len(cba.values)
}

func (cba *ConstByteArray) Get(i int) (byte, error) {
	if l := len(cba.values); i < 0 || i >= l {
		return 0, &memory.OutOfBoundsError{Value: i, LowerBound: 0, HigherBound: l - 1}
	}
	return cba.values[i], nil
}

func (cba *ConstByteArray) EqualsToSlice(b []byte) bool {
	return bytes.Equal(cba.values, b)
}

func (cba *ConstByteArray) Equals(other *ConstByteArray) bool {
	return bytes.Equal(cba.values, other.values)
}

func (cba *ConstByteArray) TypeID() uint8 {
	return ConstByteArrayID
}

func (cba *ConstByteArray) String() string {
	return fmt.Sprint(cba.values)
}

type ByteArray struct {
	ConstByteArray
}

func NewByteArray(size int) *ByteArray {
	return &ByteArray{ConstByteArray: *NewConstByteArray(make([]byte, size), true)}
}

func ReadByteArray(r io.ByteReader) (memory.DataType, error) {
	cba, err := ReadConstByteArray(r)
	return &ByteArray{*cba.(*ConstByteArray)}, err
}

func (ba *ByteArray) TypeID() uint8 {
	return ByteArrayID
}

// Set sets the value of the ByteArray at the specified index by 'i' to the value 'b'. If the ByteArray is stored in
// a MemorySegment container must be a pointer to the MemorySegment which contains that ByteArray. if the ByteArray
// is not stored in any MemorySegment the container must be nil. Passing wrong value for the container can
// result in unexpected behaviour.
func (ba *ByteArray) Set(i int, b byte, container *memory.Segment) error {
	if l := len(ba.values); i < 0 || i >= l {
		return &memory.OutOfBoundsError{Value: i, LowerBound: 0, HigherBound: l - 1}
	}
	if container != nil {
		container.NotifyUpdate(&ba.values[i], ba.values[i])
	}
	ba.values[i] = b
	return nil
}
