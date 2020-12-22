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
)

type DataType interface {
	fmt.Stringer
	// Cost returns the cost that protocol defines for every teal.DataType. This cost should not be dependant to
	// the specific implementation used.
	Cost() int
}

type UInt struct {
	value uint64
}

func NewUInt(value uint64) *UInt {
	return &UInt{value: value}
}

func (i *UInt) Cost() int {
	return 8
}

func (i *UInt) Value() uint64 {
	return i.value
}

func (i *UInt) SetValue(value uint64, container *MemorySegment) {
	if container != nil {
		container.snapManager.notifyUpdate(&i.value, i.value)
	}
	i.value = value
}

func (i *UInt) String() string {
	return fmt.Sprint(i.value)
}

type ConstByteArray struct {
	values []byte
}

func NewConstByteArray(b []byte) *ConstByteArray {
	temp := make([]byte, len(b))
	copy(temp, b)
	return &ConstByteArray{values: temp}
}

func (cba *ConstByteArray) Cost() int {
	return len(cba.values)
}

func (cba *ConstByteArray) Get(i int) (byte, *OutOfBoundsError) {
	if l := len(cba.values); i < 0 || i >= l {
		return 0, &OutOfBoundsError{Value: i, LowerBound: 0, HigherBound: l - 1}
	}
	return cba.values[i], nil
}

func (cba *ConstByteArray) EqualsToSlice(b []byte) bool {
	return bytes.Equal(cba.values, b)
}

func (cba *ConstByteArray) Equals(other *ConstByteArray) bool {
	return bytes.Equal(cba.values, other.values)
}

func (cba *ConstByteArray) String() string {
	return fmt.Sprint(cba.values)
}

type ByteArray struct {
	ConstByteArray
}

func NewByteArray(size int) *ByteArray {
	return &ByteArray{ConstByteArray: ConstByteArray{values: make([]byte, size)}}
}

func (ba *ByteArray) Set(i int, b byte, container *MemorySegment) *OutOfBoundsError {
	if l := len(ba.values); i < 0 || i >= l {
		return &OutOfBoundsError{Value: i, LowerBound: 0, HigherBound: l - 1}
	}
	if container != nil {
		container.snapManager.notifyUpdate(&ba.values[i], ba.values[i])
	}
	ba.values[i] = b
	return nil
}

// OutOfBoundsError is an error type indicating that some integer value is out of its valid range.
type OutOfBoundsError struct {
	Value       int
	LowerBound  int
	HigherBound int
}

func (orErr *OutOfBoundsError) Error() string {
	return fmt.Sprintf("out of bounds: %d is not between %d and %d", orErr.Value, orErr.LowerBound, orErr.HigherBound)
}
