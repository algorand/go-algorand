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
	setSnapshotManager(*snapshotManager)
	String() string
}

type UInt struct {
	manager *snapshotManager
	value   uint64
}

func NewUInt(value uint64) *UInt {
	return &UInt{value: value}
}

func (i *UInt) setSnapshotManager(sm *snapshotManager) {
	i.manager = sm
}

func (i *UInt) Value() uint64 {
	return i.value
}

func (i *UInt) SetValue(value uint64) {
	if i.manager != nil {
		i.manager.notifyUpdate(&i.value, i.value)
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
	copy(b, temp)
	return &ConstByteArray{values: temp}
}

func (cba *ConstByteArray) setSnapshotManager(*snapshotManager) {
	//do nothing!
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
	manager *snapshotManager
}

func NewByteArray(size int) *ByteArray {
	return &ByteArray{ConstByteArray: ConstByteArray{values: make([]byte, size)}}
}

func (ba *ByteArray) setSnapshotManager(sm *snapshotManager) {
	ba.manager = sm
}

func (ba *ByteArray) Set(i int, b byte) *OutOfBoundsError {
	if l := len(ba.values); i < 0 || i >= l {
		return &OutOfBoundsError{Value: i, LowerBound: 0, HigherBound: l - 1}
	}
	if ba.manager != nil {
		ba.manager.notifyUpdate(&ba.values[i], ba.values[i])
	}
	ba.values[i] = b
	return nil
}

//OutOfBoundsError is an error type indicating that some integer value is out of its valid range.
type OutOfBoundsError struct {
	Value       int
	LowerBound  int
	HigherBound int
}

func (orErr *OutOfBoundsError) Error() string {
	return fmt.Sprintf("out of bounds: %d is not between %d and %d", orErr.Value, orErr.LowerBound, orErr.HigherBound)
}
