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

package logic

import (
	"math"
)

// AVMType represents the types that are representable in the AVM
type AVMType byte

const (
	// AVMNone in an OpSpec shows that the op pops or yields nothing
	AVMNone AVMType = iota

	// AVMAny in an OpSpec shows that the op pops or yield any type
	AVMAny

	// AVMUint64 in an OpSpec shows that the op pops or yields a uint64
	AVMUint64

	// AVMBytes in an OpSpec shows that the op pops or yields a []byte
	AVMBytes
)

func (at AVMType) String() string {
	switch at {
	case AVMNone:
		return "none"
	case AVMAny:
		return "any"
	case AVMUint64:
		return "uint64"
	case AVMBytes:
		return "[]byte"
	}
	return "internal error, unknown type"
}

func (at AVMType) StackType() StackType {
	switch at {
	case AVMNone:
		return StackNone
	case AVMAny:
		return StackAny
	case AVMUint64:
		return StackUint64
	case AVMBytes:
		return StackBytes
	default:
		panic(at)
	}

}

var (
	// TODO: reuse String result for name of base types
	// Base stack types the AVM knows about

	// StackUint64 is any valid uint64
	StackUint64 = NewStackType(AVMUint64, bounded(0, math.MaxUint64))
	// StackBytes is any valid bytestring
	StackBytes = NewStackType(AVMBytes, bounded(0, maxStringSize))
	// StackAny could be Bytes or Uint64
	StackAny = StackType{
		Name:        AVMAny.String(),
		AVMType:     AVMAny,
		ValueBound:  StackUint64.ValueBound,
		LengthBound: StackBytes.LengthBound,
	}
	// StackNone is used when there is no input or output to
	// an opcode
	StackNone = StackType{
		Name:    AVMNone.String(),
		AVMType: AVMNone,
	}

	// Higher level types

	// StackBoolean constrains the int to 1 or 0, representing True or False
	StackBoolean = NewStackType(AVMUint64, bounded(0, 1), "bool")
	// StackHash represents output from a hash function or a field that returns a hash
	StackHash = NewStackType(AVMBytes, static(32), "hash")
	// StackAddress represents a public key or address for an account
	StackAddress = NewStackType(AVMBytes, static(32), "addr")
	// StackBigInt represents a bytestring that should be treated like an int
	StackBigInt = NewStackType(AVMBytes, bounded(0, maxByteMathSize), "bigint")
	// StackMethodSelector represents a bytestring that should be treated like a method selector
	StackMethodSelector = NewStackType(AVMBytes, static(4), "method")

	// AllStackTypes is a list of all the stack types we recognize
	// so that we can iterate over them in doc prep
	AllStackTypes = []StackType{
		StackUint64,
		StackBytes,
		StackAny,
		StackNone,
		StackBoolean,
		StackHash,
		StackAddress,
		StackBigInt,
		StackMethodSelector,
	}
)

// StackType describes the type of a value on the operand stack
type StackType struct {
	Name        string
	AVMType     AVMType
	LengthBound [2]uint64
	ValueBound  [2]uint64
}

// NewStackType Initializes a new StackType with fields passed
func NewStackType(at AVMType, bounds [2]uint64, stname ...string) StackType {
	name := at.String()
	if len(stname) > 0 {
		name = stname[0]
	}

	st := StackType{Name: name, AVMType: at}
	switch at {
	case AVMBytes:
		st.LengthBound = bounds
	case AVMUint64:
		st.ValueBound = bounds
	}
	return st
}

func (st StackType) ConvertableTo(other StackType) bool {
	// what are you doing?
	if st.AVMType == AVMNone || other.AVMType == AVMNone {
		return false
	}

	if st.AVMType == AVMAny || other.AVMType == AVMAny {
		return true
	}

	// By now, both are either uint or bytes
	// and must match
	if st.AVMType != other.AVMType {
		return false
	}

	// Same type now

	// Check if our constraints will be satisfied by
	// the other type
	switch st.AVMType {
	case AVMBytes:
		smin, smax := st.LengthBound[0], st.LengthBound[1]
		omin, omax := other.LengthBound[0], other.LengthBound[1]

		// yes definitely
		// [32,32] => [0..4k]
		// [32,32] => [32,32]

		// yes, maybe determined at runtime
		// [0..4k] => [32,32]

		// no, cant fit
		// [64,64] => [32,32]
		// no, makes no sense
		// [32,32] =>  [64,64]

		// we only have 0-N and [N,N] (static) and only
		// those that are both not static and have different lengths
		// can be assigned
		return !(smin == smax && omin == omax && smin != omin)

	case AVMUint64:
		// No static values at compile
		// time so hard to do any typechecks for assembler,
		// dont use this for AVM runtime
		return true
	default:
		panic("wat")
	}
}

// StackTypes is an alias for a list of StackType with syntactic sugar
type StackTypes []StackType

func (st StackType) String() string {
	return st.Name
}

// Typed tells whether the StackType is a specific concrete type.
func (st StackType) Typed() bool {
	switch st.AVMType {
	case AVMUint64, AVMBytes:
		return true
	}
	return false
}

func bounded(min, max uint64) [2]uint64 {
	return [2]uint64{min, max}
}

func static(size uint64) [2]uint64 {
	return bounded(size, size)
}
