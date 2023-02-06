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
	"fmt"
	"math"
	"strings"
)

// avmType represents the types that are representable in the avm
type avmType byte

const (
	// avmNone in an OpSpec shows that the op pops or yields nothing
	avmNone avmType = iota

	// avmAny in an OpSpec shows that the op pops or yield any type
	avmAny

	// avmUint64 in an OpSpec shows that the op pops or yields a uint64
	avmUint64

	// avmBytes in an OpSpec shows that the op pops or yields a []byte
	avmBytes
)

func (at avmType) String() string {
	switch at {
	case avmNone:
		return "none"
	case avmAny:
		return "any"
	case avmUint64:
		return "uint64"
	case avmBytes:
		return "[]byte"
	}
	return "internal error, unknown type"
}

func (at avmType) stackType() StackType {
	switch at {
	case avmNone:
		return StackNone
	case avmAny:
		return StackAny
	case avmUint64:
		return StackUint64
	case avmBytes:
		return StackBytes
	default:
		panic(at)
	}

}

var (
	// TODO: reuse String result for name of base types
	// Base stack types the avm knows about

	// StackUint64 is any valid uint64
	StackUint64 = NewStackType(avmUint64, bound(0, math.MaxUint64))
	// StackBytes is any valid bytestring
	StackBytes = NewStackType(avmBytes, bound(0, maxStringSize))
	// StackAny could be Bytes or Uint64
	StackAny = StackType{
		Name:        avmAny.String(),
		AVMType:     avmAny,
		ValueBound:  StackUint64.ValueBound,
		LengthBound: StackBytes.LengthBound,
	}
	// StackNone is used when there is no input or output to
	// an opcode
	StackNone = StackType{
		Name:    avmNone.String(),
		AVMType: avmNone,
	}

	// Higher level types

	// StackBoolean constrains the int to 1 or 0, representing True or False
	StackBoolean = NewStackType(avmUint64, bound(0, 1), "bool")
	// StackHash represents output from a hash function or a field that returns a hash
	StackHash = NewStackType(avmBytes, static(32), "hash")
	// StackAddress represents a public key or address for an account
	StackAddress = NewStackType(avmBytes, static(32), "addr")
	// StackBigInt represents a bytestring that should be treated like an int
	StackBigInt = NewStackType(avmBytes, bound(0, maxByteMathSize), "bigint")
	// StackMethodSelector represents a bytestring that should be treated like a method selector
	StackMethodSelector = NewStackType(avmBytes, static(4), "method")
	// StackStorageKey represents a bytestring that can be used as a key to some storage (global/local/box)
	StackStorageKey = NewStackType(avmBytes, bound(0, 64), "key")

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
		StackStorageKey,
	}
)

// StackType describes the type of a value on the operand stack
type StackType struct {
	Name        string
	AVMType     avmType
	LengthBound [2]uint64
	ValueBound  [2]uint64
}

// NewStackType Initializes a new StackType with fields passed
func NewStackType(at avmType, bounds [2]uint64, stname ...string) StackType {
	name := at.String()
	if len(stname) > 0 {
		name = stname[0]
	}

	st := StackType{Name: name, AVMType: at}
	switch at {
	case avmBytes:
		st.LengthBound = bounds
	case avmUint64:
		st.ValueBound = bounds
	}
	return st
}

func (st StackType) narrowed(min, max uint64) StackType {
	return NewStackType(st.AVMType, [2]uint64{min, max})
}

// AssignableTo returns a bool indicating whether the receiver can be
// assigned to some other type that is expected by the next operation
func (st StackType) AssignableTo(other StackType) bool {
	// what are you doing?
	if st.AVMType == avmNone || other.AVMType == avmNone {
		return false
	}

	if st.AVMType == avmAny || other.AVMType == avmAny {
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
	case avmBytes:
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

	case avmUint64:
		// No static values at compile
		// time so hard to do any typechecks for assembler,
		// dont use this for avm runtime
		return true
	default:
		panic("wat")
	}
}

// StackTypes is an alias for a list of StackType with syntactic sugar
type StackTypes []StackType

func (st StackTypes) String() string {
	var s = make([]string, len(st))
	for idx, stype := range st {
		s[idx] = stype.String()
	}
	return fmt.Sprintf("(%s)", strings.Join(s, ", "))
}

func (st StackType) String() string {
	return st.Name
}

// Typed tells whether the StackType is a specific concrete type.
func (st StackType) Typed() bool {
	switch st.AVMType {
	case avmUint64, avmBytes:
		return true
	}
	return false
}

func bound(min, max uint64) [2]uint64 {
	return [2]uint64{min, max}
}

func static(size uint64) [2]uint64 {
	return bound(size, size)
}
