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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

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

var (
	params = config.Consensus[protocol.ConsensusCurrentVersion]

	StackUint64 = NewStackType("uint64", AVMUint64, bounded(0, math.MaxUint64))
	StackBytes  = NewStackType("[]byte", AVMBytes, bounded(0, maxStringSize))
	StackAny    = StackType{
		Name:        "any",
		AVMType:     AVMAny,
		ValueBound:  StackUint64.ValueBound,
		LengthBound: StackBytes.LengthBound,
	}
	StackNone = StackType{
		Name:        "none",
		AVMType:     AVMNone,
		ValueBound:  []uint64{0, 0},
		LengthBound: []uint64{0, 0},
	}

	// Some higher level types that are common
	StackBoolean = NewStackType("bool", AVMUint64, bounded(0, 1))
	StackHash    = NewStackType("hash", AVMBytes, static(32))
	StackAddress = NewStackType("addr", AVMBytes, static(32))
	StackBigInt  = NewStackType("bigint", AVMBytes, bounded(0, maxByteMathSize))

	// These don't need to be here but makes them easier to see how it
	// might work while reviewing
	// AppArgsNumBound    = boundUint(0, uint64(params.MaxAppArgs))
	// AppArgBound        = boundBytes(0, uint64(params.MaxAppTotalArgLen))
	// AssetURLBound      = boundBytes(0, uint64(params.MaxAssetURLBytes))
	// AssetNameBound     = boundBytes(0, uint64(params.MaxAssetNameBytes))
	// AssetUnitNameBound = boundBytes(0, uint64(params.MaxAssetUnitNameBytes))
	// NoteFieldBound     = boundBytes(0, uint64(params.MaxTxnNoteBytes))
	// ...
)

// StackType describes the type of a value on the operand stack
type StackType struct {
	Name        string
	AVMType     AVMType
	LengthBound []uint64
	ValueBound  []uint64
}

// Initializes a new StackType with fields passed
func NewStackType(name string, at AVMType, bounds []uint64) StackType {
	st := StackType{Name: name, AVMType: at}
	switch at {
	case AVMBytes:
		st.LengthBound = bounds
	case AVMUint64:
		st.ValueBound = bounds
	}
	return st
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

func bounded(min, max uint64) []uint64 {
	return []uint64{min, max}
}

func static(size uint64) []uint64 {
	return bounded(size, size)
}
