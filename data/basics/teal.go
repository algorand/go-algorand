// Copyright (C) 2019-2025 Algorand, Inc.
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

package basics

import (
	"encoding/hex"
	"fmt"
	"maps"
)

// DeltaAction is an enum of actions that may be performed when applying a
// delta to a TEAL key/value store
type DeltaAction uint64

const (
	// SetBytesAction indicates that a TEAL byte slice should be stored at a key
	SetBytesAction DeltaAction = 1

	// SetUintAction indicates that a Uint should be stored at a key
	SetUintAction DeltaAction = 2

	// DeleteAction indicates that the value for a particular key should be deleted
	DeleteAction DeltaAction = 3
)

// ValueDelta links a DeltaAction with a value to be set
type ValueDelta struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Action DeltaAction `codec:"at"`
	Bytes  string      `codec:"bs,allocbound=bounds.MaxAppBytesValueLen"`
	Uint   uint64      `codec:"ui"`
}

// ToTealValue converts a ValueDelta into a TealValue if possible, and returns
// ok = false if the conversion is not possible.
func (vd *ValueDelta) ToTealValue() (value TealValue, ok bool) {
	switch vd.Action {
	case SetBytesAction:
		value.Type = TealBytesType
		value.Bytes = vd.Bytes
		ok = true
	case SetUintAction:
		value.Type = TealUintType
		value.Uint = vd.Uint
		ok = true
	case DeleteAction:
		ok = false
	default:
		ok = false
	}
	return value, ok
}

// StateDelta is a map from key/value store keys to ValueDeltas, indicating
// what should happen for that key
//
//msgp:allocbound StateDelta bounds.MaxStateDeltaKeys,bounds.MaxAppBytesKeyLen
type StateDelta map[string]ValueDelta

// Equal checks whether two StateDeltas are equal. We don't check for nilness
// equality because an empty map will encode/decode as nil. So if our generated
// map is empty but not nil, we want to equal a decoded nil off the wire.
func (sd StateDelta) Equal(o StateDelta) bool {
	return maps.Equal(sd, o)
}

// StateSchema sets maximums on the number of each type that may be stored
type StateSchema struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	NumUint      uint64 `codec:"nui"`
	NumByteSlice uint64 `codec:"nbs"`
}

// String returns a string representation of a StateSchema
func (sm StateSchema) String() string {
	return fmt.Sprintf("{NumUint:%d NumByteSlice:%d}", sm.NumUint, sm.NumByteSlice)
}

// Empty returns true if the StateSchema has no entries
func (sm StateSchema) Empty() bool {
	return sm.NumUint == 0 && sm.NumByteSlice == 0
}

// AddSchema adds two StateSchemas together
func (sm StateSchema) AddSchema(osm StateSchema) (out StateSchema) {
	out.NumUint = AddSaturate(sm.NumUint, osm.NumUint)
	out.NumByteSlice = AddSaturate(sm.NumByteSlice, osm.NumByteSlice)
	return
}

// SubSchema subtracts one StateSchema from another
func (sm StateSchema) SubSchema(osm StateSchema) (out StateSchema) {
	out.NumUint = SubSaturate(sm.NumUint, osm.NumUint)
	out.NumByteSlice = SubSaturate(sm.NumByteSlice, osm.NumByteSlice)
	return
}

// NumEntries counts the total number of values that may be stored for particular schema
func (sm StateSchema) NumEntries() uint64 {
	return AddSaturate(sm.NumUint, sm.NumByteSlice)
}

// Allows determines if `other` "fits" within this schema.
func (sm StateSchema) Allows(other StateSchema) bool {
	return other.NumUint <= sm.NumUint && other.NumByteSlice <= sm.NumByteSlice
}

// MinBalance computes the MinBalance requirements for a StateSchema based on
// the requirements for the state values in the schema.
func (sm StateSchema) MinBalance(reqs BalanceRequirements) MicroAlgos {
	// Flat cost for each key/value pair
	flatCost := MulSaturate(reqs.SchemaMinBalancePerEntry, sm.NumEntries())

	// Cost for uints
	uintCost := MulSaturate(reqs.SchemaUintMinBalance, sm.NumUint)

	// Cost for byte slices
	bytesCost := MulSaturate(reqs.SchemaBytesMinBalance, sm.NumByteSlice)

	// Sum the separate costs
	min := AddSaturate(flatCost, uintCost)
	min = AddSaturate(min, bytesCost)

	return MicroAlgos{Raw: min}
}

// TealType is an enum of the types in a TEAL program: Bytes and Uint
type TealType uint64

const (
	// TealBytesType represents the type of byte slice in a TEAL program
	TealBytesType TealType = 1

	// TealUintType represents the type of uint in a TEAL program
	TealUintType TealType = 2
)

func (tt TealType) String() string {
	switch tt {
	case TealBytesType:
		return "b"
	case TealUintType:
		return "u"
	}
	return "?"
}

// TealValue contains type information and a value, representing a value in a
// TEAL program
type TealValue struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type  TealType `codec:"tt"`
	Bytes string   `codec:"tb"`
	Uint  uint64   `codec:"ui"`
}

// ToValueDelta creates ValueDelta from TealValue
func (tv *TealValue) ToValueDelta() (vd ValueDelta) {
	if tv.Type == TealUintType {
		vd.Action = SetUintAction
		vd.Uint = tv.Uint
	} else {
		vd.Action = SetBytesAction
		vd.Bytes = tv.Bytes
	}
	return
}

func (tv *TealValue) String() string {
	if tv.Type == TealBytesType {
		return hex.EncodeToString([]byte(tv.Bytes))
	}
	return fmt.Sprintf("%d", tv.Uint)
}

// TealKeyValue represents a key/value store for use in an application's
// LocalState or GlobalState
//
//msgp:allocbound TealKeyValue bounds.EncodedMaxKeyValueEntries,bounds.MaxAppBytesKeyLen
type TealKeyValue map[string]TealValue

// Clone returns a copy of a TealKeyValue that may be modified without
// affecting the original
func (tk TealKeyValue) Clone() TealKeyValue {
	return maps.Clone(tk)
}

// ToStateSchema calculates the number of each value type in a TealKeyValue and
// represents the result as a StateSchema
func (tk TealKeyValue) ToStateSchema() (schema StateSchema, err error) {
	for _, value := range tk {
		switch value.Type {
		case TealBytesType:
			schema.NumByteSlice++
		case TealUintType:
			schema.NumUint++
		default:
			err = fmt.Errorf("unknown type %v", value.Type)
			return StateSchema{}, err
		}
	}
	return schema, nil
}
