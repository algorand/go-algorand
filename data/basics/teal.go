// Copyright (C) 2019-2021 Algorand, Inc.
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

	"github.com/algorand/go-algorand/config"
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
	Bytes  string      `codec:"bs"`
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
//msgp:allocbound StateDelta config.MaxStateDeltaKeys
type StateDelta map[string]ValueDelta

// Equal checks whether two StateDeltas are equal. We don't check for nilness
// equality because an empty map will encode/decode as nil. So if our generated
// map is empty but not nil, we want to equal a decoded nil off the wire.
func (sd StateDelta) Equal(o StateDelta) bool {
	// Lengths should be the same
	if len(sd) != len(o) {
		return false
	}
	// All keys and deltas should be the same
	for k, v := range sd {
		// Other StateDelta must contain key
		ov, ok := o[k]
		if !ok {
			return false
		}

		// Other StateDelta must have same value for key
		if ov != v {
			return false
		}
	}
	return true
}

// Valid checks whether the keys and values in a StateDelta conform to the
// consensus parameters' maximum lengths
func (sd StateDelta) Valid(proto *config.ConsensusParams) error {
	if len(sd) > 0 && proto.MaxAppKeyLen == 0 {
		return fmt.Errorf("delta not empty, but proto.MaxAppKeyLen is 0 (why did we make a delta?)")
	}
	for key, delta := range sd {
		if len(key) > proto.MaxAppKeyLen {
			return fmt.Errorf("key too long: length was %d, maximum is %d", len(key), proto.MaxAppKeyLen)
		}
		switch delta.Action {
		case SetBytesAction:
			if len(delta.Bytes) > proto.MaxAppBytesValueLen {
				return fmt.Errorf("value too long for key 0x%x: length was %d", key, len(delta.Bytes))
			}
			if sum := len(key) + len(delta.Bytes); sum > proto.MaxAppSumKeyValueLens {
				return fmt.Errorf("key/value too long for key 0x%x: sum was %d", key, sum)
			}
		case SetUintAction:
		case DeleteAction:
		default:
			return fmt.Errorf("unknown delta action: %v", delta.Action)
		}
	}
	return nil
}

// EvalDelta stores StateDeltas for an application's global key/value store, as
// well as StateDeltas for some number of accounts holding local state for that
// application
type EvalDelta struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	GlobalDelta StateDelta `codec:"gd"`

	// When decoding EvalDeltas, the integer key represents an offset into
	// [txn.Sender, txn.Accounts[0], txn.Accounts[1], ...]
	LocalDeltas map[uint64]StateDelta `codec:"ld,allocbound=config.MaxEvalDeltaAccounts"`
}

// Equal compares two EvalDeltas and returns whether or not they are
// equivalent. It does not care about nilness equality of LocalDeltas,
// because the msgpack codec will encode/decode an empty map as nil, and we want
// an empty generated EvalDelta to equal an empty one we decode off the wire.
func (ed EvalDelta) Equal(o EvalDelta) bool {
	// LocalDeltas length should be the same
	if len(ed.LocalDeltas) != len(o.LocalDeltas) {
		return false
	}

	// All keys and local StateDeltas should be the same
	for k, v := range ed.LocalDeltas {
		// Other LocalDelta must have value for key
		ov, ok := o.LocalDeltas[k]
		if !ok {
			return false
		}

		// Other LocalDelta must have same value for key
		if !ov.Equal(v) {
			return false
		}
	}

	// GlobalDeltas must be equal
	if !ed.GlobalDelta.Equal(o.GlobalDelta) {
		return false
	}

	return true
}

// StateSchema sets maximums on the number of each type that may be stored
type StateSchema struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	NumUint      uint64 `codec:"nui"`
	NumByteSlice uint64 `codec:"nbs"`
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
func (sm StateSchema) NumEntries() (tot uint64) {
	tot = AddSaturate(tot, sm.NumUint)
	tot = AddSaturate(tot, sm.NumByteSlice)
	return tot
}

// MinBalance computes the MinBalance requirements for a StateSchema based on
// the consensus parameters
func (sm StateSchema) MinBalance(proto *config.ConsensusParams) (res MicroAlgos) {
	// Flat cost for each key/value pair
	flatCost := MulSaturate(proto.SchemaMinBalancePerEntry, sm.NumEntries())

	// Cost for uints
	uintCost := MulSaturate(proto.SchemaUintMinBalance, sm.NumUint)

	// Cost for byte slices
	bytesCost := MulSaturate(proto.SchemaBytesMinBalance, sm.NumByteSlice)

	// Sum the separate costs
	var min uint64
	min = AddSaturate(min, flatCost)
	min = AddSaturate(min, uintCost)
	min = AddSaturate(min, bytesCost)

	res.Raw = min
	return res
}

// TealType is an enum of the types in a TEAL program: Bytes and Uint
type TealType uint64

const (
	// TealBytesType represents the type of a byte slice in a TEAL program
	TealBytesType TealType = 1

	// TealUintType represents the type of a uint in a TEAL program
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
//msgp:allocbound TealKeyValue EncodedMaxKeyValueEntries
type TealKeyValue map[string]TealValue

// Clone returns a copy of a TealKeyValue that may be modified without
// affecting the original
func (tk TealKeyValue) Clone() TealKeyValue {
	if tk == nil {
		return nil
	}
	res := make(TealKeyValue, len(tk))
	for k, v := range tk {
		res[k] = v
	}
	return res
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
