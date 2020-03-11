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

package basics

type DeltaAction uint64

const (
	SetUInt DeltaAction = iota
	SetBytes
	Delete
)

type ValueDelta struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Action DeltaAction `codec:"at"`
	Bytes  []byte      `codec:"bs,allocbound=-"`
	Uint   uint64      `codec:"ui"`
}

//msgp:allocbound StateDelta -
type StateDelta map[string]ValueDelta

type EvalDelta struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	GlobalDelta StateDelta `codec:"gd,allocbound=-"`

	// TODO(applications) perhaps make these keys be uint64 where 0 == sender
	// and 1..n -> txn.Addresses
	LocalDeltas map[Address]StateDelta `codec:"ld,allocbound=-"`
}

type StateSchema struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	NumUint      uint64 `codec:"nui"`
	NumByteSlice uint64 `codec:"nbs"`
}

type TealType uint64

const (
	TealBytesType TealType = iota
	TealUintType
)

type TealValue struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type TealType `codec:"tt"`

	// TealValue is only used by TEAL programs and never parsed on the wire,
	// so setting an unlimited allocbound on Bytes is OK. We use a string
	// instead of []byte to allow copying this struct by value
	Bytes string `codec:"tb,allocbound=-"`
	Uint  uint64 `codec:"ui"`
}

//msgp:allocbound TealKeyValue 4096
type TealKeyValue map[string]TealValue

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
