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

type TealType string

type TealValue struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type      TealType `codec:"vtp"`
	Int       uint64   `codec:"vit"`
	ByteSlice []byte   `codec:"vbs"`
}

type StateSchema struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	NumInt       uint64 `codec:"nit"`
	NumByteSlice uint64 `codec:"nbs"`
}

type TealKeyValue map[string]TealValue

func (tk TealKeyValue) Clone() TealKeyValue {
	res := make(TealKeyValue, len(tk))
	for k, v := range tk {
		res[k] = v
	}
	return res
}

const (
	TealByteSliceType TealType = "byt"
	TealIntType       TealType = "int"
)
