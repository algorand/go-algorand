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

package transactions

import (
	"github.com/algorand/go-algorand/data/basics"
)

type Action uint64

type TealValue struct {
	Int       uint64
	ByteSlice []byte
}

type TealType string

const (
	TealByteSliceType TealType = "byt"
	TealIntType TealType = "int"
)

const (
	FunctionCallAction      Action = 0
	OptInAction             Action = 1
	CloseOutAction          Action = 2
	CreateApplicationAction Action = 3
	DeleteApplicationAction Action = 4
)

type ApplicationCallTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ApplicationID uint64           `codec:"apid"`
	Action        Action           `codec:"apan"`
	FunctionArgs  []TealValue      `codec:"apfa"`
	Accounts      []basics.Address `codec:"apat"`

	LocalStateSchema   map[TealType]uint64 `codec:"apls"`
	ApprovalProgram    []byte              `codec:"apap"`
	StateUpdateProgram []byte              `codec:"apsu"`

	// If you add any fields here, remember you MUST modify the Empty
	// method below!
}

func (ac ApplicationCallTxnFields) Empty() bool {
	if ac.ApplicationID != 0 {
		return false
	}
	if ac.Action != 0 {
		return false
	}
	if ac.FunctionArgs != nil {
		return false
	}
	if ac.Accounts != nil {
		return false
	}
	if ac.LocalStateSchema != nil {
		return false
	}
	if ac.ApprovalProgram != nil {
		return false
	}
	if ac.StateUpdateProgram != nil {
		return false
	}
	return true
}

func (ac ApplicationCallTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	return nil
}
