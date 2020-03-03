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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

type Action uint64

const (
	FunctionCallAction      Action = 0
	OptInAction             Action = 1
	CloseOutAction          Action = 2
	CreateApplicationAction Action = 3
	DeleteApplicationAction Action = 4
	UpdateApplicationAction Action = 5
)

type ApplicationCallTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ApplicationID uint64             `codec:"apid"`
	Action        Action             `codec:"apan"`
	FunctionArgs  []basics.TealValue `codec:"apfa"`
	Accounts      []basics.Address   `codec:"apat"`

	LocalStateSchema   map[basics.TealType]uint64 `codec:"apls"`
	ApprovalProgram    []byte                     `codec:"apap"`
	StateUpdateProgram []byte                     `codec:"apsu"`

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

func cloneAppLocalStates(m map[basics.AppIndex]basics.TealKeyValue) map[basics.AppIndex]basics.TealKeyValue {
	res := make(map[basics.AppIndex]basics.TealKeyValue, len(m))
	for k, v := range m {
		res[k] = v.Clone()
	}
	return res
}

func cloneAppParams(m map[basics.AppIndex]basics.AppParams) map[basics.AppIndex]basics.AppParams {
	res := make(map[basics.AppIndex]basics.AppParams, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

func (ac ApplicationCallTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData, txnCounter uint64) error {

	switch ac.Action {
	case FunctionCallAction:
	case OptInAction:
	case CloseOutAction:
	case CreateApplicationAction:
		// Creating an application. Fetch the creator's balance record
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}

		// Clone local states + app params, so that the state delta
		// does not refer to the same underlying data structures
		record.AppLocalStates = cloneAppLocalStates(record.AppLocalStates)
		record.AppParams = cloneAppParams(record.AppParams)

		// Allocate the new app params
		newidx := basics.AppIndex(txnCounter + 1)
		record.AppParams[newidx] = basics.AppParams{}

		// Write back to the creator's balance record
		return balances.Put(record)
	case DeleteApplicationAction:
	default:
		return fmt.Errorf("invalid application action")
	}

	return nil
}
