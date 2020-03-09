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

type OnCompletion uint64

const (
	NoOpOC              OnCompletion = 0
	OptInOC             OnCompletion = 1
	CloseOutOC          OnCompletion = 2
	ClearStateOC        OnCompletion = 3
	UpdateApplicationOC OnCompletion = 4
	DeleteApplicationOC OnCompletion = 5
)

type ApplicationCallTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ApplicationID   basics.AppIndex    `codec:"apid"`
	OnCompletion    OnCompletion       `codec:"apan"`
	ApplicationArgs []basics.TealValue `codec:"apaa,allocbound=1024"`
	Accounts        []basics.Address   `codec:"apat,allocbound=1024"`

	LocalStateSchema  basics.StateSchema `codec:"apls"`
	GlobalStateSchema basics.StateSchema `codec:"apgs"`
	ApprovalProgram   string             `codec:"apap,allocbound=4096"`
	ClearStateProgram string             `codec:"apsu,allocbound=4096"`

	// If you add any fields here, remember you MUST modify the Empty
	// method below!
}

func (ac ApplicationCallTxnFields) Empty() bool {
	if ac.ApplicationID != 0 {
		return false
	}
	if ac.OnCompletion != 0 {
		return false
	}
	if ac.ApplicationArgs != nil {
		return false
	}
	if ac.Accounts != nil {
		return false
	}
	if ac.LocalStateSchema != (basics.StateSchema{}) {
		return false
	}
	if ac.GlobalStateSchema != (basics.StateSchema{}) {
		return false
	}
	if ac.ApprovalProgram != "" {
		return false
	}
	if ac.ClearStateProgram != "" {
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
		// res[k].GlobalState = res[k].GlobalState.Clone()
	}
	return res
}

func getAppParams(balances Balances, aidx basics.AppIndex) (params basics.AppParams, creator basics.Address, doesNotExist bool, err error) {
	creator, doesNotExist, err = balances.GetAppCreator(aidx)
	if err != nil {
		return
	}

	// App doesn't exist. Not an error, but return straight away
	if doesNotExist {
		return
	}

	creatorRecord, err := balances.Get(creator, false)
	if err != nil {
		return
	}

	params, ok := creatorRecord.AppParams[aidx]
	if !ok {
		// This should never happen! If app exists then we should have
		// found the creator successfully.
		// TODO(applications) panic here?
		err = fmt.Errorf("app %d not found in account %s", aidx, creator.String())
		return
	}

	return
}

func (ac ApplicationCallTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData, txnCounter uint64) error {
	// Keep track of the application ID we're working on
	appIdx := ac.ApplicationID

	// If we're creating an application, allocate its AppParams
	if ac.ApplicationID == 0 {
		// Creating an application. Fetch the creator's balance record
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}

		// Clone local states + app params, so that we have a copy that is
		// safe to modify
		record.AppLocalStates = cloneAppLocalStates(record.AppLocalStates)
		record.AppParams = cloneAppParams(record.AppParams)

		// Allocate the new app params
		appIdx = basics.AppIndex(txnCounter + 1)
		record.AppParams[appIdx] = basics.AppParams{
			// TODO(applications) fill in this struct
		}

		// Write back to the creator's balance record and continue
		err = balances.Put(record)
		if err != nil {
			return err
		}
	}

	// Fetch the application parameters, if they exist
	_, creator, doesNotExist, err := getAppParams(balances, appIdx)
	if err != nil {
		return err
	}

	// Clear out our LocalState. In this case, we don't execute the
	// ApprovalProgram, since clearing out is always allowed. We only
	// execute the ClearStateProgram, whose failures are ignored.
	if ac.OnCompletion == ClearStateOC {
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}

		// Ensure sender actually has LocalState allocated for this app.
		// Can't close out not currently opted in
		_, ok := record.AppLocalStates[appIdx]
		if !ok {
			return fmt.Errorf("cannot close out for app %d, not currently opted in")
		}

		// Execute the StateUpdate program, before we've deleted the LocalState
		// for this account

		// TODO(applications)
		/*
			err = eval(ClearStateProgram, &ctxWithAD)
			if err != nil {
				return err
			}
		*/

		// Deallocate the AppLocalState and finish
		record.AppLocalStates = cloneAppLocalStates(record.AppLocalStates)
		delete(record.AppLocalStates, appIdx)
		return balances.Put(record)
	}

	// Past this point, the AppParams must exist. NoOp, OptIn, OptOut,
	// Delete, and Update
	if doesNotExist {
		return fmt.Errorf("only closing out is supported for applications that do not exist")
	}

	// Execute the Approval program

	/*
		// TODO(applications)
		err, approved = eval(ApprovalProgram, &ctxWithAD)
		if err != nil {
			return err
		}

		if !approved {
			return fmt.Errorf("ApplicationCall txn rejected by logic")
		}

		// Ignore failures of the ClearStateProgram
		_ = eval(ClearStateProgram, &ctxWithAD)
	*/

	switch ac.OnCompletion {
	case NoOpOC:

	case OptInOC:
		// Opting into the application. Fetch the sender's balance record
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}

		// If they've already opted in, that's an error
		_, ok := record.AppLocalStates[appIdx]
		if ok {
			return fmt.Errorf("account has already opted in to app %d", appIdx)
		}

		// Allocate local state
		record.AppLocalStates = cloneAppLocalStates(record.AppLocalStates)
		record.AppLocalStates[appIdx] = basics.TealKeyValue{}
		err = balances.Put(record)
		if err != nil {
			return err
		}

	case CloseOutOC:
		// Closing out of the application. Fetch the sender's balance record
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}

		// If they haven't opted in, that's an error
		_, ok := record.AppLocalStates[appIdx]
		if !ok {
			return fmt.Errorf("account is not opted in to app %d", appIdx)
		}

		// Delete the local state
		record.AppLocalStates = cloneAppLocalStates(record.AppLocalStates)
		delete(record.AppLocalStates, appIdx)
		err = balances.Put(record)
		if err != nil {
			return err
		}

	case DeleteApplicationOC:
		// Deleting the application. Fetch the creator's balance record
		record, err := balances.Get(creator, false)
		if err != nil {
			return err
		}

		// Delete the AppParams
		record.AppParams = cloneAppParams(record.AppParams)
		delete(record.AppParams, appIdx)
		err = balances.Put(record)
		if err != nil {
			return err
		}

	case UpdateApplicationOC:
		// Ensure user isn't trying to update the local or global state
		// schemas, because that operation is not allowed
		if ac.LocalStateSchema != (basics.StateSchema{}) ||
			ac.GlobalStateSchema != (basics.StateSchema{}) {
			return fmt.Errorf("local and global state schemas are immutable")
		}

		// Updating the application. Fetch the creator's balance record
		record, err := balances.Get(creator, false)
		if err != nil {
			return err
		}

		record.AppParams = cloneAppParams(record.AppParams)

		// Fill in the updated programs
		params := record.AppParams[appIdx]

		params.ApprovalProgram = ac.ApprovalProgram
		params.ClearStateProgram = ac.ClearStateProgram

		record.AppParams[appIdx] = params
		err = balances.Put(record)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid application action")
	}

	return nil
}
