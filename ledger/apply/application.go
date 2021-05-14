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

package apply

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// Allocate the map of basics.AppParams if it is nil, and return a copy. We do *not*
// call clone on each basics.AppParams -- callers must do that for any values where
// they intend to modify a contained reference type.
func cloneAppParams(m map[basics.AppIndex]basics.AppParams) map[basics.AppIndex]basics.AppParams {
	res := make(map[basics.AppIndex]basics.AppParams, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

// Allocate the map of LocalStates if it is nil, and return a copy. We do *not*
// call clone on each AppLocalState -- callers must do that for any values
// where they intend to modify a contained reference type.
func cloneAppLocalStates(m map[basics.AppIndex]basics.AppLocalState) map[basics.AppIndex]basics.AppLocalState {
	res := make(map[basics.AppIndex]basics.AppLocalState, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

// getAppParams fetches the creator address and basics.AppParams for the app index,
// if they exist. It does *not* clone the basics.AppParams, so the returned params
// must not be modified directly.
func getAppParams(balances Balances, aidx basics.AppIndex) (params basics.AppParams, creator basics.Address, exists bool, err error) {
	creator, exists, err = balances.GetCreator(basics.CreatableIndex(aidx), basics.AppCreatable)
	if err != nil {
		return
	}

	// App doesn't exist. Not an error, but return straight away
	if !exists {
		return
	}

	record, err := balances.Get(creator, false)
	if err != nil {
		return
	}

	params, ok := record.AppParams[aidx]
	if !ok {
		// This should never happen. If app exists then we should have
		// found the creator successfully.
		err = fmt.Errorf("app %d not found in account %s", aidx, creator.String())
		return
	}

	return
}

// createApplication writes a new AppParams entry, allocates global storage,
// and returns the generated application ID
func createApplication(ac *transactions.ApplicationCallTxnFields, balances Balances, creator basics.Address, txnCounter uint64) (appIdx basics.AppIndex, err error) {
	// Fetch the creator's (sender's) balance record
	record, err := balances.Get(creator, false)
	if err != nil {
		return
	}

	// Make sure the creator isn't already at the app creation max
	maxAppsCreated := balances.ConsensusParams().MaxAppsCreated
	if len(record.AppParams) >= maxAppsCreated {
		err = fmt.Errorf("cannot create app for %s: max created apps per acct is %d", creator.String(), maxAppsCreated)
		return
	}

	// Clone app params, so that we have a copy that is safe to modify
	record.AppParams = cloneAppParams(record.AppParams)

	// Allocate the new app params (+ 1 to match Assets Idx namespace)
	appIdx = basics.AppIndex(txnCounter + 1)
	record.AppParams[appIdx] = basics.AppParams{
		ApprovalProgram:   ac.ApprovalProgram,
		ClearStateProgram: ac.ClearStateProgram,
		StateSchemas: basics.StateSchemas{
			LocalStateSchema:  ac.LocalStateSchema,
			GlobalStateSchema: ac.GlobalStateSchema,
		},
	}

	// Update the cached TotalStateSchema for this account, used
	// when computing MinBalance, since the creator has to store
	// the global state
	totalSchema := record.TotalAppSchema
	totalSchema = totalSchema.AddSchema(ac.GlobalStateSchema)
	record.TotalAppSchema = totalSchema

	// Update the cached TotalExtraAppPages for this account, used
	// when computing MinBalance
	totalExtraPages := record.TotalExtraAppPages
	totalExtraPages = totalExtraPages + ac.ExtraProgramPages
	record.TotalExtraAppPages = totalExtraPages

	// Tell the cow what app we created
	created := &basics.CreatableLocator{
		Creator: creator,
		Type:    basics.AppCreatable,
		Index:   basics.CreatableIndex(appIdx),
	}

	// Write back to the creator's balance record
	err = balances.PutWithCreatable(creator, record, created, nil)
	if err != nil {
		return 0, err
	}

	// Allocate global storage
	err = balances.Allocate(creator, appIdx, true, ac.GlobalStateSchema)
	if err != nil {
		return 0, err
	}

	return
}

func deleteApplication(balances Balances, creator basics.Address, appIdx basics.AppIndex) error {
	// Deleting the application. Fetch the creator's balance record
	record, err := balances.Get(creator, false)
	if err != nil {
		return err
	}

	// Update the TotalAppSchema used for MinBalance calculation,
	// since the creator no longer has to store the GlobalState
	totalSchema := record.TotalAppSchema
	globalSchema := record.AppParams[appIdx].GlobalStateSchema
	totalSchema = totalSchema.SubSchema(globalSchema)
	record.TotalAppSchema = totalSchema

	// Delete the AppParams
	record.AppParams = cloneAppParams(record.AppParams)
	delete(record.AppParams, appIdx)

	// Tell the cow what app we deleted
	deleted := &basics.CreatableLocator{
		Creator: creator,
		Type:    basics.AppCreatable,
		Index:   basics.CreatableIndex(appIdx),
	}
	err = balances.PutWithCreatable(creator, record, nil, deleted)
	if err != nil {
		return err
	}

	// Deallocate global storage
	err = balances.Deallocate(creator, appIdx, true)
	if err != nil {
		return err
	}

	return nil
}

func updateApplication(ac *transactions.ApplicationCallTxnFields, balances Balances, creator basics.Address, appIdx basics.AppIndex) error {
	// Updating the application. Fetch the creator's balance record
	record, err := balances.Get(creator, false)
	if err != nil {
		return err
	}

	// Fill in the new programs
	record.AppParams = cloneAppParams(record.AppParams)
	params := record.AppParams[appIdx]
	params.ApprovalProgram = ac.ApprovalProgram
	params.ClearStateProgram = ac.ClearStateProgram

	record.AppParams[appIdx] = params
	return balances.Put(creator, record)
}

func optInApplication(balances Balances, sender basics.Address, appIdx basics.AppIndex, params basics.AppParams) error {
	record, err := balances.Get(sender, false)
	if err != nil {
		return err
	}

	// If the user has already opted in, fail
	_, ok := record.AppLocalStates[appIdx]
	if ok {
		return fmt.Errorf("account %s has already opted in to app %d", sender.String(), appIdx)
	}

	// Make sure the user isn't already at the app opt-in max
	maxAppsOptedIn := balances.ConsensusParams().MaxAppsOptedIn
	if len(record.AppLocalStates) >= maxAppsOptedIn {
		return fmt.Errorf("cannot opt in app %d for %s: max opted-in apps per acct is %d", appIdx, sender.String(), maxAppsOptedIn)
	}

	// Write an AppLocalState, opting in the user
	record.AppLocalStates = cloneAppLocalStates(record.AppLocalStates)
	record.AppLocalStates[appIdx] = basics.AppLocalState{
		Schema: params.LocalStateSchema,
	}

	// Update the TotalAppSchema used for MinBalance calculation,
	// since the sender must now store LocalState
	totalSchema := record.TotalAppSchema
	totalSchema = totalSchema.AddSchema(params.LocalStateSchema)
	record.TotalAppSchema = totalSchema

	// Write opted-in user back to cow
	err = balances.Put(sender, record)
	if err != nil {
		return err
	}

	// Allocate local storage
	err = balances.Allocate(sender, appIdx, false, params.LocalStateSchema)
	if err != nil {
		return err
	}

	return nil
}

func closeOutApplication(balances Balances, sender basics.Address, appIdx basics.AppIndex) error {
	// Closing out of the application. Fetch the sender's balance record
	record, err := balances.Get(sender, false)
	if err != nil {
		return err
	}

	// If they haven't opted in, that's an error
	localState, ok := record.AppLocalStates[appIdx]
	if !ok {
		return fmt.Errorf("account %s is not opted in to app %d", sender, appIdx)
	}

	// Update the TotalAppSchema used for MinBalance calculation,
	// since the sender no longer has to store LocalState
	totalSchema := record.TotalAppSchema
	totalSchema = totalSchema.SubSchema(localState.Schema)
	record.TotalAppSchema = totalSchema

	// Delete the local state
	record.AppLocalStates = cloneAppLocalStates(record.AppLocalStates)
	delete(record.AppLocalStates, appIdx)

	// Write closed-out user back to cow
	err = balances.Put(sender, record)
	if err != nil {
		return err
	}

	// Deallocate local storage
	err = balances.Deallocate(sender, appIdx, false)
	if err != nil {
		return err
	}

	return nil
}

func checkPrograms(ac *transactions.ApplicationCallTxnFields, evalParams *logic.EvalParams, maxCost int) error {
	cost, err := logic.CheckStateful(ac.ApprovalProgram, *evalParams)
	if err != nil {
		return fmt.Errorf("check failed on ApprovalProgram: %v", err)
	}

	if cost > maxCost {
		return fmt.Errorf("ApprovalProgram too resource intensive. Cost is %d, max %d", cost, maxCost)
	}

	cost, err = logic.CheckStateful(ac.ClearStateProgram, *evalParams)
	if err != nil {
		return fmt.Errorf("check failed on ClearStateProgram: %v", err)
	}

	if cost > maxCost {
		return fmt.Errorf("ClearStateProgram too resource intensive. Cost is %d, max %d", cost, maxCost)
	}

	return nil
}

// ApplicationCall evaluates ApplicationCall transaction
func ApplicationCall(ac transactions.ApplicationCallTxnFields, header transactions.Header, balances Balances, ad *transactions.ApplyData, evalParams *logic.EvalParams, txnCounter uint64) (err error) {
	defer func() {
		// If we are returning a non-nil error, then don't return a
		// non-empty EvalDelta. Not required for correctness.
		if err != nil && ad != nil {
			ad.EvalDelta = basics.EvalDelta{}
		}
	}()

	// Ensure we are always passed a non-nil ApplyData
	if ad == nil {
		err = fmt.Errorf("ApplicationCall cannot have nil ApplyData")
		return
	}

	// Ensure we are always passed non-nil EvalParams
	if evalParams == nil {
		err = fmt.Errorf("ApplicationCall cannot have nil EvalParams")
		return
	}

	// Keep track of the application ID we're working on
	appIdx := ac.ApplicationID

	// Specifying an application ID of 0 indicates application creation
	if ac.ApplicationID == 0 {
		appIdx, err = createApplication(&ac, balances, header.Sender, txnCounter)
		if err != nil {
			return
		}
	}

	// Fetch the application parameters, if they exist
	params, creator, exists, err := getAppParams(balances, appIdx)
	if err != nil {
		return err
	}

	// Ensure that the only operation we can do is ClearState if the application
	// does not exist
	if !exists && ac.OnCompletion != transactions.ClearStateOC {
		return fmt.Errorf("only clearing out is supported for applications that do not exist")
	}

	// If this txn is going to set new programs (either for creation or
	// update), check that the programs are valid and not too expensive
	if ac.ApplicationID == 0 || ac.OnCompletion == transactions.UpdateApplicationOC {
		maxCost := balances.ConsensusParams().MaxAppProgramCost
		err = checkPrograms(&ac, evalParams, maxCost)
		if err != nil {
			return err
		}
	}

	// Clear out our LocalState. In this case, we don't execute the
	// ApprovalProgram, since clearing out is always allowed. We only
	// execute the ClearStateProgram, whose failures are ignored.
	if ac.OnCompletion == transactions.ClearStateOC {
		// Ensure that the user is already opted in
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}
		_, ok := record.AppLocalStates[appIdx]
		if !ok {
			return fmt.Errorf("cannot clear state: %v is not currently opted in to app %d", header.Sender, appIdx)
		}

		// If the app still exists, run the ClearStateProgram
		if exists {
			pass, evalDelta, err := balances.StatefulEval(*evalParams, appIdx, params.ClearStateProgram)
			if err != nil {
				// Fail on non-logic eval errors and ignore LogicEvalError errors
				if _, ok := err.(ledgercore.LogicEvalError); !ok {
					return err
				}
			}

			// We will have applied any changes if and only if we passed
			if err == nil && pass {
				// Fill in applyData, so that consumers don't have to implement a
				// stateful TEAL interpreter to apply state changes
				ad.EvalDelta = evalDelta
			} else {
				// Ignore logic eval errors and rejections from the ClearStateProgram
			}
		}

		return closeOutApplication(balances, header.Sender, appIdx)
	}

	// If this is an OptIn transaction, ensure that the sender has
	// LocalState allocated prior to TEAL execution, so that it may be
	// initialized in the same transaction.
	if ac.OnCompletion == transactions.OptInOC {
		err = optInApplication(balances, header.Sender, appIdx, params)
		if err != nil {
			return err
		}
	}

	// Execute the Approval program
	approved, evalDelta, err := balances.StatefulEval(*evalParams, appIdx, params.ApprovalProgram)
	if err != nil {
		return err
	}

	if !approved {
		return fmt.Errorf("transaction rejected by ApprovalProgram")
	}

	switch ac.OnCompletion {
	case transactions.NoOpOC:
		// Nothing to do

	case transactions.OptInOC:
		// Handled above

	case transactions.CloseOutOC:
		err = closeOutApplication(balances, header.Sender, appIdx)
		if err != nil {
			return err
		}

	case transactions.DeleteApplicationOC:
		err = deleteApplication(balances, creator, appIdx)
		if err != nil {
			return err
		}

	case transactions.UpdateApplicationOC:
		err = updateApplication(&ac, balances, creator, appIdx)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid application action")
	}

	// Fill in applyData, so that consumers don't have to implement a
	// stateful TEAL interpreter to apply state changes
	ad.EvalDelta = evalDelta

	return nil
}
