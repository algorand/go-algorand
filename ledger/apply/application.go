// Copyright (C) 2019-2024 Algorand, Inc.
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

	var ok bool
	params, ok, err = balances.GetAppParams(creator, aidx)
	if err != nil {
		return
	}

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
	var record ledgercore.AccountData
	record, err = balances.Get(creator, false)
	if err != nil {
		return
	}

	// look up how many apps they have
	totalAppParams := record.TotalAppParams

	// Make sure the creator isn't already at the app creation max
	maxAppsCreated := balances.ConsensusParams().MaxAppsCreated
	if maxAppsCreated > 0 && totalAppParams >= uint64(maxAppsCreated) {
		err = fmt.Errorf("cannot create app for %s: max created apps per acct is %d", creator.String(), maxAppsCreated)
		return
	}

	// Allocate the new app params (+ 1 to match Assets Idx namespace)
	appIdx = basics.AppIndex(txnCounter + 1)

	// Sanity check that there isn't an app with this counter value.
	var present bool
	_, present, err = balances.GetAppParams(creator, appIdx)
	if err != nil {
		return
	}
	if present {
		err = fmt.Errorf("already found app with index %d", appIdx)
		return
	}

	params := basics.AppParams{
		ApprovalProgram:   ac.ApprovalProgram,
		ClearStateProgram: ac.ClearStateProgram,
		StateSchemas: basics.StateSchemas{
			LocalStateSchema:  ac.LocalStateSchema,
			GlobalStateSchema: ac.GlobalStateSchema,
		},
		ExtraProgramPages: ac.ExtraProgramPages,
	}

	// Update the cached TotalStateSchema for this account, used
	// when computing MinBalance, since the creator has to store
	// the global state
	totalSchema := record.TotalAppSchema
	totalSchema = totalSchema.AddSchema(ac.GlobalStateSchema)
	record.TotalAppSchema = totalSchema
	record.TotalAppParams = basics.AddSaturate(record.TotalAppParams, 1)

	// Update the cached TotalExtraAppPages for this account, used
	// when computing MinBalance
	totalExtraPages := record.TotalExtraAppPages
	totalExtraPages = basics.AddSaturate(totalExtraPages, ac.ExtraProgramPages)
	record.TotalExtraAppPages = totalExtraPages

	// Write back to the creator's balance record
	err = balances.Put(creator, record)
	if err != nil {
		return 0, err
	}

	// Write new params
	err = balances.PutAppParams(creator, appIdx, params)
	if err != nil {
		return 0, err
	}

	// Allocate global storage
	err = balances.AllocateApp(creator, appIdx, true, ac.GlobalStateSchema)
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

	var params basics.AppParams
	params, _, err = balances.GetAppParams(creator, appIdx)
	if err != nil {
		return err
	}

	// Update the TotalAppSchema used for MinBalance calculation,
	// since the creator no longer has to store the GlobalState
	totalSchema := record.TotalAppSchema
	globalSchema := params.GlobalStateSchema
	totalSchema = totalSchema.SubSchema(globalSchema)
	record.TotalAppSchema = totalSchema
	record.TotalAppParams = basics.SubSaturate(record.TotalAppParams, 1)

	// Delete app's extra program pages
	totalExtraPages := record.TotalExtraAppPages
	if totalExtraPages > 0 {
		proto := balances.ConsensusParams()
		if proto.EnableExtraPagesOnAppUpdate {
			extraPages := params.ExtraProgramPages
			totalExtraPages = basics.SubSaturate(totalExtraPages, extraPages)
		}
		record.TotalExtraAppPages = totalExtraPages
	}

	err = balances.Put(creator, record)
	if err != nil {
		return err
	}

	// Delete the AppParams
	err = balances.DeleteAppParams(creator, appIdx)
	if err != nil {
		return err
	}

	// Deallocate global storage
	err = balances.DeallocateApp(creator, appIdx, true)
	if err != nil {
		return err
	}

	return nil
}

func updateApplication(ac *transactions.ApplicationCallTxnFields, balances Balances, creator basics.Address, appIdx basics.AppIndex) error {
	// Updating the application. Fetch the creator's balance record
	params, _, err := balances.GetAppParams(creator, appIdx)
	if err != nil {
		return err
	}

	// Fill in the new programs
	proto := balances.ConsensusParams()
	// when proto.EnableExtraPageOnAppUpdate is false, WellFormed rejects all updates with a multiple-page program
	if proto.EnableExtraPagesOnAppUpdate {
		lap := len(ac.ApprovalProgram)
		lcs := len(ac.ClearStateProgram)
		pages := int(1 + params.ExtraProgramPages)
		if lap > pages*proto.MaxAppProgramLen {
			return fmt.Errorf("updateApplication approval program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
		}
		if lcs > pages*proto.MaxAppProgramLen {
			return fmt.Errorf("updateApplication clear state program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
		}
		if lap+lcs > pages*proto.MaxAppTotalProgramLen {
			return fmt.Errorf("updateApplication app programs too long, %d. max total len %d bytes", lap+lcs, pages*proto.MaxAppTotalProgramLen)
		}
	}

	params.ApprovalProgram = ac.ApprovalProgram
	params.ClearStateProgram = ac.ClearStateProgram

	return balances.PutAppParams(creator, appIdx, params)
}

func optInApplication(balances Balances, sender basics.Address, appIdx basics.AppIndex, params basics.AppParams) error {
	record, err := balances.Get(sender, false)
	if err != nil {
		return err
	}

	// If the user has already opted in, fail
	// future optimization: find a way to avoid testing this in case record.TotalAppLocalStates == 0.
	ok, err := balances.HasAppLocalState(sender, appIdx)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("account %s has already opted in to app %d", sender.String(), appIdx)
	}

	totalAppLocalState := record.TotalAppLocalStates

	// Make sure the user isn't already at the app opt-in max
	maxAppsOptedIn := balances.ConsensusParams().MaxAppsOptedIn
	if maxAppsOptedIn > 0 && totalAppLocalState >= uint64(maxAppsOptedIn) {
		return fmt.Errorf("cannot opt in app %d for %s: max opted-in apps per acct is %d", appIdx, sender.String(), maxAppsOptedIn)
	}

	// Write an AppLocalState, opting in the user
	localState := basics.AppLocalState{
		Schema: params.LocalStateSchema,
	}

	// Update the TotalAppSchema used for MinBalance calculation,
	// since the sender must now store LocalState
	totalSchema := record.TotalAppSchema
	totalSchema = totalSchema.AddSchema(params.LocalStateSchema)
	record.TotalAppSchema = totalSchema
	record.TotalAppLocalStates = basics.AddSaturate(record.TotalAppLocalStates, 1)

	// Write opted-in user back to cow
	err = balances.Put(sender, record)
	if err != nil {
		return err
	}

	// Write local state back to cow
	err = balances.PutAppLocalState(sender, appIdx, localState)
	if err != nil {
		return err
	}

	// Allocate local storage
	err = balances.AllocateApp(sender, appIdx, false, params.LocalStateSchema)
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

	if record.TotalAppLocalStates == 0 {
		return fmt.Errorf("account %v is not opted in to any app, and in particular %d", sender, appIdx)
	}

	// If they haven't opted in, that's an error
	localState, ok, err := balances.GetAppLocalState(sender, appIdx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("account %s is not opted in to app %d", sender, appIdx)
	}

	// Update the TotalAppSchema used for MinBalance calculation,
	// since the sender no longer has to store LocalState
	totalSchema := record.TotalAppSchema
	totalSchema = totalSchema.SubSchema(localState.Schema)
	record.TotalAppSchema = totalSchema
	record.TotalAppLocalStates = basics.SubSaturate(record.TotalAppLocalStates, 1)

	// Write closed-out user back to cow
	err = balances.Put(sender, record)
	if err != nil {
		return err
	}

	// Delete the local state
	err = balances.DeleteAppLocalState(sender, appIdx)
	if err != nil {
		return err
	}

	// Deallocate local storage
	err = balances.DeallocateApp(sender, appIdx, false)
	if err != nil {
		return err
	}

	return nil
}

func checkPrograms(ac *transactions.ApplicationCallTxnFields, evalParams *logic.EvalParams) error {
	err := logic.CheckContract(ac.ApprovalProgram, evalParams)
	if err != nil {
		return fmt.Errorf("check failed on ApprovalProgram: %v", err)
	}

	err = logic.CheckContract(ac.ClearStateProgram, evalParams)
	if err != nil {
		return fmt.Errorf("check failed on ClearStateProgram: %v", err)
	}

	return nil
}

// ApplicationCall evaluates ApplicationCall transaction
func ApplicationCall(ac transactions.ApplicationCallTxnFields, header transactions.Header, balances Balances, ad *transactions.ApplyData, gi int, evalParams *logic.EvalParams, txnCounter uint64) (err error) {
	defer func() {
		// If we are returning a non-nil error, then don't return a
		// non-empty EvalDelta. Not required for correctness.
		if err != nil && ad != nil {
			ad.EvalDelta = transactions.EvalDelta{}
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
		ad.ApplicationID = appIdx
	}

	// Fetch the application parameters, if they exist
	params, creator, exists, err := getAppParams(balances, appIdx)
	if err != nil {
		return err
	}

	// Ensure that the only operation we can do is ClearState if the application
	// does not exist
	if !exists && ac.OnCompletion != transactions.ClearStateOC {
		return fmt.Errorf("only ClearState is supported for an application (%d) that does not exist", appIdx)
	}

	// If this txn is going to set new programs (either for creation or
	// update), check that the programs are valid and not too expensive
	if ac.ApplicationID == 0 || ac.OnCompletion == transactions.UpdateApplicationOC {
		err = transactions.CheckContractVersions(ac.ApprovalProgram, ac.ClearStateProgram, params, evalParams.Proto)
		if err != nil {
			return err
		}

		err = checkPrograms(&ac, evalParams)
		if err != nil {
			return err
		}
	}

	// Clear out our LocalState. In this case, we don't execute the
	// ApprovalProgram, since clearing out is always allowed. We only
	// execute the ClearStateProgram, whose failures are ignored.
	if ac.OnCompletion == transactions.ClearStateOC {
		// Ensure that the user is already opted in
		ok, hasErr := balances.HasAppLocalState(header.Sender, appIdx)
		if hasErr != nil {
			return hasErr
		}
		if !ok {
			return fmt.Errorf("cannot clear state: %v is not currently opted in to app %d", header.Sender, appIdx)
		}

		// If the app still exists, run the ClearStateProgram
		if exists {
			pass, evalDelta, evalErr := balances.StatefulEval(gi, evalParams, appIdx, params.ClearStateProgram)
			if evalErr != nil {
				// ClearStateProgram evaluation can't make the txn fail.
				if _, ok := evalErr.(logic.EvalError); !ok {
					return evalErr
				}
			}

			// We will have applied any changes if and only if we passed
			if evalErr == nil && pass {
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
	approved, evalDelta, err := balances.StatefulEval(gi, evalParams, appIdx, params.ApprovalProgram)
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
