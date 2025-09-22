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

package apply

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// hdrProvider allows fetching old block headers
type hdrProvider interface {
	BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error)
}

// StateProofsApplier allows fetching and updating state-proofs state on the ledger
type StateProofsApplier interface {
	hdrProvider
	GetStateProofNextRound() basics.Round
	SetStateProofNextRound(rnd basics.Round)
	GetStateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error)
	ConsensusParams() config.ConsensusParams
}

// Balances allow to move MicroAlgos from one address to another and to update balance records, or to access and modify individual balance records
// After a call to Put (or Move), future calls to Get or Move will reflect the updated balance record(s)
type Balances interface {
	// Get looks up the account data for an address, ignoring application and asset data
	// If the account is known to be empty, then err should be nil and the returned balance record should have the given address and empty AccountData
	// withPendingRewards specifies whether pending rewards should be applied.
	// A non-nil error means the lookup is impossible (e.g., if the database doesn't have necessary state anymore)
	Get(addr basics.Address, withPendingRewards bool) (ledgercore.AccountData, error)

	Put(basics.Address, ledgercore.AccountData) error

	// CloseAccount is used by payment.go to delete an account, after ensuring no balance, asset or app state remains.
	CloseAccount(basics.Address) error

	// Methods for accessing app and asset data:
	// GetX returns the app or asset data associated with a given address and app/asset index.
	// HasX checks when an account has data associated with a given address and app/asset index.
	// PutX updates or creates app or asset data for an address and app/asset index.
	// DeleteX deletes the app or asset data associated with an address and app/asset index.

	GetAppParams(addr basics.Address, aidx basics.AppIndex) (basics.AppParams, bool, error)
	PutAppParams(addr basics.Address, aidx basics.AppIndex, params basics.AppParams) error
	DeleteAppParams(addr basics.Address, aidx basics.AppIndex) error

	GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (basics.AppLocalState, bool, error)
	HasAppLocalState(addr basics.Address, aidx basics.AppIndex) (bool, error)
	PutAppLocalState(addr basics.Address, aidx basics.AppIndex, state basics.AppLocalState) error
	DeleteAppLocalState(addr basics.Address, aidx basics.AppIndex) error

	SetAppGlobalSchema(addr basics.Address, aidx basics.AppIndex, limits basics.StateSchema) error

	GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (basics.AssetHolding, bool, error)
	PutAssetHolding(addr basics.Address, aidx basics.AssetIndex, data basics.AssetHolding) error
	DeleteAssetHolding(addr basics.Address, aidx basics.AssetIndex) error

	GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (basics.AssetParams, bool, error)
	HasAssetParams(addr basics.Address, aidx basics.AssetIndex) (bool, error)
	PutAssetParams(addr basics.Address, aidx basics.AssetIndex, data basics.AssetParams) error
	DeleteAssetParams(addr basics.Address, aidx basics.AssetIndex) error

	// GetCreator gets the address of the account that created a given creatable
	GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)

	// Allocate or deallocate either global or address-local app storage.
	//
	// Put(...) and then {AllocateApp/DeallocateApp}(..., ..., global=true)
	// creates/destroys an application.
	//
	// Put(...) and then {AllocateApp/DeallocateApp}(..., ..., global=false)
	// opts into/closes out of an application.
	AllocateApp(addr basics.Address, aidx basics.AppIndex, global bool, space basics.StateSchema) error
	DeallocateApp(addr basics.Address, aidx basics.AppIndex, global bool) error

	// Similar to above, notify COW that global/local asset state was created.
	AllocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error
	DeallocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error

	// StatefulEval executes a TEAL program in stateful mode on the balances.
	// It returns whether the program passed and its error.  It also returns
	// an EvalDelta that contains the changes made by the program.
	StatefulEval(gi int, params *logic.EvalParams, aidx basics.AppIndex, program []byte) (passed bool, evalDelta transactions.EvalDelta, err error)

	// Move MicroAlgos from one account to another, doing all necessary overflow checking (convenience method)
	// TODO: Does this need to be part of the balances interface, or can it just be implemented here as a function that calls Put and Get?
	Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error

	// Balances correspond to a Round, which mean that they also correspond
	// to a ConsensusParams.  This returns those parameters.
	ConsensusParams() config.ConsensusParams
}

// Rekey updates tx.Sender's AuthAddr to tx.RekeyTo, if provided
func Rekey(balances Balances, tx *transactions.Transaction) error {
	if (tx.RekeyTo != basics.Address{}) {
		acct, err := balances.Get(tx.Sender, false)
		if err != nil {
			return err
		}
		// Special case: rekeying to the account's actual address just sets acct.AuthAddr to 0
		// This saves 32 bytes in your balance record if you want to go back to using your original key
		if tx.RekeyTo == tx.Sender {
			acct.AuthAddr = basics.Address{}
		} else {
			acct.AuthAddr = tx.RekeyTo
		}

		err = balances.Put(tx.Sender, acct)
		if err != nil {
			return err
		}
	}
	return nil
}
