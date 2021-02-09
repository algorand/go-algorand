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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

// Balances allow to move MicroAlgos from one address to another and to update balance records, or to access and modify individual balance records
// After a call to Put (or Move), future calls to Get or Move will reflect the updated balance record(s)
type Balances interface {
	// Get looks up the account data for an address, ignoring application state
	// If the account is known to be empty, then err should be nil and the returned balance record should have the given address and empty AccountData
	// withPendingRewards specifies whether pending rewards should be applied.
	// A non-nil error means the lookup is impossible (e.g., if the database doesn't have necessary state anymore)
	Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error)

	// GetWithHolding is like Get, but also loads specific creatable
	GetWithHolding(addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.AccountData, error)

	Put(basics.Address, basics.AccountData) error

	// PutWithCreatable is like Put, but should be used when creating or deleting an asset or application.
	PutWithCreatable(addr basics.Address, acct basics.AccountData, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) error

	// GetCreator gets the address of the account that created a given creatable
	GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)

	// Allocate or Deallocate either global or address-local app storage.
	//
	// PutWithCreatable(...) and then {Allocate/Deallocate}(..., ..., global=true)
	// creates/destroys an application.
	//
	// Put(...) and then {Allocate/Deallocate}(..., ..., global=false)
	// opts into/closes out of an application.
	Allocate(addr basics.Address, aidx basics.AppIndex, global bool, space basics.StateSchema) error
	Deallocate(addr basics.Address, aidx basics.AppIndex, global bool) error

	// StatefulEval executes a TEAL program in stateful mode on the balances.
	// It returns whether the program passed and its error.  It alo returns
	// an EvalDelta that contains the changes made by the program.
	StatefulEval(params logic.EvalParams, aidx basics.AppIndex, program []byte) (passed bool, evalDelta basics.EvalDelta, err error)

	// Move MicroAlgos from one account to another, doing all necessary overflow checking (convenience method)
	// TODO: Does this need to be part of the balances interface, or can it just be implemented here as a function that calls Put and Get?
	Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error

	// Balances correspond to a Round, which mean that they also correspond
	// to a ConsensusParams.  This returns those parameters.
	ConsensusParams() config.ConsensusParams
}
