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
)

// Balances allow to move MicroAlgos from one address to another and to update balance records, or to access and modify individual balance records
// After a call to Put (or Move), future calls to Get or Move will reflect the updated balance record(s)
type Balances interface {
	// Get looks up the balance record for an address
	// If the account is known to be empty, then err should be nil and the returned balance record should have the given address and empty AccountData
	// withPendingRewards specifies whether pending rewards should be applied.
	// A non-nil error means the lookup is impossible (e.g., if the database doesn't have necessary state anymore)
	Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error)

	Put(basics.BalanceRecord) error

	// PutWithCreatable is like Put, but should be used when creating or deleting an asset or application.
	PutWithCreatable(record basics.BalanceRecord, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) error

	// GetCreator gets the address of the account that created a given creatable
	GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)

	// Move MicroAlgos from one account to another, doing all necessary overflow checking (convenience method)
	// TODO: Does this need to be part of the balances interface, or can it just be implemented here as a function that calls Put and Get?
	Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error

	// Balances correspond to a Round, which mean that they also correspond
	// to a ConsensusParams.  This returns those parameters.
	ConsensusParams() config.ConsensusParams
}

// StateEvaluator is an interface that provides some Stateful TEAL
// functionality that may be passed through to Apply from ledger. It was
// originally created to avoid a circular dependency between the logic and
// transactions packages (when the apply methods were in the transactions
// package).
type StateEvaluator interface {
	Eval(program []byte) (pass bool, stateDelta basics.EvalDelta, err error)
	Check(program []byte) (cost int, err error)
	InitLedger(balances Balances, appIdx basics.AppIndex, schemas basics.StateSchemas) error
}
