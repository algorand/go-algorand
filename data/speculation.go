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

package data

import (
	"github.com/algorand/go-algorand/data/basics"
)

// A SpeculationLedger sits in front of a data.Ledger and implements
// the same interface. It absorbs writes using the cow apparatus. The
// underlying ledger is never changed, it is just used to lookup
// things that have not been changed in speculation.
type SpeculationLedger struct {
	ConcreteLedger *Ledger

	// Account
	// Latest() report base round, plus one for each tg processed
	// Lookup() contructs a record from stack of changes, else in original ledger
	// LookupWithoutRewards() contructs a record from stack of changes, else in original ledger
	// GetCreator() look for creatable in stack, but likely in ledger

	// Asset
	// GetCreator() look for creatable in stack, but likely in ledger

	// Transactions
	// Node.Status (for catchpoint)
	// BroadcastSignedTxGroup, ignore signature, put changes into cow stack
}

func (sl *SpeculationLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return sl.ConcreteLedger.GetCreator(cidx, ctype)
}
func (sl *SpeculationLedger) Latest() basics.Round {
	return sl.ConcreteLedger.Latest()
}
func (sl *SpeculationLedger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	return sl.ConcreteLedger.Lookup(rnd, addr)
}
func (sl *SpeculationLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, basics.Round, error) {
	return sl.ConcreteLedger.LookupWithoutRewards(rnd, addr)
}
