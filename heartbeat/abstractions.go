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

package heartbeat

import (
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// txnBroadcaster is an interface that captures the node's ability to broadcast
// a new transaction.
type txnBroadcaster interface {
	BroadcastInternalSignedTxGroup([]transactions.SignedTxn) error
}

// ledger represents the aspects of the "real" Ledger that the heartbeat service
// needs to interact with
type ledger interface {
	// LastRound tells the round is ready for checking
	LastRound() basics.Round

	// WaitMem allows the Service to wait for the results of a round to be available
	WaitMem(r basics.Round) chan struct{}

	// BlockHdr allows the service access to consensus values
	BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error)

	// LookupAccount allows the Service to observe accounts for suspension
	LookupAccount(round basics.Round, addr basics.Address) (data ledgercore.AccountData, validThrough basics.Round, withoutRewards basics.MicroAlgos, err error)

	LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error)
}

// participants captures the aspects of the AccountManager that are used by this
// package. Service must be able to find out which accounts to monitor and have
// access to their part keys to construct heartbeats.
type participants interface {
	Keys(rnd basics.Round) []account.ParticipationRecordForRound
}
