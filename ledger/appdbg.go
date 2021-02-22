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

package ledger

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/protocol"
)

// ApplicationDbgLedger is a subset of ledgerForCowBase for external use (dryrun, tealdbg)
type ApplicationDbgLedger interface {
	LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, basics.Round, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
}

type ledgerForCowBaseWrapper struct {
	l ApplicationDbgLedger
}

func (w *ledgerForCowBaseWrapper) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func (w *ledgerForCowBaseWrapper) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, TxLease) error {
	return nil
}

func (w *ledgerForCowBaseWrapper) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, basics.Round, error) {
	return w.l.LookupWithoutRewards(rnd, addr)
}

func (w *ledgerForCowBaseWrapper) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return w.l.GetCreatorForRound(rnd, cidx, ctype)
}

// MakeDebugBalances creates a ledger suitable for dryrun and debugger
func MakeDebugBalances(l ApplicationDbgLedger, round basics.Round, proto protocol.ConsensusVersion, prevTimestamp int64) apply.Balances {
	w := ledgerForCowBaseWrapper{l}

	base := &roundCowBase{
		l:     &w,
		rnd:   round - 1,
		proto: config.Consensus[proto],
	}

	hdr := bookkeeping.BlockHeader{
		Round:        round,
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: proto},
	}
	hint := 2
	cb := makeRoundCowState(base, hdr, prevTimestamp, hint)
	return cb
}
