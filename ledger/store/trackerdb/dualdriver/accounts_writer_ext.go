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

package dualdriver

import (
	"context"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

type accountsWriterExt struct {
	primary   trackerdb.AccountsWriterExt
	secondary trackerdb.AccountsWriterExt
}

// AccountsPruneOnlineRoundParams implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) AccountsPruneOnlineRoundParams(deleteBeforeRound basics.Round) error {
	errP := aw.primary.AccountsPruneOnlineRoundParams(deleteBeforeRound)
	errS := aw.secondary.AccountsPruneOnlineRoundParams(deleteBeforeRound)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// AccountsPutOnlineRoundParams implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) AccountsPutOnlineRoundParams(onlineRoundParamsData []ledgercore.OnlineRoundParamsData, startRound basics.Round) error {
	errP := aw.primary.AccountsPutOnlineRoundParams(onlineRoundParamsData, startRound)
	errS := aw.secondary.AccountsPutOnlineRoundParams(onlineRoundParamsData, startRound)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// AccountsPutTotals implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) AccountsPutTotals(totals ledgercore.AccountTotals, catchpointStaging bool) error {
	errP := aw.primary.AccountsPutTotals(totals, catchpointStaging)
	errS := aw.secondary.AccountsPutTotals(totals, catchpointStaging)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// AccountsReset implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) AccountsReset(ctx context.Context) error {
	errP := aw.primary.AccountsReset(ctx)
	errS := aw.secondary.AccountsReset(ctx)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// OnlineAccountsDelete implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) OnlineAccountsDelete(forgetBefore basics.Round) (err error) {
	errP := aw.primary.OnlineAccountsDelete(forgetBefore)
	errS := aw.secondary.OnlineAccountsDelete(forgetBefore)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// ResetAccountHashes implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) ResetAccountHashes(ctx context.Context) (err error) {
	errP := aw.primary.ResetAccountHashes(ctx)
	errS := aw.secondary.ResetAccountHashes(ctx)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// TxtailNewRound implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) TxtailNewRound(ctx context.Context, baseRound basics.Round, roundData [][]byte, forgetBeforeRound basics.Round) error {
	errP := aw.primary.TxtailNewRound(ctx, baseRound, roundData, forgetBeforeRound)
	errS := aw.secondary.TxtailNewRound(ctx, baseRound, roundData, forgetBeforeRound)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// UpdateAccountsHashRound implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) UpdateAccountsHashRound(ctx context.Context, hashRound basics.Round) (err error) {
	errP := aw.primary.UpdateAccountsHashRound(ctx, hashRound)
	errS := aw.secondary.UpdateAccountsHashRound(ctx, hashRound)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// UpdateAccountsRound implements trackerdb.AccountsWriterExt
func (aw *accountsWriterExt) UpdateAccountsRound(rnd basics.Round) (err error) {
	errP := aw.primary.UpdateAccountsRound(rnd)
	errS := aw.secondary.UpdateAccountsRound(rnd)
	// coalesce errors
	return coalesceErrors(errP, errS)
}
