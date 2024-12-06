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

package ledger

import (
	"context"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/util/metrics"
)

type metricsTracker struct {
	ledgerTransactionsTotal *metrics.Counter
	ledgerRewardClaimsTotal *metrics.Counter
	ledgerRound             *metrics.Gauge
	ledgerDBRound           *metrics.Gauge
}

func (mt *metricsTracker) loadFromDisk(l ledgerForTracker, _ basics.Round) error {
	mt.ledgerTransactionsTotal = metrics.MakeCounter(metrics.LedgerTransactionsTotal)
	mt.ledgerRewardClaimsTotal = metrics.MakeCounter(metrics.LedgerRewardClaimsTotal)
	mt.ledgerRound = metrics.MakeGauge(metrics.LedgerRound)
	mt.ledgerDBRound = metrics.MakeGauge(metrics.LedgerDBRound)
	return nil
}

func (mt *metricsTracker) close() {
	if mt.ledgerTransactionsTotal != nil {
		mt.ledgerTransactionsTotal.Deregister(nil)
		mt.ledgerTransactionsTotal = nil
	}
	if mt.ledgerRewardClaimsTotal != nil {
		mt.ledgerRewardClaimsTotal.Deregister(nil)
		mt.ledgerRewardClaimsTotal = nil
	}
	if mt.ledgerRound != nil {
		mt.ledgerRound.Deregister(nil)
		mt.ledgerRound = nil
	}
	if mt.ledgerDBRound != nil {
		mt.ledgerDBRound.Deregister(nil)
		mt.ledgerDBRound = nil
	}
}

func (mt *metricsTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	rnd := blk.Round()
	mt.ledgerRound.Set(uint64(rnd))
	mt.ledgerTransactionsTotal.AddUint64(uint64(len(blk.Payset)), nil)
	// TODO rewards: need to provide meaningful metric here.
	mt.ledgerRewardClaimsTotal.Inc(nil)
}

func (mt *metricsTracker) committedUpTo(committedRnd basics.Round) (retRound, lookback basics.Round) {
	return committedRnd, basics.Round(0)
}

func (mt *metricsTracker) prepareCommit(dcc *deferredCommitContext) error {
	return nil
}

func (mt *metricsTracker) commitRound(context.Context, trackerdb.TransactionScope, *deferredCommitContext) error {
	return nil
}

func (mt *metricsTracker) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	mt.ledgerDBRound.Set(uint64(dcc.newBase()))
}

func (mt *metricsTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}
