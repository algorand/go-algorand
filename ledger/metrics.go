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
	"context"
	"database/sql"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/util/metrics"
)

type metricsTracker struct {
	ledgerTransactionsTotal *metrics.Counter
	ledgerRewardClaimsTotal *metrics.Counter
	ledgerRound             *metrics.Gauge
}

func (mt *metricsTracker) loadFromDisk(l ledgerForTracker, _ basics.Round) error {
	mt.ledgerTransactionsTotal = metrics.MakeCounter(metrics.LedgerTransactionsTotal)
	mt.ledgerRewardClaimsTotal = metrics.MakeCounter(metrics.LedgerRewardClaimsTotal)
	mt.ledgerRound = metrics.MakeGauge(metrics.LedgerRound)
	return nil
}

func (mt *metricsTracker) close() {
}

func (mt *metricsTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	rnd := blk.Round()
	mt.ledgerRound.Set(float64(rnd), map[string]string{})
	mt.ledgerTransactionsTotal.Add(float64(len(blk.Payset)), map[string]string{})
	// TODO rewards: need to provide meaningful metric here.
	mt.ledgerRewardClaimsTotal.Add(float64(1), map[string]string{})
}

func (mt *metricsTracker) committedUpTo(committedRnd basics.Round) (retRound, lookback basics.Round) {
	return committedRnd, basics.Round(0)
}

func (mt *metricsTracker) prepareCommit(dcc *deferredCommitContext) error {
	return nil
}

func (mt *metricsTracker) commitRound(context.Context, *sql.Tx, *deferredCommitContext) error {
	return nil
}

func (mt *metricsTracker) postCommit(ctx context.Context, dcc *deferredCommitContext) {
}

func (mt *metricsTracker) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
}

func (mt *metricsTracker) handleUnorderedCommit(uint64, basics.Round, basics.Round) {
}
func (mt *metricsTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}
