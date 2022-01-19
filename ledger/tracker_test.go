// Copyright (C) 2019-2022 Algorand, Inc.
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
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestTrackerScheduleCommit checks catchpointTracker.produceCommittingTask does not increase commit offset relative
// to the value set by accountUpdates
func TestTrackerScheduleCommit(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var bufNewLogger bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&bufNewLogger)

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(1, true)}
	ml := makeMockLedgerForTrackerWithLogger(t, true, 10, protocol.ConsensusCurrentVersion, accts, log)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointTracking = 1
	conf.CatchpointInterval = 10

	au := &accountUpdates{}
	ct := &catchpointTracker{}
	au.initialize(conf)
	ct.initialize(conf, ".")

	_, err := trackerDBInitialize(ml, false, ".")
	a.NoError(err)

	ml.trackers.initialize(ml, []ledgerTracker{au, ct}, conf)
	defer ml.trackers.close()
	err = ml.trackers.loadFromDisk(ml)
	a.NoError(err)
	// close commitSyncer goroutine
	ml.trackers.ctxCancel()
	ml.trackers.ctxCancel = nil
	<-ml.trackers.commitSyncerClosed
	ml.trackers.commitSyncerClosed = nil

	// simulate situation when au returns smaller offset b/c of consecutive versions
	// and ct increses it
	// base = 1, offset = 100, lookback = 16
	// lastest = 1000
	// would give a large mostRecentCatchpointRound value => large newBase => larger offset

	expectedOffset := uint64(100)
	blockqRound := basics.Round(1000)
	lookback := basics.Round(16)
	dbRound := basics.Round(1)

	// prepare deltas and versions
	au.accountsMu.Lock()
	au.deltas = make([]ledgercore.AccountDeltas, int(blockqRound))
	au.deltasAccum = make([]int, int(blockqRound))
	au.versions = make([]protocol.ConsensusVersion, int(blockqRound))
	for i := 0; i <= int(expectedOffset); i++ {
		au.versions[i] = protocol.ConsensusCurrentVersion
	}
	for i := int(expectedOffset) + 1; i < len(au.versions); i++ {
		au.versions[i] = protocol.ConsensusFuture
	}
	au.accountsMu.Unlock()

	// ensure au and ct produce data we expect
	dcc := &deferredCommitContext{
		deferredCommitRange: deferredCommitRange{
			lookback: lookback,
		},
	}
	cdr := &dcc.deferredCommitRange

	cdr = au.produceCommittingTask(blockqRound, dbRound, cdr)
	a.NotNil(cdr)
	a.Equal(expectedOffset, cdr.offset)

	cdr = ct.produceCommittingTask(blockqRound, dbRound, cdr)
	a.NotNil(cdr)
	// before the fix
	// expectedOffset = uint64(blockqRound - lookback - dbRound) // 983
	a.Equal(expectedOffset, cdr.offset)

	// schedule the commit. au is expected to return offset 100 and
	ml.trackers.mu.Lock()
	ml.trackers.dbRound = dbRound
	ml.trackers.mu.Unlock()
	ml.trackers.scheduleCommit(blockqRound, lookback)

	a.Equal(1, len(ml.trackers.deferredCommits))
	// before the fix
	// a.Contains(bufNewLogger.String(), "tracker *ledger.catchpointTracker produced offset 983")
	a.NotContains(bufNewLogger.String(), "tracker *ledger.catchpointTracker produced offset")
	dc := <-ml.trackers.deferredCommits
	a.Equal(expectedOffset, dc.offset)
}
