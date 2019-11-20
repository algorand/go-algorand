// Copyright (C) 2019 Algorand, Inc.
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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type mockLedgerForTracker struct {
	dbs    dbPair
	blocks []blockEntry
}

func makeMockLedgerForTracker(t *testing.T) *mockLedgerForTracker {
	dbs := dbOpenTest(t)
	return &mockLedgerForTracker{dbs: dbs}
}

func (ml *mockLedgerForTracker) close() {
	ml.dbs.close()
}

func (ml *mockLedgerForTracker) Latest() basics.Round {
	return basics.Round(len(ml.blocks)) - 1
}

func (ml *mockLedgerForTracker) trackerEvalVerified(blk bookkeeping.Block, aux evalAux) (StateDelta, error) {
	delta := StateDelta{
		hdr: &bookkeeping.BlockHeader{},
	}
	return delta, nil
}

func (ml *mockLedgerForTracker) Block(rnd basics.Round) (bookkeeping.Block, error) {
	if rnd > ml.Latest() {
		return bookkeeping.Block{}, fmt.Errorf("rnd %d out of bounds", rnd)
	}

	return ml.blocks[int(rnd)].block, nil
}

func (ml *mockLedgerForTracker) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	if rnd > ml.Latest() {
		return bookkeeping.BlockHeader{}, fmt.Errorf("rnd %d out of bounds", rnd)
	}

	return ml.blocks[int(rnd)].block.BlockHeader, nil
}

func (ml *mockLedgerForTracker) blockAux(rnd basics.Round) (bookkeeping.Block, evalAux, error) {
	if rnd > ml.Latest() {
		return bookkeeping.Block{}, evalAux{}, fmt.Errorf("rnd %d out of bounds", rnd)
	}

	return ml.blocks[int(rnd)].block, ml.blocks[int(rnd)].aux, nil
}

func (ml *mockLedgerForTracker) trackerDB() dbPair {
	return ml.dbs
}

func (ml *mockLedgerForTracker) trackerLog() logging.Logger {
	return logging.Base()
}

func checkAcctUpdates(t *testing.T, au *accountUpdates, base basics.Round, latestRnd basics.Round, accts []map[basics.Address]basics.AccountData, rewards []uint64, proto config.ConsensusParams) {
	latest := au.latest()
	require.Equal(t, latest, latestRnd)

	_, err := au.totals(latest + 1)
	require.Error(t, err)

	_, err = au.lookup(latest+1, randomAddress(), false)
	require.Error(t, err)

	if base > 0 {
		_, err := au.totals(base - 1)
		require.Error(t, err)

		_, err = au.lookup(base-1, randomAddress(), false)
		require.Error(t, err)
	}

	for rnd := base; rnd <= latest; rnd++ {
		var totalOnline, totalOffline, totalNotPart uint64

		for addr, data := range accts[rnd] {
			d, err := au.lookup(rnd, addr, false)
			require.NoError(t, err)
			require.Equal(t, d, data)

			rewardsDelta := rewards[rnd] - d.RewardsBase
			switch d.Status {
			case basics.Online:
				totalOnline += d.MicroAlgos.Raw
				totalOnline += (d.MicroAlgos.Raw / proto.RewardUnit) * rewardsDelta
			case basics.Offline:
				totalOffline += d.MicroAlgos.Raw
				totalOffline += (d.MicroAlgos.Raw / proto.RewardUnit) * rewardsDelta
			case basics.NotParticipating:
				totalNotPart += d.MicroAlgos.Raw
			default:
				t.Errorf("unknown status %v", d.Status)
			}
		}

		all, err := au.allBalances(rnd)
		require.NoError(t, err)
		require.Equal(t, all, accts[rnd])

		totals, err := au.totals(rnd)
		require.NoError(t, err)
		require.Equal(t, totals.Online.Money.Raw, totalOnline)
		require.Equal(t, totals.Offline.Money.Raw, totalOffline)
		require.Equal(t, totals.NotParticipating.Money.Raw, totalNotPart)
		require.Equal(t, totals.Participating().Raw, totalOnline+totalOffline)
		require.Equal(t, totals.All().Raw, totalOnline+totalOffline+totalNotPart)

		d, err := au.lookup(rnd, randomAddress(), false)
		require.NoError(t, err)
		require.Equal(t, d, basics.AccountData{})
	}

	checkAcctUpdatesConsistency(t, au)
}

func checkAcctUpdatesConsistency(t *testing.T, au *accountUpdates) {
	accounts := make(map[basics.Address]modifiedAccount)

	for _, rdelta := range au.deltas {
		for addr, adelta := range rdelta {
			macct := accounts[addr]
			macct.data = adelta.new
			macct.ndeltas++
			accounts[addr] = macct
		}
	}

	require.Equal(t, au.accounts, accounts)
}

func TestAcctUpdates(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(t)
	defer ml.close()
	ml.blocks = randomInitChain(protocol.ConsensusCurrentVersion, 10)

	accts := []map[basics.Address]basics.AccountData{randomAccounts(20)}
	rewardsLevels := []uint64{0}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	au := &accountUpdates{initAccounts: accts[0], initProto: proto}
	err := au.loadFromDisk(ml)
	require.NoError(t, err)

	// cover 10 genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < 10; i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	checkAcctUpdates(t, au, 0, 9, accts, rewardsLevels, proto)

	for i := basics.Round(10); i < basics.Round(proto.MaxBalLookback+15); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		updates, totals := randomDeltasBalanced(1, accts[i-1], rewardLevel)

		prevTotals, err := au.totals(basics.Round(i - 1))
		require.NoError(t, err)

		oldPool := accts[i-1][testPoolAddr]
		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates[testPoolAddr] = accountDelta{old: oldPool, new: newPool}
		totals[testPoolAddr] = newPool

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = protocol.ConsensusCurrentVersion

		au.newBlock(blk, StateDelta{
			accts: updates,
			hdr:   &blk.BlockHeader,
		})
		accts = append(accts, totals)
		rewardsLevels = append(rewardsLevels, rewardLevel)

		checkAcctUpdates(t, au, 0, i, accts, rewardsLevels, proto)
	}

	for i := basics.Round(0); i < 15; i++ {
		// Clear the timer to ensure a flush
		au.lastFlushTime = time.Time{}

		au.committedUpTo(basics.Round(proto.MaxBalLookback) + i)
		checkAcctUpdates(t, au, i, basics.Round(proto.MaxBalLookback+14), accts, rewardsLevels, proto)
	}
}
