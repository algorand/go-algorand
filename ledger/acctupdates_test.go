// Copyright (C) 2019-2020 Algorand, Inc.
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
	"context"
	"database/sql"
	"fmt"
	"os"
	"runtime"
	"sync"
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
	dbs      dbPair
	blocks   []blockEntry
	log      logging.Logger
	filename string
	inMemory bool
}

func makeMockLedgerForTracker(t testing.TB, inMemory bool) *mockLedgerForTracker {
	dbs, fileName := dbOpenTest(t, inMemory)
	dblogger := logging.TestingLog(t)
	dblogger.SetLevel(logging.Info)
	dbs.rdb.SetLogger(dblogger)
	dbs.wdb.SetLogger(dblogger)
	return &mockLedgerForTracker{dbs: dbs, log: dblogger, filename: fileName, inMemory: inMemory}
}

func (ml *mockLedgerForTracker) close() {
	ml.dbs.close()
	// delete the database files of non-memory instances.
	if !ml.inMemory {
		os.Remove(ml.filename)
		os.Remove(ml.filename + "-shm")
		os.Remove(ml.filename + "-wal")
	}
}

func (ml *mockLedgerForTracker) Latest() basics.Round {
	return basics.Round(len(ml.blocks)) - 1
}

func (ml *mockLedgerForTracker) trackerEvalVerified(blk bookkeeping.Block) (StateDelta, error) {
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

func (ml *mockLedgerForTracker) trackerDB() dbPair {
	return ml.dbs
}

func (ml *mockLedgerForTracker) blockDB() dbPair {
	return dbPair{}
}

func (ml *mockLedgerForTracker) trackerLog() logging.Logger {
	return ml.log
}

// this function used to be in acctupdates.go, but we were never using it for production purposes. This
// function has a conceptual flaw in that it attempts to load the entire balances into memory. This might
// not work if we have large number of balances. On these unit testing, however, it's not the case, and it's
// safe to call it.
func (au *accountUpdates) allBalances(rnd basics.Round) (bals map[basics.Address]basics.AccountData, err error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	offsetLimit, err := au.roundOffset(rnd)

	if err != nil {
		return
	}

	err = au.dbs.rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err0 error
		bals, err0 = accountsAll(tx)
		return err0
	})
	if err != nil {
		return
	}

	for offset := uint64(0); offset < offsetLimit; offset++ {
		for addr, delta := range au.deltas[offset] {
			bals[addr] = delta.new
		}
	}
	return
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

	roundsRanges := []struct {
		start, end basics.Round
	}{}

	// running the checkAcctUpdates on the entire range of base..latestRnd is too slow, and unlikely to help us
	// to trap a regression ( might be a good to find where the regression started ). so, for
	// performance reasons, we're going to run it againt the first and last 5 rounds, plus few rounds
	// in between.
	if latestRnd-base <= 10 {
		roundsRanges = append(roundsRanges, struct{ start, end basics.Round }{base, latestRnd})
	} else {
		roundsRanges = append(roundsRanges, struct{ start, end basics.Round }{base, base + 5})
		roundsRanges = append(roundsRanges, struct{ start, end basics.Round }{latestRnd - 5, latestRnd})
		for i := base + 5; i < latestRnd-5; i += 1 + (latestRnd-base-10)/10 {
			roundsRanges = append(roundsRanges, struct{ start, end basics.Round }{i, i + 1})
		}
	}
	for _, roundRange := range roundsRanges {
		for rnd := roundRange.start; rnd <= roundRange.end; rnd++ {
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
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		t.Skip("This test is too slow on ARM and causes travis builds to time out")
	}
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(t, true)
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

	au := &accountUpdates{}
	au.initialize(config.GetDefaultLocal(), ".", proto, accts[0])
	defer au.close()

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
		au.waitAccountsWriting()
		checkAcctUpdates(t, au, i, basics.Round(proto.MaxBalLookback+14), accts, rewardsLevels, proto)
	}
}

func TestAcctUpdatesFastUpdates(t *testing.T) {
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		t.Skip("This test is too slow on ARM and causes travis builds to time out")
	}
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(t, true)
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

	au := &accountUpdates{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	au.initialize(conf, ".", proto, accts[0])
	defer au.close()

	err := au.loadFromDisk(ml)
	require.NoError(t, err)

	// cover 10 genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < 10; i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	checkAcctUpdates(t, au, 0, 9, accts, rewardsLevels, proto)

	wg := sync.WaitGroup{}

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

		wg.Add(1)
		go func(round basics.Round) {
			defer wg.Done()
			au.committedUpTo(round)
		}(i)
	}
	wg.Wait()
}

func BenchmarkBalancesChanges(b *testing.B) {
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		b.Skip("This test is too slow on ARM and causes travis builds to time out")
	}
	if b.N < 100 {
		b.N = 50
	}
	protocolVersion := protocol.ConsensusVersion("BenchmarkBalancesChanges-test-protocol-version")
	testProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	testProtocol.MaxBalLookback = 25
	config.Consensus[protocolVersion] = testProtocol
	defer func() {
		delete(config.Consensus, protocolVersion)
	}()

	proto := config.Consensus[protocolVersion]

	ml := makeMockLedgerForTracker(b, true)
	defer ml.close()
	initialRounds := uint64(1)
	ml.blocks = randomInitChain(protocolVersion, int(initialRounds))
	accountsCount := 5000
	accts := []map[basics.Address]basics.AccountData{randomAccounts(accountsCount)}
	rewardsLevels := []uint64{0}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	au := &accountUpdates{}
	au.initialize(config.GetDefaultLocal(), ".", proto, accts[0])
	err := au.loadFromDisk(ml)
	require.NoError(b, err)
	defer au.close()

	// cover initialRounds genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < int(initialRounds); i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	for i := basics.Round(initialRounds); i < basics.Round(proto.MaxBalLookback+uint64(b.N)); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 0
		if i <= basics.Round(initialRounds)+basics.Round(b.N) {
			accountChanges = accountsCount - 2 - int(basics.Round(proto.MaxBalLookback+uint64(b.N))+i)
		}

		updates, totals := randomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevTotals, err := au.totals(basics.Round(i - 1))
		require.NoError(b, err)

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
		blk.CurrentProtocol = protocolVersion

		au.newBlock(blk, StateDelta{
			accts: updates,
			hdr:   &blk.BlockHeader,
		})
		accts = append(accts, totals)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}
	for i := proto.MaxBalLookback; i < proto.MaxBalLookback+initialRounds; i++ {
		// Clear the timer to ensure a flush
		au.lastFlushTime = time.Time{}
		au.committedUpTo(basics.Round(i))
	}
	au.waitAccountsWriting()
	b.ResetTimer()
	startTime := time.Now()
	for i := proto.MaxBalLookback + initialRounds; i < proto.MaxBalLookback+uint64(b.N); i++ {
		// Clear the timer to ensure a flush
		au.lastFlushTime = time.Time{}
		au.committedUpTo(basics.Round(i))
	}
	au.waitAccountsWriting()
	deltaTime := time.Now().Sub(startTime)
	if deltaTime > time.Second {
		return
	}
	// we want to fake the N to reflect the time it took us, if we were to wait an entire second.
	singleIterationTime := deltaTime / time.Duration((uint64(b.N) - initialRounds))
	b.N = int(time.Second / singleIterationTime)
	// and now, wait for the reminder of the second.
	time.Sleep(time.Second - deltaTime)

}

func BenchmarkCalibrateNodesPerPage(b *testing.B) {
	b.Skip("This benchmark was used to tune up the NodesPerPage; it's not really usefull otherwise")
	defaultNodesPerPage := merkleCommitterNodesPerPage
	for nodesPerPage := 32; nodesPerPage < 300; nodesPerPage++ {
		b.Run(fmt.Sprintf("Test_merkleCommitterNodesPerPage_%d", nodesPerPage), func(b *testing.B) {
			merkleCommitterNodesPerPage = int64(nodesPerPage)
			BenchmarkBalancesChanges(b)
		})
	}
	merkleCommitterNodesPerPage = defaultNodesPerPage
}

func BenchmarkCalibrateCacheNodeSize(b *testing.B) {
	//b.Skip("This benchmark was used to tune up the trieCachedNodesCount; it's not really usefull otherwise")
	defaultTrieCachedNodesCount := trieCachedNodesCount
	for cacheSize := 3000; cacheSize < 50000; cacheSize += 1000 {
		b.Run(fmt.Sprintf("Test_cacheSize_%d", cacheSize), func(b *testing.B) {
			trieCachedNodesCount = cacheSize
			BenchmarkBalancesChanges(b)
		})
	}
	trieCachedNodesCount = defaultTrieCachedNodesCount
}

// TestLargeAccountCountCatchpointGeneration creates a ledger containing a large set of accounts ( i.e. 100K accounts )
// and attempts to have the accountUpdates create the associated catchpoint. It's designed precisly around setting an
// environment which would quickly ( i.e. after 32 rounds ) would start producing catchpoints.
func TestLargeAccountCountCatchpointGeneration(t *testing.T) {
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		t.Skip("This test is too slow on ARM and causes travis builds to time out")
	}
	// create new protocol version, which has lower back balance.
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestLargeAccountCountCatchpointGeneration")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = 32
	protoParams.SeedLookback = 2
	protoParams.SeedRefreshInterval = 8
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
		os.RemoveAll("./catchpoints")
	}()

	ml := makeMockLedgerForTracker(t, true)
	defer ml.close()
	ml.blocks = randomInitChain(testProtocolVersion, 10)
	accts := []map[basics.Address]basics.AccountData{randomAccounts(100000)}
	rewardsLevels := []uint64{0}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	au := &accountUpdates{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au.initialize(conf, ".", protoParams, accts[0])
	defer au.close()
	err := au.loadFromDisk(ml)
	require.NoError(t, err)

	// cover 10 genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < 10; i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	for i := basics.Round(10); i < basics.Round(protoParams.MaxBalLookback+5); i++ {
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
		blk.CurrentProtocol = testProtocolVersion

		au.newBlock(blk, StateDelta{
			accts: updates,
			hdr:   &blk.BlockHeader,
		})
		accts = append(accts, totals)
		rewardsLevels = append(rewardsLevels, rewardLevel)

		au.committedUpTo(i)
		if i%2 == 1 {
			au.waitAccountsWriting()
		}
	}
}

// The TestAcctUpdatesUpdatesCorrectness conduct a correctless test for the accounts update in the following way -
// Each account is initialized with 100 algos.
// On every round, each account move variable amount of funds to an accumulating account.
// The deltas for each accounts are picked by using the lookup method.
// At the end of the test, we verify that each account has the expected amount of algos.
// In addition, throughout the test, we check ( using lookup ) that the historical balances, *beyond* the
// lookback are generating either an error, or returning the correct amount.
func TestAcctUpdatesUpdatesCorrectness(t *testing.T) {
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		t.Skip("This test is too slow on ARM and causes travis builds to time out")
	}

	// create new protocol version, which has lower look back.
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctUpdatesUpdatesCorrectness")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = 5
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	inMemory := true

	testFunction := func(t *testing.T) {
		ml := makeMockLedgerForTracker(t, inMemory)
		defer ml.close()
		ml.blocks = randomInitChain(testProtocolVersion, 10)

		accts := []map[basics.Address]basics.AccountData{randomAccounts(9)}

		pooldata := basics.AccountData{}
		pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
		pooldata.Status = basics.NotParticipating
		accts[0][testPoolAddr] = pooldata

		sinkdata := basics.AccountData{}
		sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
		sinkdata.Status = basics.NotParticipating
		accts[0][testSinkAddr] = sinkdata

		var moneyAccounts []basics.Address

		for addr := range accts[0] {
			if bytes.Compare(addr[:], testPoolAddr[:]) == 0 || bytes.Compare(addr[:], testSinkAddr[:]) == 0 {
				continue
			}
			moneyAccounts = append(moneyAccounts, addr)
		}

		moneyAccountsExpectedAmounts := make([][]uint64, 0)
		// set all the accounts with 100 algos.
		for _, addr := range moneyAccounts {
			accountData := accts[0][addr]
			accountData.MicroAlgos.Raw = 100 * 1000000
			accts[0][addr] = accountData
		}

		au := &accountUpdates{}
		au.initialize(config.GetDefaultLocal(), ".", protoParams, accts[0])
		defer au.close()

		err := au.loadFromDisk(ml)
		require.NoError(t, err)

		// cover 10 genesis blocks
		rewardLevel := uint64(0)
		for i := 1; i < 10; i++ {
			accts = append(accts, accts[0])

		}
		for i := 0; i < 10; i++ {
			moneyAccountsExpectedAmounts = append(moneyAccountsExpectedAmounts, make([]uint64, len(moneyAccounts)))
			for j := range moneyAccounts {
				moneyAccountsExpectedAmounts[i][j] = 100 * 1000000
			}
		}

		i := basics.Round(10)
		roundCount := 50
		for ; i < basics.Round(10+roundCount); i++ {
			updates := make(map[basics.Address]accountDelta)
			moneyAccountsExpectedAmounts = append(moneyAccountsExpectedAmounts, make([]uint64, len(moneyAccounts)))
			toAccount := moneyAccounts[0]
			toAccountDataOld, err := au.lookup(i-1, toAccount, false)
			require.NoError(t, err)
			toAccountDataNew := toAccountDataOld

			for j := 1; j < len(moneyAccounts); j++ {
				fromAccount := moneyAccounts[j]

				fromAccountDataOld, err := au.lookup(i-1, fromAccount, false)
				require.NoError(t, err)
				require.Equalf(t, moneyAccountsExpectedAmounts[i-1][j], fromAccountDataOld.MicroAlgos.Raw, "Account index : %d\nRound number : %d", j, i)

				fromAccountDataNew := fromAccountDataOld

				fromAccountDataNew.MicroAlgos.Raw -= uint64(i - 10)
				toAccountDataNew.MicroAlgos.Raw += uint64(i - 10)
				updates[fromAccount] = accountDelta{
					old: fromAccountDataOld,
					new: fromAccountDataNew,
				}

				moneyAccountsExpectedAmounts[i][j] = fromAccountDataNew.MicroAlgos.Raw
			}

			moneyAccountsExpectedAmounts[i][0] = moneyAccountsExpectedAmounts[i-1][0] + uint64(len(moneyAccounts)-1)*uint64(i-10)

			// force to perform a test that goes directly to disk, and see if it has the expected values.
			if uint64(i) > protoParams.MaxBalLookback+3 {

				// check the status at a historical time:
				checkRound := uint64(i) - protoParams.MaxBalLookback - 2

				testback := 1
				for j := 1; j < len(moneyAccounts); j++ {
					if checkRound < uint64(testback) {
						continue
					}
					acct, err := au.lookup(basics.Round(checkRound-uint64(testback)), moneyAccounts[j], false)
					// we might get an error like "round 2 before dbRound 5", which is the success case, so we'll ignore it.
					if err != nil {
						// verify it's the expected error and not anything else.
						var r1, r2 int
						n, err2 := fmt.Sscanf(err.Error(), "round %d before dbRound %d", &r1, &r2)
						require.NoErrorf(t, err2, "unable to parse : %v", err)
						require.Equal(t, 2, n)
						require.Less(t, r1, r2)
						if testback > 1 {
							testback--
						}
						continue
					}
					// if we received no error, we want to make sure the reported amount is correct.
					require.Equalf(t, moneyAccountsExpectedAmounts[checkRound-uint64(testback)][j], acct.MicroAlgos.Raw, "Account index : %d\nRound number : %d", j, checkRound)
					testback++
					j--
				}
			}

			updates[toAccount] = accountDelta{
				old: toAccountDataOld,
				new: toAccountDataNew,
			}

			blk := bookkeeping.Block{
				BlockHeader: bookkeeping.BlockHeader{
					Round: basics.Round(i),
				},
			}
			blk.RewardsLevel = rewardLevel
			blk.CurrentProtocol = testProtocolVersion

			au.newBlock(blk, StateDelta{
				accts: updates,
				hdr:   &blk.BlockHeader,
			})
			au.committedUpTo(i)
		}
		lastRound := i - 1
		au.waitAccountsWriting()

		for idx, addr := range moneyAccounts {
			balance, err := au.lookup(lastRound, addr, false)
			require.NoErrorf(t, err, "unable to retrieve balance for account idx %d %v", idx, addr)
			if idx != 0 {
				require.Equalf(t, 100*1000000-roundCount*(roundCount-1)/2, int(balance.MicroAlgos.Raw), "account idx %d %v has the wrong balance", idx, addr)
			} else {
				require.Equalf(t, 100*1000000+(len(moneyAccounts)-1)*roundCount*(roundCount-1)/2, int(balance.MicroAlgos.Raw), "account idx %d %v has the wrong balance", idx, addr)
			}

		}
	}

	t.Run("InMemoryDB", testFunction)
	inMemory = false
	t.Run("DiskDB", testFunction)
}
