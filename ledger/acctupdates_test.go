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
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

func (ml *mockLedgerForTracker) trackerEvalVerified(blk bookkeeping.Block, accUpdatesLedger ledgerForEvaluator) (StateDelta, error) {
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

func (ml *mockLedgerForTracker) GenesisHash() crypto.Digest {
	if len(ml.blocks) > 0 {
		return ml.blocks[0].block.GenesisHash()
	}
	return crypto.Digest{}
}

func (ml *mockLedgerForTracker) GenesisProto() config.ConsensusParams {
	if len(ml.blocks) > 0 {
		return config.Consensus[ml.blocks[0].block.CurrentProtocol]
	}
	return config.Consensus[protocol.ConsensusCurrentVersion]
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

	_, err := au.Totals(latest + 1)
	require.Error(t, err)

	var validThrough basics.Round
	_, validThrough, err = au.LookupWithoutRewards(latest+1, randomAddress())
	require.Error(t, err)
	require.Equal(t, basics.Round(0), validThrough)

	if base > 0 {
		_, err := au.Totals(base - 1)
		require.Error(t, err)

		_, validThrough, err = au.LookupWithoutRewards(base-1, randomAddress())
		require.Error(t, err)
		require.Equal(t, basics.Round(0), validThrough)
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
				d, validThrough, err := au.LookupWithoutRewards(rnd, addr)
				require.NoError(t, err)
				require.Equal(t, d, data)
				require.GreaterOrEqualf(t, uint64(validThrough), uint64(rnd), fmt.Sprintf("validThrough :%v\nrnd :%v\n", validThrough, rnd))

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

			totals, err := au.Totals(rnd)
			require.NoError(t, err)
			require.Equal(t, totals.Online.Money.Raw, totalOnline)
			require.Equal(t, totals.Offline.Money.Raw, totalOffline)
			require.Equal(t, totals.NotParticipating.Money.Raw, totalNotPart)
			require.Equal(t, totals.Participating().Raw, totalOnline+totalOffline)
			require.Equal(t, totals.All().Raw, totalOnline+totalOffline+totalNotPart)

			d, validThrough, err := au.LookupWithoutRewards(rnd, randomAddress())
			require.NoError(t, err)
			require.GreaterOrEqualf(t, uint64(validThrough), uint64(rnd), fmt.Sprintf("validThrough :%v\nrnd :%v\n", validThrough, rnd))
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

	accts := []map[basics.Address]basics.AccountData{randomAccounts(20, true)}
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

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	lastCreatableID := crypto.RandUint64() % 512
	knownCreatables := make(map[basics.CreatableIndex]bool)
	for i := basics.Round(10); i < basics.Round(proto.MaxBalLookback+15); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		var updates map[basics.Address]accountDelta
		var totals map[basics.Address]basics.AccountData
		updates, totals, lastCreatableID = randomDeltasBalancedFull(1, accts[i-1], rewardLevel, lastCreatableID)
		prevTotals, err := au.Totals(basics.Round(i - 1))
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
			accts:      updates,
			hdr:        &blk.BlockHeader,
			creatables: creatablesFromUpdates(updates, knownCreatables),
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

	accts := []map[basics.Address]basics.AccountData{randomAccounts(20, true)}
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

		prevTotals, err := au.Totals(basics.Round(i - 1))
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
	accts := []map[basics.Address]basics.AccountData{randomAccounts(accountsCount, true)}
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
		prevTotals, err := au.Totals(basics.Round(i - 1))
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
	// create new protocol version, which has lower lookback
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
	accts := []map[basics.Address]basics.AccountData{randomAccounts(100000, true)}
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

		prevTotals, err := au.Totals(basics.Round(i - 1))
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

		accts := []map[basics.Address]basics.AccountData{randomAccounts(9, true)}

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
			toAccountDataOld, validThrough, err := au.LookupWithoutRewards(i-1, toAccount)
			require.NoError(t, err)
			require.Equal(t, i-1, validThrough)
			toAccountDataNew := toAccountDataOld

			for j := 1; j < len(moneyAccounts); j++ {
				fromAccount := moneyAccounts[j]

				fromAccountDataOld, validThrough, err := au.LookupWithoutRewards(i-1, fromAccount)
				require.NoError(t, err)
				require.Equal(t, i-1, validThrough)
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
					acct, validThrough, err := au.LookupWithoutRewards(basics.Round(checkRound-uint64(testback)), moneyAccounts[j])
					// we might get an error like "round 2 before dbRound 5", which is the success case, so we'll ignore it.
					roundOffsetError := &RoundOffsetError{}
					if errors.As(err, &roundOffsetError) {
						require.Equal(t, basics.Round(0), validThrough)
						// verify it's the expected error and not anything else.
						require.Less(t, int64(roundOffsetError.round), int64(roundOffsetError.dbRound))
						if testback > 1 {
							testback--
						}
						continue
					}
					require.NoError(t, err)
					require.GreaterOrEqual(t, int64(validThrough), int64(basics.Round(checkRound-uint64(testback))))
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
			balance, validThrough, err := au.LookupWithoutRewards(lastRound, addr)
			require.NoErrorf(t, err, "unable to retrieve balance for account idx %d %v", idx, addr)
			require.Equal(t, lastRound, validThrough)
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

// TestAcctUpdatesDeleteStoredCatchpoints - The goal of this test is to verify that the deleteStoredCatchpoints function works correctly.
// it doing so by filling up the storedcatchpoints with dummy catchpoint file entries, as well as creating these dummy files on disk.
// ( the term dummy is only because these aren't real catchpoint files, but rather a zero-length file ). Then, the test call the function
// and ensures that it did not errored, the catchpoint files were correctly deleted, and that deleteStoredCatchpoints contains no more
// entries.
func TestAcctUpdatesDeleteStoredCatchpoints(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(t, true)
	defer ml.close()
	ml.blocks = randomInitChain(protocol.ConsensusCurrentVersion, 10)

	accts := []map[basics.Address]basics.AccountData{randomAccounts(20, true)}
	au := &accountUpdates{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	au.initialize(conf, ".", proto, accts[0])
	defer au.close()

	err := au.loadFromDisk(ml)
	require.NoError(t, err)

	dummyCatchpointFilesToCreate := 42

	for i := 0; i < dummyCatchpointFilesToCreate; i++ {
		f, err := os.Create(fmt.Sprintf("./dummy_catchpoint_file-%d", i))
		require.NoError(t, err)
		err = f.Close()
		require.NoError(t, err)
	}

	for i := 0; i < dummyCatchpointFilesToCreate; i++ {
		err := au.accountsq.storeCatchpoint(context.Background(), basics.Round(i), fmt.Sprintf("./dummy_catchpoint_file-%d", i), "", 0)
		require.NoError(t, err)
	}
	err = au.deleteStoredCatchpoints(context.Background(), au.accountsq)
	require.NoError(t, err)

	for i := 0; i < dummyCatchpointFilesToCreate; i++ {
		// ensure that all the files were deleted.
		_, err := os.Open(fmt.Sprintf("./dummy_catchpoint_file-%d", i))
		require.True(t, os.IsNotExist(err))
	}
	fileNames, err := au.accountsq.getOldestCatchpointFiles(context.Background(), dummyCatchpointFilesToCreate, 0)
	require.NoError(t, err)
	require.Equal(t, 0, len(fileNames))
}

// listAndCompareComb lists the assets/applications and then compares against the expected
// It repeats with different combinations of the limit parameters
func listAndCompareComb(t *testing.T, au *accountUpdates, expected map[basics.CreatableIndex]modifiedCreatable) {

	// test configuration parameters

	// pick the second largest index for the app and asset
	// This is to make sure exactly one element is left out
	// as a result of max index
	maxAss1 := basics.CreatableIndex(0)
	maxAss2 := basics.CreatableIndex(0)
	maxApp1 := basics.CreatableIndex(0)
	maxApp2 := basics.CreatableIndex(0)
	for a, b := range expected {
		// A moving window of the last two largest indexes: [maxAss1, maxAss2]
		if b.ctype == basics.AssetCreatable {
			if maxAss2 < a {
				maxAss1 = maxAss2
				maxAss2 = a
			} else if maxAss1 < a {
				maxAss1 = a
			}
		}
		if b.ctype == basics.AppCreatable {
			if maxApp2 < a {
				maxApp1 = maxApp2
				maxApp2 = a
			} else if maxApp1 < a {
				maxApp1 = a
			}
		}
	}

	// No limits. max asset index, max app index and max results have no effect
	// This is to make sure the deleted elements do not show up
	maxAssetIdx := basics.AssetIndex(maxAss2)
	maxAppIdx := basics.AppIndex(maxApp2)
	maxResults := uint64(len(expected))
	listAndCompare(t, maxAssetIdx, maxAppIdx, maxResults, au, expected)

	// Limit with max asset index and max app index (max results has no effect)
	maxAssetIdx = basics.AssetIndex(maxAss1)
	maxAppIdx = basics.AppIndex(maxApp1)
	maxResults = uint64(len(expected))
	listAndCompare(t, maxAssetIdx, maxAppIdx, maxResults, au, expected)

	// Limit with max results
	maxResults = 1
	listAndCompare(t, maxAssetIdx, maxAppIdx, maxResults, au, expected)
}

// listAndCompareComb lists the assets/applications and then compares against the expected
// It uses the provided limit parameters
func listAndCompare(t *testing.T,
	maxAssetIdx basics.AssetIndex,
	maxAppIdx basics.AppIndex,
	maxResults uint64,
	au *accountUpdates,
	expected map[basics.CreatableIndex]modifiedCreatable) {

	// get the results with the given parameters
	assetRes, err := au.ListAssets(maxAssetIdx, maxResults)
	require.NoError(t, err)
	appRes, err := au.ListApplications(maxAppIdx, maxResults)
	require.NoError(t, err)

	// count the expected number of results
	expectedAssetCount := uint64(0)
	expectedAppCount := uint64(0)
	for a, b := range expected {
		if b.created {
			if b.ctype == basics.AssetCreatable &&
				a <= basics.CreatableIndex(maxAssetIdx) &&
				expectedAssetCount < maxResults {
				expectedAssetCount++
			}
			if b.ctype == basics.AppCreatable &&
				a <= basics.CreatableIndex(maxAppIdx) &&
				expectedAppCount < maxResults {
				expectedAppCount++
			}
		}
	}

	// check the total counts are as expected
	require.Equal(t, int(expectedAssetCount), len(assetRes))
	require.Equal(t, int(expectedAppCount), len(appRes))

	// verify the results are correct
	for _, respCrtor := range assetRes {
		crtor := expected[respCrtor.Index]
		require.NotNil(t, crtor)
		require.Equal(t, basics.AssetCreatable, crtor.ctype)
		require.Equal(t, true, crtor.created)

		require.Equal(t, basics.AssetCreatable, respCrtor.Type)
		require.Equal(t, crtor.creator, respCrtor.Creator)
	}
	for _, respCrtor := range appRes {
		crtor := expected[respCrtor.Index]
		require.NotNil(t, crtor)
		require.Equal(t, basics.AppCreatable, crtor.ctype)
		require.Equal(t, true, crtor.created)

		require.Equal(t, basics.AppCreatable, respCrtor.Type)
		require.Equal(t, crtor.creator, respCrtor.Creator)
	}
}

// TestListCreatables tests ListAssets and ListApplications
// It tests with all elements in cache, all synced to database, and combination of both
// It also tests the max results, max app index and max asset index
func TestListCreatables(t *testing.T) {

	// test configuration parameters
	numElementsPerSegement := 25

	// set up the database
	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.close()

	tx, err := dbs.wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	accts := make(map[basics.Address]basics.AccountData)
	err = accountsInit(tx, accts, proto)
	require.NoError(t, err)

	err = accountsAddNormalizedBalance(tx, proto)
	require.NoError(t, err)

	au := &accountUpdates{}
	au.accountsq, err = accountsDbInit(tx, tx)
	require.NoError(t, err)

	// ******* All results are obtained from the cache. Empty database *******
	// ******* No deletes                                              *******
	// get random data. Inital batch, no deletes
	ctbsList, randomCtbs := randomCreatables(numElementsPerSegement)
	expectedDbImage := make(map[basics.CreatableIndex]modifiedCreatable)
	ctbsWithDeletes := randomCreatableSampling(1, ctbsList, randomCtbs,
		expectedDbImage, numElementsPerSegement)
	// set the cache
	au.creatables = ctbsWithDeletes
	listAndCompareComb(t, au, expectedDbImage)

	// ******* All results are obtained from the database. Empty cache *******
	// ******* No deletes	                                           *******
	// sync with the database
	var updates map[basics.Address]accountDeltaCount
	err = accountsNewRound(tx, updates, ctbsWithDeletes, proto)
	require.NoError(t, err)
	// nothing left in cache
	au.creatables = make(map[basics.CreatableIndex]modifiedCreatable)
	listAndCompareComb(t, au, expectedDbImage)

	// ******* Results are obtained from the database and from the cache *******
	// ******* No deletes in the database.                               *******
	// ******* Data in the database deleted in the cache                 *******
	au.creatables = randomCreatableSampling(2, ctbsList, randomCtbs,
		expectedDbImage, numElementsPerSegement)
	listAndCompareComb(t, au, expectedDbImage)

	// ******* Results are obtained from the database and from the cache *******
	// ******* Deletes are in the database and in the cache              *******
	// sync with the database. This has deletes synced to the database.
	err = accountsNewRound(tx, updates, au.creatables, proto)
	require.NoError(t, err)
	// get new creatables in the cache. There will be deletes in the cache from the previous batch.
	au.creatables = randomCreatableSampling(3, ctbsList, randomCtbs,
		expectedDbImage, numElementsPerSegement)
	listAndCompareComb(t, au, expectedDbImage)
}

func TestIsWritingCatchpointFile(t *testing.T) {

	au := &accountUpdates{}

	au.catchpointWriting = -1
	ans := au.IsWritingCatchpointFile()
	require.True(t, ans)

	au.catchpointWriting = 0
	ans = au.IsWritingCatchpointFile()
	require.False(t, ans)
}

func TestGetCatchpointStream(t *testing.T) {

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(t, true)
	defer ml.close()
	ml.blocks = randomInitChain(protocol.ConsensusCurrentVersion, 10)

	accts := []map[basics.Address]basics.AccountData{randomAccounts(20, true)}
	au := &accountUpdates{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	au.initialize(conf, ".", proto, accts[0])
	defer au.close()

	err := au.loadFromDisk(ml)
	require.NoError(t, err)

	filesToCreate := 4

	temporaryDirectroy, err := ioutil.TempDir(os.TempDir(), "catchpoints")
	require.NoError(t, err)
	defer func() {
		os.RemoveAll(temporaryDirectroy)
	}()
	catchpointsDirectory := filepath.Join(temporaryDirectroy, "catchpoints")
	err = os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(t, err)

	au.dbDirectory = temporaryDirectroy

	// Create the catchpoint files with dummy data
	for i := 0; i < filesToCreate; i++ {
		fileName := filepath.Join("catchpoints", fmt.Sprintf("%d.catchpoint", i))
		data := []byte{byte(i), byte(i + 1), byte(i + 2)}
		err = ioutil.WriteFile(filepath.Join(temporaryDirectroy, fileName), data, 0666)
		require.NoError(t, err)

		// Store the catchpoint into the database
		err := au.accountsq.storeCatchpoint(context.Background(), basics.Round(i), fileName, "", int64(len(data)))
		require.NoError(t, err)
	}

	dataRead := make([]byte, 3)
	var n int

	// File on disk, and database has the record
	reader, err := au.GetCatchpointStream(basics.Round(1))
	n, err = reader.Read(dataRead)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	outData := []byte{1, 2, 3}
	require.Equal(t, outData, dataRead)
	len, err := reader.Size()
	require.NoError(t, err)
	require.Equal(t, int64(3), len)

	// File deleted, but record in the database
	err = os.Remove(filepath.Join(temporaryDirectroy, "catchpoints", "2.catchpoint"))
	reader, err = au.GetCatchpointStream(basics.Round(2))
	require.Equal(t, ErrNoEntry{}, err)
	require.Nil(t, reader)

	// File on disk, but database lost the record
	err = au.accountsq.storeCatchpoint(context.Background(), basics.Round(3), "", "", 0)
	reader, err = au.GetCatchpointStream(basics.Round(3))
	n, err = reader.Read(dataRead)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	outData = []byte{3, 4, 5}
	require.Equal(t, outData, dataRead)

	err = au.deleteStoredCatchpoints(context.Background(), au.accountsq)
	require.NoError(t, err)
}

func accountsAll(tx *sql.Tx) (bals map[basics.Address]basics.AccountData, err error) {
	rows, err := tx.Query("SELECT address, data FROM accountbase")
	if err != nil {
		return
	}
	defer rows.Close()

	bals = make(map[basics.Address]basics.AccountData)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return
		}

		var data basics.AccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}

		copy(addr[:], addrbuf)
		bals[addr] = data
	}

	err = rows.Err()
	return
}

func BenchmarkLargeMerkleTrieRebuild(b *testing.B) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(b, true)
	defer ml.close()
	ml.blocks = randomInitChain(protocol.ConsensusCurrentVersion, 10)

	accts := []map[basics.Address]basics.AccountData{randomAccounts(5, true)}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	au := &accountUpdates{}
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	au.initialize(cfg, ".", proto, accts[0])
	defer au.close()

	err := au.loadFromDisk(ml)
	require.NoError(b, err)

	// at this point, the database was created. We want to fill the accounts data
	accountsNumber := 6000000 * b.N
	for i := 0; i < accountsNumber-5-2; { // subtract the account we've already created above, plus the sink/reward
		updates := make(map[basics.Address]accountDeltaCount, 0)
		for k := 0; i < accountsNumber-5-2 && k < 1024; k++ {
			addr := randomAddress()
			acctData := basics.AccountData{}
			acctData.MicroAlgos.Raw = 1
			updates[addr] = accountDeltaCount{accountDelta: accountDelta{new: acctData}}
			i++
		}

		err := ml.dbs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
			return accountsNewRound(tx, updates, nil, proto)
		})
		require.NoError(b, err)
	}

	err = ml.dbs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return updateAccountsRound(tx, 0, 1)
	})
	require.NoError(b, err)

	au.close()

	b.ResetTimer()
	err = au.loadFromDisk(ml)
	require.NoError(b, err)
	b.StopTimer()
	b.ReportMetric(float64(accountsNumber), "entries/trie")
}

func BenchmarkLargeCatchpointWriting(b *testing.B) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(b, true)
	defer ml.close()
	ml.blocks = randomInitChain(protocol.ConsensusCurrentVersion, 10)

	accts := []map[basics.Address]basics.AccountData{randomAccounts(5, true)}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	au := &accountUpdates{}
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	au.initialize(cfg, ".", proto, accts[0])
	defer au.close()

	temporaryDirectroy, err := ioutil.TempDir(os.TempDir(), "catchpoints")
	require.NoError(b, err)
	defer func() {
		os.RemoveAll(temporaryDirectroy)
	}()
	catchpointsDirectory := filepath.Join(temporaryDirectroy, "catchpoints")
	err = os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(b, err)

	au.dbDirectory = temporaryDirectroy

	err = au.loadFromDisk(ml)
	require.NoError(b, err)

	// at this point, the database was created. We want to fill the accounts data
	accountsNumber := 6000000 * b.N
	err = ml.dbs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		for i := 0; i < accountsNumber-5-2; { // subtract the account we've already created above, plus the sink/reward
			updates := make(map[basics.Address]accountDeltaCount, 0)
			for k := 0; i < accountsNumber-5-2 && k < 1024; k++ {
				addr := randomAddress()
				acctData := basics.AccountData{}
				acctData.MicroAlgos.Raw = 1
				updates[addr] = accountDeltaCount{accountDelta: accountDelta{new: acctData}}
				i++
			}

			err = accountsNewRound(tx, updates, nil, proto)
			if err != nil {
				return
			}
		}

		return updateAccountsRound(tx, 0, 1)
	})
	require.NoError(b, err)

	b.ResetTimer()
	au.generateCatchpoint(basics.Round(0), "0#ABCD", crypto.Digest{}, time.Second)
	b.StopTimer()
	b.ReportMetric(float64(accountsNumber), "accounts")
}

func BenchmarkCompactDeltas(b *testing.B) {
	b.Run("account-deltas", func(b *testing.B) {
		if b.N < 500 {
			b.N = 500
		}
		window := 5000
		accountDeltas := make([]map[basics.Address]accountDelta, b.N)
		addrs := make([]basics.Address, b.N*window)
		for i := 0; i < len(addrs); i++ {
			addrs[i] = basics.Address(crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}))
		}
		for rnd := 0; rnd < b.N; rnd++ {
			m := make(map[basics.Address]accountDelta)
			start := 0
			if rnd > 0 {
				start = window/2 + (rnd-1)*window
			}
			for k := start; k < start+window; k++ {
				m[addrs[k]] = accountDelta{
					old: basics.AccountData{},
					new: basics.AccountData{},
				}
			}

			accountDeltas[rnd] = m
		}
		b.ResetTimer()

		compactDeltas(accountDeltas, []map[basics.CreatableIndex]modifiedCreatable{{}})

	})
}
func TestCompactDeltas(t *testing.T) {
	addrs := make([]basics.Address, 10)
	for i := 0; i < len(addrs); i++ {
		addrs[i] = basics.Address(crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}))
	}
	var accountDeltas []map[basics.Address]accountDelta
	var creatableDeltas []map[basics.CreatableIndex]modifiedCreatable

	accountDeltas = make([]map[basics.Address]accountDelta, 1, 1)
	creatableDeltas = make([]map[basics.CreatableIndex]modifiedCreatable, 1, 1)
	accountDeltas[0] = make(map[basics.Address]accountDelta)
	creatableDeltas[0] = make(map[basics.CreatableIndex]modifiedCreatable)
	accountDeltas[0][addrs[0]] = accountDelta{old: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 1}}, new: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 2}}}
	creatableDeltas[0][100] = modifiedCreatable{creator: addrs[2], created: true}
	outAccountDeltas, outCreatableDeltas := compactDeltas(accountDeltas, creatableDeltas)

	require.Equal(t, len(accountDeltas[0]), len(outAccountDeltas))
	require.Equal(t, len(creatableDeltas[0]), len(outCreatableDeltas))

	require.Equal(t, basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 1}}, outAccountDeltas[addrs[0]].old)
	require.Equal(t, basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 2}}, outAccountDeltas[addrs[0]].new)
	require.Equal(t, modifiedCreatable{creator: addrs[2], created: true, ndeltas: 1}, outCreatableDeltas[100])

	// add another round
	accountDeltas = append(accountDeltas, make(map[basics.Address]accountDelta))
	creatableDeltas = append(creatableDeltas, make(map[basics.CreatableIndex]modifiedCreatable))
	accountDeltas[1][addrs[0]] = accountDelta{old: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 2}}, new: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 3}}}
	accountDeltas[1][addrs[3]] = accountDelta{old: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 0}}, new: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 8}}}

	creatableDeltas[1][100] = modifiedCreatable{creator: addrs[2], created: false}
	creatableDeltas[1][101] = modifiedCreatable{creator: addrs[4], created: true}

	outAccountDeltas, outCreatableDeltas = compactDeltas(accountDeltas, creatableDeltas)

	require.Equal(t, 2, len(outAccountDeltas))
	require.Equal(t, 2, len(outCreatableDeltas))

	require.Equal(t, uint64(1), outAccountDeltas[addrs[0]].old.MicroAlgos.Raw)
	require.Equal(t, uint64(3), outAccountDeltas[addrs[0]].new.MicroAlgos.Raw)
	require.Equal(t, int(2), outAccountDeltas[addrs[0]].ndeltas)
	require.Equal(t, uint64(0), outAccountDeltas[addrs[3]].old.MicroAlgos.Raw)
	require.Equal(t, uint64(8), outAccountDeltas[addrs[3]].new.MicroAlgos.Raw)
	require.Equal(t, int(1), outAccountDeltas[addrs[3]].ndeltas)

	require.Equal(t, addrs[2], outCreatableDeltas[100].creator)
	require.Equal(t, addrs[4], outCreatableDeltas[101].creator)
	require.Equal(t, false, outCreatableDeltas[100].created)
	require.Equal(t, true, outCreatableDeltas[101].created)
	require.Equal(t, 2, outCreatableDeltas[100].ndeltas)
	require.Equal(t, 1, outCreatableDeltas[101].ndeltas)

}
