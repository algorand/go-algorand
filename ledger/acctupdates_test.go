// Copyright (C) 2019-2025 Algorand, Inc.
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
	"errors"
	"fmt"
	"maps"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/sqlitedriver"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-deadlock"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}

type mockLedgerForTracker struct {
	dbs              trackerdb.Store
	blocks           []blockEntry
	deltas           []ledgercore.StateDelta
	log              logging.Logger
	filename         string
	inMemory         bool
	consensusParams  config.ConsensusParams
	consensusVersion protocol.ConsensusVersion
	accts            map[basics.Address]basics.AccountData

	mu deadlock.RWMutex

	// trackerRegistry manages persistence into DB so we have to have it here even for a single tracker test
	trackers trackerRegistry
}

// onlineTotals returns the online totals of all accounts at the end of round rnd.
// used in tests only
func (au *accountUpdates) onlineTotals(rnd basics.Round) (basics.MicroAlgos, error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return basics.MicroAlgos{}, err
	}

	totals := au.roundTotals[offset]
	return totals.Online.Money, nil
}

func accumulateTotals(t testing.TB, consensusVersion protocol.ConsensusVersion, accts []map[basics.Address]ledgercore.AccountData, rewardLevel uint64) (totals ledgercore.AccountTotals) {
	var ot basics.OverflowTracker
	proto := config.Consensus[consensusVersion]
	totals.RewardsLevel = rewardLevel
	for _, ar := range accts {
		for _, data := range ar {
			totals.AddAccount(proto.RewardUnit, data, &ot)
		}
	}
	require.False(t, ot.Overflowed)
	return
}

func setupAccts(niter int) []map[basics.Address]basics.AccountData {
	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(niter, true)}
	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 100 * 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	return accts
}

func makeMockLedgerForTrackerWithLogger(t testing.TB, inMemory bool, initialBlocksCount basics.Round, consensusVersion protocol.ConsensusVersion, accts []map[basics.Address]basics.AccountData, l logging.Logger) *mockLedgerForTracker {
	dbs, fileName := sqlitedriver.OpenForTesting(t, inMemory)

	blocks := randomInitChain(consensusVersion, initialBlocksCount)
	deltas := make([]ledgercore.StateDelta, initialBlocksCount)

	newAccts := make([]map[basics.Address]ledgercore.AccountData, len(accts))
	for idx, update := range accts {
		newAcct := make(map[basics.Address]ledgercore.AccountData, len(update))
		for addr, bad := range update {
			newAcct[addr] = ledgercore.ToAccountData(bad)
		}
		newAccts[idx] = newAcct
	}
	totals := accumulateTotals(t, consensusVersion, newAccts, 0)
	for i := range deltas {
		deltas[i] = ledgercore.StateDelta{
			Hdr:    &bookkeeping.BlockHeader{},
			Totals: totals,
		}
	}
	ml := &mockLedgerForTracker{
		dbs:      dbs,
		log:      l,
		filename: fileName,
		inMemory: inMemory,
		blocks:   blocks,
		deltas:   deltas, consensusParams: config.Consensus[consensusVersion],
		consensusVersion: consensusVersion,
		accts:            accts[0],
		trackers:         trackerRegistry{log: l},
	}
	return ml

}

func makeMockLedgerForTracker(t testing.TB, inMemory bool, initialBlocksCount basics.Round, consensusVersion protocol.ConsensusVersion, accts []map[basics.Address]basics.AccountData) *mockLedgerForTracker {
	dblogger := logging.TestingLog(t)
	dblogger.SetLevel(logging.Info)

	return makeMockLedgerForTrackerWithLogger(t, inMemory, initialBlocksCount, consensusVersion, accts, dblogger)
}

// fork creates another database which has the same content as the current one. Works only for non-memory databases.
func (ml *mockLedgerForTracker) fork(t testing.TB) *mockLedgerForTracker {
	if ml.inMemory {
		return nil
	}
	// create a new random file name.
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())

	dblogger := logging.TestingLog(t)
	dblogger.SetLevel(logging.Info)
	newLedgerTracker := &mockLedgerForTracker{
		inMemory:         false,
		log:              dblogger,
		blocks:           make([]blockEntry, len(ml.blocks)),
		deltas:           make([]ledgercore.StateDelta, len(ml.deltas)),
		accts:            maps.Clone(ml.accts),
		filename:         fn,
		consensusParams:  ml.consensusParams,
		consensusVersion: ml.consensusVersion,
		trackers:         trackerRegistry{log: dblogger},
	}
	copy(newLedgerTracker.blocks, ml.blocks)
	copy(newLedgerTracker.deltas, ml.deltas)

	// calling Vacuum implies flushing the database content to disk..
	ml.dbs.Vacuum(context.Background())
	// copy the database files.
	for _, ext := range []string{"", "-shm", "-wal"} {
		bytes, err := os.ReadFile(ml.filename + ext)
		require.NoError(t, err)
		err = os.WriteFile(newLedgerTracker.filename+ext, bytes, 0600)
		require.NoError(t, err)
	}
	dbs, err := db.OpenPair(newLedgerTracker.filename, false)
	require.NoError(t, err)
	dbs.Rdb.SetLogger(dblogger)
	dbs.Wdb.SetLogger(dblogger)

	newLedgerTracker.dbs = sqlitedriver.MakeStore(dbs)
	return newLedgerTracker
}

func (ml *mockLedgerForTracker) Close() {
	ml.trackers.close()

	ml.dbs.Close()
	// delete the database files of non-memory instances.
	if !ml.inMemory {
		os.Remove(ml.filename)
		os.Remove(ml.filename + "-shm")
		os.Remove(ml.filename + "-wal")
	}
}

func (ml *mockLedgerForTracker) Latest() basics.Round {
	ml.mu.RLock()
	defer ml.mu.RUnlock()
	return basics.Round(len(ml.blocks)) - 1
}

func (ml *mockLedgerForTracker) addBlock(be blockEntry, delta ledgercore.StateDelta) {
	ml.addToBlockQueue(be, delta)
	ml.trackers.newBlock(be.block, delta)
}

func (ml *mockLedgerForTracker) addToBlockQueue(be blockEntry, delta ledgercore.StateDelta) {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	ml.blocks = append(ml.blocks, be)
	ml.deltas = append(ml.deltas, delta)
}

func (ml *mockLedgerForTracker) trackerEvalVerified(blk bookkeeping.Block, accUpdatesLedger eval.LedgerForEvaluator) (ledgercore.StateDelta, error) {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	// support returning the deltas if the client explicitly provided them by calling addToBlockQueue, otherwise,
	// just return an empty state delta ( since the client clearly didn't care about these )
	if len(ml.deltas) > int(blk.Round()) {
		return ml.deltas[uint64(blk.Round())], nil
	}
	return ledgercore.StateDelta{
		Hdr: &bookkeeping.BlockHeader{},
	}, nil
}

func (ml *mockLedgerForTracker) Block(rnd basics.Round) (bookkeeping.Block, error) {
	if rnd > ml.Latest() {
		return bookkeeping.Block{}, fmt.Errorf("rnd %d out of bounds", rnd)
	}

	ml.mu.Lock()
	defer ml.mu.Unlock()

	return ml.blocks[int(rnd)].block, nil
}

func (ml *mockLedgerForTracker) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	if rnd > ml.Latest() {
		return bookkeeping.BlockHeader{}, fmt.Errorf("rnd %d out of bounds", rnd)
	}

	ml.mu.RLock()
	defer ml.mu.RUnlock()

	return ml.blocks[int(rnd)].block.BlockHeader, nil
}

func (ml *mockLedgerForTracker) trackerDB() trackerdb.Store {
	return ml.dbs
}

func (ml *mockLedgerForTracker) blockDB() db.Pair {
	return db.Pair{}
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
	return ml.consensusParams
}

func (ml *mockLedgerForTracker) GenesisProtoVersion() protocol.ConsensusVersion {
	return ml.consensusVersion
}

func (ml *mockLedgerForTracker) GenesisAccounts() map[basics.Address]basics.AccountData {
	return ml.accts
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

	err = au.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) error {
		var err0 error
		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}
		bals, err0 = ar.Testing().AccountsAllTest()
		return err0
	})
	if err != nil {
		return
	}

	for offset := uint64(0); offset < offsetLimit; offset++ {
		deltas := au.deltas[offset]
		bals = ledgercore.AccumulateDeltas(bals, deltas.Accts)
	}
	return
}

func newAcctUpdates(tb testing.TB, l *mockLedgerForTracker, conf config.Local) (*accountUpdates, *onlineAccounts) {
	au := &accountUpdates{}
	au.initialize(conf)
	ao := &onlineAccounts{}
	ao.initialize(conf)

	_, err := trackerDBInitialize(l, false, ".")
	require.NoError(tb, err)

	err = l.trackers.initialize(l, []ledgerTracker{au, ao, &txTail{}}, conf)
	require.NoError(tb, err)
	err = l.trackers.loadFromDisk(l)
	require.NoError(tb, err)

	return au, ao
}

func checkAcctUpdates(t *testing.T, au *accountUpdates, ao *onlineAccounts, base basics.Round, latestRnd basics.Round, accts []map[basics.Address]basics.AccountData, rewards []uint64, proto config.ConsensusParams) {
	latest := au.latest()
	require.Equal(t, latestRnd, latest)

	// the log has "onlineAccounts failed to fetch online totals for rnd" warning that is expected
	_, err := ao.onlineCirculation(latest+1, latest+1+basics.Round(ao.maxBalLookback()))
	require.Error(t, err)

	var validThrough basics.Round
	_, validThrough, err = au.LookupWithoutRewards(latest+1, ledgertesting.RandomAddress())
	require.Error(t, err)
	require.Zero(t, validThrough)

	if base > 0 && base >= basics.Round(ao.maxBalLookback()) {
		rnd := base - basics.Round(ao.maxBalLookback())
		_, err := ao.onlineCirculation(rnd, base)
		require.Error(t, err)

		_, validThrough, err = au.LookupWithoutRewards(base-1, ledgertesting.RandomAddress())
		require.Error(t, err)
		require.Zero(t, validThrough)
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
				require.Equal(t, d, ledgercore.ToAccountData(data))
				require.GreaterOrEqualf(t, uint64(validThrough), uint64(rnd), fmt.Sprintf("validThrough :%v\nrnd :%v\n", validThrough, rnd))
				// TODO: make lookupOnlineAccountData returning extended version of ledgercore.VotingData ?
				od, err := ao.lookupOnlineAccountData(rnd, addr)
				require.NoError(t, err)

				// If lookupOnlineAccountData returned something, it should agree with `data`.
				if !od.VoteID.IsEmpty() {
					require.Equal(t, od.VoteID, data.VoteID)
					require.Equal(t, od.SelectionID, data.SelectionID)
					require.Equal(t, od.VoteFirstValid, data.VoteFirstValid)
					require.Equal(t, od.VoteLastValid, data.VoteLastValid)
					require.Equal(t, od.VoteKeyDilution, data.VoteKeyDilution)
				}

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
			bll := accts[rnd]
			require.Equal(t, all, bll)

			totals, err := ao.onlineCirculation(rnd, rnd+basics.Round(ao.maxBalLookback()))
			require.NoError(t, err)
			require.Equal(t, totals.Raw, totalOnline)

			auTotals, err := au.onlineTotals(rnd)
			require.NoError(t, err)
			require.Equal(t, totals.Raw, auTotals.Raw)

			d, validThrough, err := au.LookupWithoutRewards(rnd, ledgertesting.RandomAddress())
			require.NoError(t, err)
			require.GreaterOrEqualf(t, uint64(validThrough), uint64(rnd), fmt.Sprintf("validThrough :%v\nrnd :%v\n", validThrough, rnd))
			require.Equal(t, d, ledgercore.AccountData{})
			od, err := ao.lookupOnlineAccountData(rnd, ledgertesting.RandomAddress())
			require.NoError(t, err)
			require.Equal(t, od, basics.OnlineAccountData{})
		}
	}
	checkAcctUpdatesConsistency(t, au, latestRnd)
	checkOnlineAcctUpdatesConsistency(t, ao, latestRnd)
}

func checkAcctUpdatesConsistency(t *testing.T, au *accountUpdates, rnd basics.Round) {
	accounts := make(map[basics.Address]modifiedAccount)
	resources := make(resourcesUpdates)

	for _, sdelta := range au.deltas {
		rdelta := sdelta.Accts
		for i := 0; i < rdelta.Len(); i++ {
			addr, adelta := rdelta.GetByIdx(i)
			macct := accounts[addr]
			macct.data = adelta
			macct.ndeltas++
			accounts[addr] = macct
		}

		for _, rec := range rdelta.GetAllAppResources() {
			key := accountCreatable{rec.Addr, basics.CreatableIndex(rec.Aidx)}
			entry, _ := resources.get(key)
			entry.resource.AppLocalState = rec.State.LocalState
			entry.resource.AppParams = rec.Params.Params
			entry.ndeltas++
			resources[key] = entry
		}
		for _, rec := range rdelta.GetAllAssetResources() {
			key := accountCreatable{rec.Addr, basics.CreatableIndex(rec.Aidx)}
			entry, _ := resources.get(key)
			entry.resource.AssetHolding = rec.Holding.Holding
			entry.resource.AssetParams = rec.Params.Params
			entry.ndeltas++
			resources[key] = entry
		}
	}

	require.Equal(t, au.accounts, accounts)
	require.Equal(t, au.resources, resources)

	latest := au.deltas[len(au.deltas)-1].Accts
	for i := 0; i < latest.Len(); i++ {
		addr, acct := latest.GetByIdx(i)
		d, r, withoutRewards, err := au.lookupLatest(addr)
		require.NoError(t, err)
		require.Equal(t, rnd, r)
		require.Equal(t, int(acct.TotalAppParams), len(d.AppParams))
		require.Equal(t, int(acct.TotalAssetParams), len(d.AssetParams))
		require.Equal(t, int(acct.TotalAppLocalStates), len(d.AppLocalStates))
		require.Equal(t, int(acct.TotalAssets), len(d.Assets))
		// check "withoutRewards" matches result of LookupWithoutRewards
		d2, r2, err2 := au.LookupWithoutRewards(r, addr)
		require.NoError(t, err2)
		require.Equal(t, r2, r)
		require.Equal(t, withoutRewards, d2.MicroAlgos)
	}
}

func checkOnlineAcctUpdatesConsistency(t *testing.T, ao *onlineAccounts, rnd basics.Round) {
	accounts := make(map[basics.Address]modifiedOnlineAccount)

	for _, rdelta := range ao.deltas {
		for i := 0; i < rdelta.Len(); i++ {
			addr, adelta := rdelta.GetByIdx(i)
			macct := accounts[addr]
			macct.data = adelta
			macct.ndeltas++
			accounts[addr] = macct
		}
	}

	require.Equal(t, ao.accounts, accounts)

	latest := ao.deltas[len(ao.deltas)-1]
	for i := 0; i < latest.Len(); i++ {
		addr, acct := latest.GetByIdx(i)
		od, err := ao.lookupOnlineAccountData(rnd, addr)
		if od.VoteID.IsEmpty() {
			// suspended accounts will be in `latest` (from ao.deltas), but
			// `lookupOnlineAccountData` will return {}.
			continue
		}
		require.NoError(t, err)
		require.Equal(t, acct.VoteID, od.VoteID)
		require.Equal(t, acct.SelectionID, od.SelectionID)
		require.Equal(t, acct.VoteFirstValid, od.VoteFirstValid)
		require.Equal(t, acct.VoteLastValid, od.VoteLastValid)
		require.Equal(t, acct.VoteKeyDilution, od.VoteKeyDilution)
	}
}

func testAcctUpdates(t *testing.T, conf config.Local) {
	// The next operations are heavy on the memory.
	// Garbage collection helps prevent trashing
	runtime.GC()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	for _, lookback := range []uint64{conf.MaxAcctLookback, proto.MaxBalLookback} {
		t.Run(fmt.Sprintf("lookback=%d", lookback), func(t *testing.T) {

			conf.MaxAcctLookback = lookback

			accts := setupAccts(20)
			rewardsLevels := []uint64{0}
			initialBlocksCount := basics.Round(lookback)
			ml := makeMockLedgerForTracker(t, true, initialBlocksCount, protocol.ConsensusCurrentVersion, accts)
			defer ml.Close()

			au, ao := newAcctUpdates(t, ml, conf)
			// au and ao are closed via ml.Close() -> ml.trackers.close()

			// cover 10 genesis blocks
			rewardLevel := uint64(0)
			for i := 1; i < int(initialBlocksCount); i++ {
				accts = append(accts, accts[0])
				rewardsLevels = append(rewardsLevels, rewardLevel)
			}

			checkAcctUpdates(t, au, ao, 0, initialBlocksCount-1, accts, rewardsLevels, proto)

			// lastCreatableID stores asset or app max used index to get rid of conflicts
			lastCreatableID := basics.CreatableIndex(crypto.RandUint64() % 512)
			knownCreatables := make(map[basics.CreatableIndex]bool)

			maxLookback := conf.MaxAcctLookback

			start := basics.Round(initialBlocksCount)
			end := basics.Round(maxLookback + 15)
			for i := start; i < end; i++ {
				rewardLevelDelta := crypto.RandUint64() % 5
				rewardLevel += rewardLevelDelta
				var updates ledgercore.AccountDeltas
				var totals map[basics.Address]ledgercore.AccountData
				base := accts[i-1]
				updates, totals = ledgertesting.RandomDeltasBalancedFull(1, base, rewardLevel, &lastCreatableID)
				prevRound, prevTotals, err := au.LatestTotals()
				require.Equal(t, i-1, prevRound)
				require.NoError(t, err)

				newPool := totals[testPoolAddr]
				newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
				updates.Upsert(testPoolAddr, newPool)
				totals[testPoolAddr] = newPool
				newAccts := applyPartialDeltas(base, updates)

				blk := bookkeeping.Block{
					BlockHeader: bookkeeping.BlockHeader{
						Round: basics.Round(i),
					},
				}
				blk.RewardsLevel = rewardLevel
				blk.CurrentProtocol = protocol.ConsensusCurrentVersion

				delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
				delta.Accts.MergeAccounts(updates)
				delta.Creatables = creatablesFromUpdates(base, updates, knownCreatables)

				delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
				ml.addBlock(blockEntry{block: blk}, delta)
				accts = append(accts, newAccts)
				rewardsLevels = append(rewardsLevels, rewardLevel)

				// checkAcctUpdates is kind of slow because of amount of data it needs to compare
				// instead, compare at start, end in between approx 10 rounds
				if i == start || i == end-1 || crypto.RandUint64()%10 == 0 || lookback < 10 {
					checkAcctUpdates(t, au, ao, 0, i, accts, rewardsLevels, proto)
				}
			}
			for i := basics.Round(0); i < 15; i++ {
				// Clear the timer to ensure a flush
				ml.trackers.lastFlushTime = time.Time{}

				ml.trackers.committedUpTo(basics.Round(maxLookback) + i)
				ml.trackers.waitAccountsWriting()
				checkAcctUpdates(t, au, ao, i, basics.Round(maxLookback+14), accts, rewardsLevels, proto)
			}

			// check the account totals.
			var dbRound basics.Round
			err := ml.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
				ar, err := tx.MakeAccountsReader()
				if err != nil {
					return err
				}

				dbRound, err = ar.AccountsRound()
				return
			})
			require.NoError(t, err)

			var updates ledgercore.AccountDeltas
			for addr, acctData := range accts[dbRound] {
				updates.Upsert(addr, ledgercore.ToAccountData(acctData))
			}

			expectedTotals := ledgertesting.CalculateNewRoundAccountTotals(t, updates, rewardsLevels[dbRound], proto, nil, ledgercore.AccountTotals{})
			var actualTotals ledgercore.AccountTotals
			err = ml.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
				ar, err := tx.MakeAccountsReader()
				if err != nil {
					return err
				}

				actualTotals, err = ar.AccountsTotals(ctx, false)
				return
			})
			require.NoError(t, err)
			require.Equal(t, expectedTotals, actualTotals)
		})
	}
}

func TestAcctUpdates(t *testing.T) {
	partitiontest.PartitionTest(t)

	conf := config.GetDefaultLocal()
	ledgertesting.WithAndWithoutLRUCache(t, conf, testAcctUpdates)
}

func BenchmarkBalancesChanges(b *testing.B) {
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		b.Skip("This test is too slow on ARM and causes travis builds to time out")
	}
	if b.N < 100 {
		b.N = 50
	}
	protocolVersion := protocol.ConsensusCurrentVersion

	const initialRounds basics.Round = 1
	accountsCount := 5000
	accts := setupAccts(accountsCount)
	rewardsLevels := []uint64{0}

	ml := makeMockLedgerForTracker(b, true, initialRounds, protocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	maxAcctLookback := basics.Round(conf.MaxAcctLookback)
	au, _ := newAcctUpdates(b, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	// cover initialRounds genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < int(initialRounds); i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	for i := initialRounds; i < maxAcctLookback+basics.Round(b.N); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 0
		if i <= initialRounds+basics.Round(b.N) {
			accountChanges = accountsCount - 2 - int(maxAcctLookback+basics.Round(b.N)+i)
		}

		updates, totals := ledgertesting.RandomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(b, i-1, prevRound)
		require.NoError(b, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = protocolVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}
	for i := maxAcctLookback; i < maxAcctLookback+initialRounds; i++ {
		// Clear the timer to ensure a flush
		ml.trackers.lastFlushTime = time.Time{}
		ml.trackers.committedUpTo(basics.Round(i))
	}
	ml.trackers.waitAccountsWriting()
	b.ResetTimer()
	startTime := time.Now()
	for i := maxAcctLookback + initialRounds; i < maxAcctLookback+basics.Round(b.N); i++ {
		// Clear the timer to ensure a flush
		ml.trackers.lastFlushTime = time.Time{}
		ml.trackers.committedUpTo(i)
	}
	ml.trackers.waitAccountsWriting()
	deltaTime := time.Since(startTime)
	if deltaTime > time.Second {
		return
	}
	// we want to fake the N to reflect the time it took us, if we were to wait an entire second.
	singleIterationTime := deltaTime / time.Duration(uint64(basics.Round(b.N)-initialRounds))
	b.N = int(time.Second / singleIterationTime)
	// and now, wait for the reminder of the second.
	time.Sleep(time.Second - deltaTime)
}

func BenchmarkCalibrateNodesPerPage(b *testing.B) {
	b.Skip("This benchmark was used to tune up the NodesPerPage; it's not really useful otherwise")
	defaultNodesPerPage := trackerdb.MerkleCommitterNodesPerPage
	for nodesPerPage := 32; nodesPerPage < 300; nodesPerPage++ {
		b.Run(fmt.Sprintf("Test_merkleCommitterNodesPerPage_%d", nodesPerPage), func(b *testing.B) {
			trackerdb.MerkleCommitterNodesPerPage = int64(nodesPerPage)
			BenchmarkBalancesChanges(b)
		})
	}
	trackerdb.MerkleCommitterNodesPerPage = defaultNodesPerPage
}

func BenchmarkCalibrateCacheNodeSize(b *testing.B) {
	//b.Skip("This benchmark was used to tune up the TrieCachedNodesCount; it's not really useful otherwise")
	defaultTrieCachedNodesCount := trackerdb.TrieCachedNodesCount
	for cacheSize := 3000; cacheSize < 50000; cacheSize += 1000 {
		b.Run(fmt.Sprintf("Test_cacheSize_%d", cacheSize), func(b *testing.B) {
			trackerdb.TrieCachedNodesCount = cacheSize
			BenchmarkBalancesChanges(b)
		})
	}
	trackerdb.TrieCachedNodesCount = defaultTrieCachedNodesCount
}

// The TestAcctUpdatesUpdatesCorrectness conduct a correctless test for the accounts update in the following way -
// Each account is initialized with 100 algos.
// On every round, each account move variable amount of funds to an accumulating account.
// The deltas for each account are picked by using the lookup method.
// At the end of the test, we verify that each account has the expected amount of algos.
// In addition, throughout the test, we check ( using lookup ) that the historical balances, *beyond* the
// lookback are generating either an error, or returning the correct amount.
func TestAcctUpdatesUpdatesCorrectness(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfgLocal := config.GetDefaultLocal()
	ledgertesting.WithAndWithoutLRUCache(t, cfgLocal, testAcctUpdatesUpdatesCorrectness)
}

func testAcctUpdatesUpdatesCorrectness(t *testing.T, cfg config.Local) {
	// create new protocol version, which has lower look back.
	testProtocolVersion := protocol.ConsensusCurrentVersion
	maxAcctLookback := cfg.MaxAcctLookback
	inMemory := true

	testFunction := func(t *testing.T) {
		accts := setupAccts(9)
		ml := makeMockLedgerForTracker(t, inMemory, 10, testProtocolVersion, accts)
		defer ml.Close()

		var moneyAccounts []basics.Address

		for addr := range accts[0] {
			if bytes.Equal(addr[:], testPoolAddr[:]) || bytes.Equal(addr[:], testSinkAddr[:]) {
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

		au, _ := newAcctUpdates(t, ml, cfg)
		// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

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
			updates := make(map[basics.Address]ledgercore.AccountData)
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
				updates[fromAccount] = fromAccountDataNew

				moneyAccountsExpectedAmounts[i][j] = fromAccountDataNew.MicroAlgos.Raw
			}

			moneyAccountsExpectedAmounts[i][0] = moneyAccountsExpectedAmounts[i-1][0] + uint64(len(moneyAccounts)-1)*uint64(i-10)

			// force to perform a test that goes directly to disk, and see if it has the expected values.
			if uint64(i) > maxAcctLookback+3 {

				// check the status at a historical time:
				checkRound := uint64(i) - maxAcctLookback - 2

				testback := 1
				for j := 1; j < len(moneyAccounts); j++ {
					if checkRound < uint64(testback) {
						continue
					}
					acct, validThrough, err := au.LookupWithoutRewards(basics.Round(checkRound-uint64(testback)), moneyAccounts[j])
					// we might get an error like "round 2 before dbRound 5", which is the success case, so we'll ignore it.
					roundOffsetError := &RoundOffsetError{}
					if errors.As(err, &roundOffsetError) {
						require.Zero(t, validThrough)
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

			updates[toAccount] = toAccountDataNew

			blk := bookkeeping.Block{
				BlockHeader: bookkeeping.BlockHeader{
					Round: basics.Round(i),
				},
			}
			blk.RewardsLevel = rewardLevel
			blk.CurrentProtocol = testProtocolVersion

			delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, len(updates), 0)
			for addr, ad := range updates {
				delta.Accts.Upsert(addr, ad)
			}
			ml.addBlock(blockEntry{block: blk}, delta)
			ml.trackers.committedUpTo(i)
		}
		lastRound := i - 1
		ml.trackers.waitAccountsWriting()

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

func TestBoxNamesByAppIDs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const initialBlocksCount = 1
	accts := make(map[basics.Address]basics.AccountData)

	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]

	ml := makeMockLedgerForTracker(t, true, initialBlocksCount, protocol.ConsensusCurrentVersion,
		[]map[basics.Address]basics.AccountData{accts},
	)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	knownCreatables := make(map[basics.CreatableIndex]bool)
	opts := auNewBlockOpts{ledgercore.AccountDeltas{}, protocol.ConsensusCurrentVersion, protoParams, knownCreatables}

	testingBoxNames := []string{
		` `,
		`     	`,
		` % `,
		` ? = % ;`,
		`; DROP *;`,
		`OR 1 = 1;`,
		`"      ;  SELECT * FROM kvstore; DROP acctrounds; `,
		`; SELECT key from kvstore WHERE key LIKE %;`,
		`?&%!=`,
		"SELECT * FROM kvstore " + string([]byte{0, 0}) + " WHERE key LIKE %; ",
		`b64:APj/AA==`,
		`str:123.3/aa\\0`,
		string([]byte{0, 255, 254, 254}),
		string([]byte{0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}),
		string([]byte{'%', 'a', 'b', 'c', 0, 0, '%', 'a', '!'}),
		`
`,
		`™£´´∂ƒ∂ƒßƒ©∑®ƒß∂†¬∆`,
		`∑´´˙©˚¬∆ßåƒ√¬`,
		`背负青天而莫之夭阏者，而后乃今将图南。`,
		`於浩歌狂熱之際中寒﹔於天上看見深淵。`,
		`於一切眼中看見無所有﹔於無所希望中得救。`,
		`有一遊魂，化為長蛇，口有毒牙。`,
		`不以嚙人，自嚙其身，終以殞顛。`,
		`那些智力超常的人啊`,
		`认为已经，熟悉了云和闪电的脾气`,
		`就不再迷惑，就不必了解自己，世界和他人`,
		`每天只管，被微风吹拂，与猛虎谈情`,
		`他们从来，不需要楼梯，只有窗口`,
		`把一切交付于梦境，和优美的浪潮`,
		`在这颗行星所有的酒馆，青春自由似乎理所应得`,
		`面向涣散的未来，只唱情歌，看不到坦克`,
		`在科学和啤酒都不能安抚的夜晚`,
		`他们丢失了四季，惶惑之行开始`,
		`这颗行星所有的酒馆，无法听到远方的呼喊`,
		`野心勃勃的灯火，瞬间吞没黑暗的脸庞`,
	}

	appIDset := make(map[basics.AppIndex]struct{}, len(testingBoxNames))
	boxNameToAppID := make(map[string]basics.AppIndex, len(testingBoxNames))
	var currentRound basics.Round

	// keep adding one box key and one random appID (non-duplicated)
	for i, boxName := range testingBoxNames {
		currentRound = basics.Round(i + 1)

		var appID basics.AppIndex
		for {
			appID = basics.AppIndex(crypto.RandUint64())
			_, preExisting := appIDset[appID]
			if !preExisting {
				break
			}
		}

		appIDset[appID] = struct{}{}
		boxNameToAppID[boxName] = appID

		boxChange := ledgercore.KvValueDelta{Data: []byte(boxName)}
		auNewBlock(t, currentRound, au, accts, opts, map[string]ledgercore.KvValueDelta{
			apps.MakeBoxKey(uint64(appID), boxName): boxChange,
		})
		auCommitSync(t, currentRound, au, ml)

		// ensure rounds
		rnd := au.latest()
		require.Equal(t, currentRound, rnd)
		if uint64(currentRound) > conf.MaxAcctLookback {
			require.Equal(t, basics.Round(uint64(currentRound)-conf.MaxAcctLookback), au.cachedDBRound)
		} else {
			require.Equal(t, basics.Round(0), au.cachedDBRound)
		}

		// check input, see all present keys are all still there
		for _, storedBoxName := range testingBoxNames[:i+1] {
			res, err := au.LookupKeysByPrefix(currentRound, apps.MakeBoxKey(uint64(boxNameToAppID[storedBoxName]), ""), 10000)
			require.NoError(t, err)
			require.Len(t, res, 1)
			require.Equal(t, apps.MakeBoxKey(uint64(boxNameToAppID[storedBoxName]), storedBoxName), res[0])
		}
	}

	// removing inserted boxes
	for _, boxName := range testingBoxNames {
		currentRound++

		// remove inserted box
		appID := boxNameToAppID[boxName]
		auNewBlock(t, currentRound, au, accts, opts, map[string]ledgercore.KvValueDelta{
			apps.MakeBoxKey(uint64(appID), boxName): {},
		})
		auCommitSync(t, currentRound, au, ml)

		// ensure recently removed key is not present, and it is not part of the result
		res, err := au.LookupKeysByPrefix(currentRound, apps.MakeBoxKey(uint64(boxNameToAppID[boxName]), ""), 10000)
		require.NoError(t, err)
		require.Len(t, res, 0)
	}
}

func TestKVCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const initialBlocksCount = 1
	accts := make(map[basics.Address]basics.AccountData)

	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	ml := makeMockLedgerForTracker(t, true, initialBlocksCount, protocol.ConsensusCurrentVersion,
		[]map[basics.Address]basics.AccountData{accts},
	)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	knownCreatables := make(map[basics.CreatableIndex]bool)
	opts := auNewBlockOpts{ledgercore.AccountDeltas{}, protocol.ConsensusCurrentVersion, protoParams, knownCreatables}

	kvCnt := 1000
	kvsPerBlock := 100
	curKV := 0
	var currentRound basics.Round
	currentDBRound := basics.Round(1)

	kvMap := make(map[string][]byte)
	for i := 0; i < kvCnt; i++ {
		kvMap[fmt.Sprintf("%d", i)] = []byte(fmt.Sprintf("value%d", i))
	}

	// add kvsPerBlock KVs on each iteration. The first kvCnt/kvsPerBlock
	// iterations produce a block with kvCnt kv manipulations. The last
	// conf.MaxAcctLookback iterations are meant to verify the contents of the cache
	// are correct after every kv containing block has been committed.
	for i := 0; i < kvCnt/kvsPerBlock+int(conf.MaxAcctLookback); i++ {
		currentRound = currentRound + 1
		kvMods := make(map[string]ledgercore.KvValueDelta)
		if i < kvCnt/kvsPerBlock {
			for j := 0; j < kvsPerBlock; j++ {
				name := fmt.Sprintf("%d", curKV)
				curKV++
				val := kvMap[name]
				kvMods[name] = ledgercore.KvValueDelta{Data: val, OldData: nil}
			}
		}

		auNewBlock(t, currentRound, au, accts, opts, kvMods)
		auCommitSync(t, currentRound, au, ml)

		// ensure rounds
		rnd := au.latest()
		require.Equal(t, currentRound, rnd)
		if uint64(currentRound) > conf.MaxAcctLookback {
			require.Equal(t, basics.Round(uint64(currentRound)-conf.MaxAcctLookback), au.cachedDBRound)
		} else {
			require.Equal(t, basics.Round(0), au.cachedDBRound)
		}

		// verify cache doesn't contain the new kvs until committed to DB.
		for name := range kvMods {
			_, has := au.baseKVs.read(name)
			require.False(t, has)
		}

		// verify commited kvs appear in the kv cache
		for ; currentDBRound <= au.cachedDBRound; currentDBRound++ {
			startKV := (currentDBRound - 1) * basics.Round(kvsPerBlock)
			for j := 0; j < kvsPerBlock; j++ {
				name := fmt.Sprintf("%d", uint64(startKV)+uint64(j))
				persistedValue, has := au.baseKVs.read(name)
				require.True(t, has)
				require.Equal(t, kvMap[name], persistedValue.Value)
			}
		}
	}

	// updating inserted KVs
	curKV = 0
	for i := 0; i < kvCnt/kvsPerBlock+int(conf.MaxAcctLookback); i++ {
		currentRound = currentRound + 1

		kvMods := make(map[string]ledgercore.KvValueDelta)
		if i < kvCnt/kvsPerBlock {
			for j := 0; j < kvsPerBlock; j++ {
				name := fmt.Sprintf("%d", curKV)
				val := fmt.Sprintf("modified value%d", curKV)
				kvMods[name] = ledgercore.KvValueDelta{Data: []byte(val)}
				curKV++
			}
		}

		auNewBlock(t, currentRound, au, accts, opts, kvMods)
		auCommitSync(t, currentRound, au, ml)

		// ensure rounds
		rnd := au.latest()
		require.Equal(t, currentRound, rnd)
		require.Equal(t, basics.Round(uint64(currentRound)-conf.MaxAcctLookback), au.cachedDBRound)

		// verify cache doesn't contain updated kv values that haven't been committed to db
		if i < kvCnt/kvsPerBlock {
			for name := range kvMods {
				persistedValue, has := au.baseKVs.read(name)
				require.True(t, has)
				require.Equal(t, kvMap[name], persistedValue.Value)
			}
		}

		// verify commited updated kv values appear in the kv cache
		for ; currentDBRound <= au.cachedDBRound; currentDBRound++ {
			lookback := basics.Round(kvCnt/kvsPerBlock + int(conf.MaxAcctLookback) + 1)
			if currentDBRound < lookback {
				continue
			}

			startKV := (currentDBRound - lookback) * basics.Round(kvsPerBlock)
			for j := 0; j < kvsPerBlock; j++ {
				name := fmt.Sprintf("%d", uint64(startKV)+uint64(j))
				persistedValue, has := au.baseKVs.read(name)
				require.True(t, has)
				expectedValue := fmt.Sprintf("modified value%s", name)
				require.Equal(t, expectedValue, string(persistedValue.Value))
			}
		}
	}

	// deleting KVs
	curKV = 0
	for i := 0; i < kvCnt/kvsPerBlock+int(conf.MaxAcctLookback); i++ {
		currentRound = currentRound + 1

		kvMods := make(map[string]ledgercore.KvValueDelta)
		if i < kvCnt/kvsPerBlock {
			for j := 0; j < kvsPerBlock; j++ {
				name := fmt.Sprintf("%d", curKV)
				// needs an old data, else optimized away.
				// if oldData = "" there is the best chance of a bug, so we use that
				kvMods[name] = ledgercore.KvValueDelta{Data: nil, OldData: []byte("")}
				curKV++
			}
		}

		auNewBlock(t, currentRound, au, accts, opts, kvMods)
		auCommitSync(t, currentRound, au, ml)

		// ensure rounds
		rnd := au.latest()
		require.Equal(t, currentRound, rnd)
		require.Equal(t, basics.Round(uint64(currentRound)-conf.MaxAcctLookback), au.cachedDBRound)

		// verify cache doesn't contain updated kv values that haven't been committed to db
		if i < kvCnt/kvsPerBlock {
			for name := range kvMods {
				persistedValue, has := au.baseKVs.read(name)
				require.True(t, has)
				value := fmt.Sprintf("modified value%s", name)
				require.Equal(t, value, string(persistedValue.Value))
			}
		}

		// verify commited updated kv values appear in the kv cache
		for ; currentDBRound <= au.cachedDBRound; currentDBRound++ {
			lookback := basics.Round(2*(kvCnt/kvsPerBlock+int(conf.MaxAcctLookback)) + 1)
			if currentDBRound < lookback {
				continue
			}

			startKV := (currentDBRound - lookback) * basics.Round(kvsPerBlock)
			for j := 0; j < kvsPerBlock; j++ {
				name := fmt.Sprintf("%d", uint64(startKV)+uint64(j))
				persistedValue, has := au.baseKVs.read(name)
				require.True(t, has)
				require.True(t, persistedValue.Value == nil)
			}
		}
	}
}

func BenchmarkLargeMerkleTrieRebuild(b *testing.B) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	accts := setupAccts(5)
	ml := makeMockLedgerForTracker(b, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	au, _ := newAcctUpdates(b, ml, cfg)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	// at this point, the database was created. We want to fill the accounts data
	accountsNumber := 6000000 * b.N
	for i := 0; i < accountsNumber-5-2; { // subtract the account we've already created above, plus the sink/reward
		var updates compactAccountDeltas
		for k := 0; i < accountsNumber-5-2 && k < 1024; k++ {
			addr := ledgertesting.RandomAddress()
			acctData := trackerdb.BaseAccountData{}
			acctData.MicroAlgos.Raw = 1
			updates.upsert(addr, accountDelta{newAcct: acctData})
			i++
		}

		err := ml.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
			_, _, _, err = accountsNewRound(tx, updates, compactResourcesDeltas{}, nil, nil, proto, basics.Round(1))
			return
		})
		require.NoError(b, err)
	}

	err := ml.dbs.Batch(func(ctx context.Context, tx trackerdb.BatchScope) (err error) {
		aw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		return aw.UpdateAccountsHashRound(ctx, 1)
	})
	require.NoError(b, err)

	au.close()

	b.ResetTimer()
	err = au.loadFromDisk(ml, 0)
	require.NoError(b, err)
	b.StopTimer()
	b.ReportMetric(float64(accountsNumber), "entries/trie")
}

func BenchmarkCompactDeltas(b *testing.B) {
	b.Run("account-deltas", func(b *testing.B) {
		if b.N < 500 {
			b.N = 500
		}
		window := 5000
		stateDeltas := make([]ledgercore.StateDelta, b.N)
		addrs := make([]basics.Address, b.N*window)
		for i := 0; i < len(addrs); i++ {
			addrs[i] = basics.Address(crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}))
		}
		for rnd := 0; rnd < b.N; rnd++ {
			m := make(map[basics.Address]basics.AccountData)
			start := 0
			if rnd > 0 {
				start = window/2 + (rnd-1)*window
			}
			for k := start; k < start+window; k++ {
				stateDeltas[rnd].Accts.Upsert(addrs[k], ledgercore.AccountData{})
				m[addrs[k]] = basics.AccountData{}
			}
		}
		var baseAccounts lruAccounts
		baseAccounts.init(nil, 100, 80)
		b.ResetTimer()

		makeCompactAccountDeltas(stateDeltas, 0, false, baseAccounts)

	})
}
func TestCompactDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	addrs := make([]basics.Address, 10)
	for i := 0; i < len(addrs); i++ {
		addrs[i] = basics.Address(crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}))
	}

	stateDeltas := make([]ledgercore.StateDelta, 1)
	stateDeltas[0].Creatables = make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	stateDeltas[0].Accts.Upsert(addrs[0], ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 2}}})
	stateDeltas[0].Creatables[100] = ledgercore.ModifiedCreatable{Creator: addrs[2], Created: true}
	var baseAccounts lruAccounts
	baseAccounts.init(nil, 100, 80)
	outAccountDeltas := makeCompactAccountDeltas(stateDeltas, 1, true, baseAccounts)
	outCreatableDeltas := compactCreatableDeltas(stateDeltas)

	require.Equal(t, stateDeltas[0].Accts.Len(), outAccountDeltas.len())
	require.Equal(t, len(stateDeltas[0].Creatables), len(outCreatableDeltas))
	require.Equal(t, stateDeltas[0].Accts.Len(), len(outAccountDeltas.misses))

	// check deltas with missing accounts
	delta, _ := outAccountDeltas.get(addrs[0])
	require.Equal(t, trackerdb.PersistedAccountData{}, delta.oldAcct)
	require.NotEmpty(t, delta.newAcct)
	require.Equal(t, ledgercore.ModifiedCreatable{Creator: addrs[2], Created: true, Ndeltas: 1}, outCreatableDeltas[100])

	// check deltas without missing accounts
	baseAccounts.write(trackerdb.PersistedAccountData{Addr: addrs[0], AccountData: trackerdb.BaseAccountData{}})
	outAccountDeltas = makeCompactAccountDeltas(stateDeltas, basics.Round(1), true, baseAccounts)
	require.Equal(t, 0, len(outAccountDeltas.misses))
	delta, _ = outAccountDeltas.get(addrs[0])
	require.Equal(t, trackerdb.PersistedAccountData{Addr: addrs[0]}, delta.oldAcct)
	require.Equal(t, trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 2}, UpdateRound: 2}, delta.newAcct)
	require.Equal(t, ledgercore.ModifiedCreatable{Creator: addrs[2], Created: true, Ndeltas: 1}, outCreatableDeltas[100])
	baseAccounts.init(nil, 100, 80)

	// add another round
	stateDeltas = append(stateDeltas, ledgercore.StateDelta{Creatables: make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)})
	stateDeltas[1].Accts.Upsert(addrs[0], ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 3}}})
	stateDeltas[1].Accts.Upsert(addrs[3], ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 8}}})

	stateDeltas[1].Creatables[100] = ledgercore.ModifiedCreatable{Creator: addrs[2], Created: false}
	stateDeltas[1].Creatables[101] = ledgercore.ModifiedCreatable{Creator: addrs[4], Created: true}

	baseAccounts.write(trackerdb.PersistedAccountData{Addr: addrs[0], AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 1}}})
	baseAccounts.write(trackerdb.PersistedAccountData{Addr: addrs[3], AccountData: trackerdb.BaseAccountData{}})
	outAccountDeltas = makeCompactAccountDeltas(stateDeltas, 1, true, baseAccounts)
	outCreatableDeltas = compactCreatableDeltas(stateDeltas)

	require.Equal(t, 2, outAccountDeltas.len())
	require.Equal(t, 2, len(outCreatableDeltas))

	delta, _ = outAccountDeltas.get(addrs[0])
	require.Equal(t, uint64(1), delta.oldAcct.AccountData.MicroAlgos.Raw)
	require.Equal(t, uint64(3), delta.newAcct.MicroAlgos.Raw)
	require.Equal(t, int(2), delta.nAcctDeltas)
	delta, _ = outAccountDeltas.get(addrs[3])
	require.Equal(t, uint64(0), delta.oldAcct.AccountData.MicroAlgos.Raw)
	require.Equal(t, uint64(8), delta.newAcct.MicroAlgos.Raw)
	require.Equal(t, int(1), delta.nAcctDeltas)

	require.Equal(t, addrs[2], outCreatableDeltas[100].Creator)
	require.Equal(t, addrs[4], outCreatableDeltas[101].Creator)
	require.Equal(t, false, outCreatableDeltas[100].Created)
	require.Equal(t, true, outCreatableDeltas[101].Created)
	require.Equal(t, 2, outCreatableDeltas[100].Ndeltas)
	require.Equal(t, 1, outCreatableDeltas[101].Ndeltas)
}

func TestCompactDeltasResources(t *testing.T) {
	partitiontest.PartitionTest(t)

	addrs := make([]basics.Address, 10)
	for i := 0; i < len(addrs); i++ {
		addrs[i] = basics.Address(crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}))
	}

	var baseAccounts lruAccounts
	var baseResources lruResources
	baseResources.init(nil, 100, 80)

	// check empty deltas do no produce empty resourcesData records
	stateDeltas := make([]ledgercore.StateDelta, 1)
	stateDeltas[0].Accts.UpsertAppResource(addrs[0], 100, ledgercore.AppParamsDelta{Deleted: true}, ledgercore.AppLocalStateDelta{})
	stateDeltas[0].Accts.UpsertAppResource(addrs[1], 101, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{Deleted: true})
	stateDeltas[0].Accts.UpsertAssetResource(addrs[2], 102, ledgercore.AssetParamsDelta{Deleted: true}, ledgercore.AssetHoldingDelta{})
	stateDeltas[0].Accts.UpsertAssetResource(addrs[3], 103, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Deleted: true})

	outResourcesDeltas := makeCompactResourceDeltas(stateDeltas, basics.Round(1), true, baseAccounts, baseResources)
	delta, _ := outResourcesDeltas.get(addrs[0], 100)
	require.NotEmpty(t, delta.newResource)
	require.True(t, !delta.newResource.IsApp() && !delta.newResource.IsAsset())
	require.Equal(t, trackerdb.ResourceFlagsNotHolding, delta.newResource.ResourceFlags)

	delta, _ = outResourcesDeltas.get(addrs[1], 101)
	require.NotEmpty(t, delta.newResource)
	require.True(t, !delta.newResource.IsApp() && !delta.newResource.IsAsset())
	require.Equal(t, trackerdb.ResourceFlagsNotHolding, delta.newResource.ResourceFlags)

	delta, _ = outResourcesDeltas.get(addrs[2], 102)
	require.NotEmpty(t, delta.newResource)
	require.True(t, !delta.newResource.IsApp() && !delta.newResource.IsAsset())
	require.Equal(t, trackerdb.ResourceFlagsNotHolding, delta.newResource.ResourceFlags)

	delta, _ = outResourcesDeltas.get(addrs[3], 103)
	require.NotEmpty(t, delta.newResource)
	require.True(t, !delta.newResource.IsApp() && !delta.newResource.IsAsset())
	require.Equal(t, trackerdb.ResourceFlagsNotHolding, delta.newResource.ResourceFlags)

	// check actual data on non-empty input
	stateDeltas = make([]ledgercore.StateDelta, 1)
	// addr 0 has app params and a local state for another app
	appParams100 := basics.AppParams{ApprovalProgram: []byte{100}}
	appLocalState200 := basics.AppLocalState{KeyValue: basics.TealKeyValue{"200": basics.TealValue{Type: basics.TealBytesType, Bytes: "200"}}}
	stateDeltas[0].Accts.UpsertAppResource(addrs[0], 100, ledgercore.AppParamsDelta{Params: &appParams100}, ledgercore.AppLocalStateDelta{})
	stateDeltas[0].Accts.UpsertAppResource(addrs[0], 200, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{LocalState: &appLocalState200})

	// addr 1 has app params and a local state for the same app
	appParams101 := basics.AppParams{ApprovalProgram: []byte{101}}
	appLocalState101 := basics.AppLocalState{KeyValue: basics.TealKeyValue{"101": basics.TealValue{Type: basics.TealBytesType, Bytes: "101"}}}
	stateDeltas[0].Accts.UpsertAppResource(addrs[1], 101, ledgercore.AppParamsDelta{Params: &appParams101}, ledgercore.AppLocalStateDelta{LocalState: &appLocalState101})

	// addr 2 has asset params and a holding for another asset
	assetParams102 := basics.AssetParams{Total: 102}
	assetHolding202 := basics.AssetHolding{Amount: 202}
	stateDeltas[0].Accts.UpsertAssetResource(addrs[2], 102, ledgercore.AssetParamsDelta{Params: &assetParams102}, ledgercore.AssetHoldingDelta{})
	stateDeltas[0].Accts.UpsertAssetResource(addrs[2], 202, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &assetHolding202})

	// addr 3 has asset params and a holding for the same asset
	assetParams103 := basics.AssetParams{Total: 103}
	assetHolding103 := basics.AssetHolding{Amount: 103}
	stateDeltas[0].Accts.UpsertAssetResource(addrs[3], 103, ledgercore.AssetParamsDelta{Params: &assetParams103}, ledgercore.AssetHoldingDelta{Holding: &assetHolding103})

	baseResources.init(nil, 100, 80)

	outResourcesDeltas = makeCompactResourceDeltas(stateDeltas, 1, true, baseAccounts, baseResources)
	// 6 entries are missing: same app (asset) params and local state are combined into a single entry
	require.Equal(t, 6, len(outResourcesDeltas.misses))
	require.Equal(t, 6, len(outResourcesDeltas.deltas))

	// check deltas with missing accounts

	checkNewDeltas := func(outResourcesDeltas compactResourcesDeltas) {
		delta, _ := outResourcesDeltas.get(addrs[0], 100)
		require.NotEmpty(t, delta.newResource)
		require.Equal(t, appParams100.ApprovalProgram, delta.newResource.ApprovalProgram)
		// do not check delta.nAcctDeltas since checkNewDeltas func is reused and this entry gets modified

		delta, _ = outResourcesDeltas.get(addrs[0], 200)
		require.NotEmpty(t, delta.newResource)
		require.Equal(t, appLocalState200.KeyValue, delta.newResource.GetAppLocalState().KeyValue)
		require.Equal(t, int(1), delta.nAcctDeltas)

		delta, _ = outResourcesDeltas.get(addrs[1], 101)
		require.NotEmpty(t, delta.newResource)
		require.Equal(t, appParams101.ApprovalProgram, delta.newResource.ApprovalProgram)
		require.Equal(t, appLocalState101.KeyValue, delta.newResource.GetAppLocalState().KeyValue)
		require.Equal(t, int(1), delta.nAcctDeltas)

		delta, _ = outResourcesDeltas.get(addrs[2], 102)
		require.NotEmpty(t, delta.newResource)
		require.Equal(t, assetParams102.Total, delta.newResource.Total)
		require.Equal(t, int(1), delta.nAcctDeltas)
		delta, _ = outResourcesDeltas.get(addrs[2], 202)
		require.NotEmpty(t, delta.newResource)
		require.Equal(t, assetHolding202.Amount, delta.newResource.GetAssetHolding().Amount)
		require.Equal(t, int(1), delta.nAcctDeltas)

		delta, _ = outResourcesDeltas.get(addrs[3], 103)
		require.NotEmpty(t, delta.newResource)
		require.Equal(t, assetParams103.Total, delta.newResource.Total)
		require.Equal(t, assetHolding103.Amount, delta.newResource.GetAssetHolding().Amount)
		require.Equal(t, int(1), delta.nAcctDeltas)
	}

	checkNewDeltas(outResourcesDeltas)
	for i := int64(0); i < 4; i++ {
		delta, idx := outResourcesDeltas.get(addrs[i], basics.CreatableIndex(100+i))
		require.NotEqual(t, -1, idx)
		require.Equal(t, trackerdb.PersistedResourcesData{Aidx: basics.CreatableIndex(100 + i)}, delta.oldResource)
		if i%2 == 0 {
			delta, idx = outResourcesDeltas.get(addrs[i], basics.CreatableIndex(200+i))
			require.NotEqual(t, -1, idx)
			require.Equal(t, trackerdb.PersistedResourcesData{Aidx: basics.CreatableIndex(200 + i)}, delta.oldResource)
		}
	}

	// check deltas without missing accounts
	for i := int64(0); i < 4; i++ {
		baseResources.write(trackerdb.PersistedResourcesData{AcctRef: mockEntryRef{i + 1}, Aidx: basics.CreatableIndex(100 + i)}, addrs[i])
		if i%2 == 0 {
			baseResources.write(trackerdb.PersistedResourcesData{AcctRef: mockEntryRef{i + 1}, Aidx: basics.CreatableIndex(200 + i)}, addrs[i])
		}
	}

	outResourcesDeltas = makeCompactResourceDeltas(stateDeltas, 1, true, baseAccounts, baseResources)
	require.Equal(t, 0, len(outResourcesDeltas.misses))
	require.Equal(t, 6, len(outResourcesDeltas.deltas))

	checkNewDeltas(outResourcesDeltas)
	for i := int64(0); i < 4; i++ {
		delta, idx := outResourcesDeltas.get(addrs[i], basics.CreatableIndex(100+i))
		require.NotEqual(t, -1, idx)
		require.Equal(t, trackerdb.PersistedResourcesData{AcctRef: mockEntryRef{i + 1}, Aidx: basics.CreatableIndex(100 + i)}, delta.oldResource)
		if i%2 == 0 {
			delta, idx = outResourcesDeltas.get(addrs[i], basics.CreatableIndex(200+i))
			require.NotEqual(t, -1, idx)
			require.Equal(t, trackerdb.PersistedResourcesData{AcctRef: mockEntryRef{i + 1}, Aidx: basics.CreatableIndex(200 + i)}, delta.oldResource)
		}
	}

	// add another round
	stateDeltas = append(stateDeltas, ledgercore.StateDelta{})
	stateDeltas[1].Accts.Upsert(addrs[0], ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 3}}})
	stateDeltas[1].Accts.Upsert(addrs[3], ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 8}}})

	appLocalState100 := basics.AppLocalState{KeyValue: basics.TealKeyValue{"100": basics.TealValue{Type: basics.TealBytesType, Bytes: "100"}}}
	stateDeltas[1].Accts.UpsertAppResource(addrs[0], 100, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{LocalState: &appLocalState100})

	appParams104 := basics.AppParams{ApprovalProgram: []byte{104}}
	appLocalState204 := basics.AppLocalState{KeyValue: basics.TealKeyValue{"204": basics.TealValue{Type: basics.TealBytesType, Bytes: "204"}}}
	stateDeltas[1].Accts.UpsertAppResource(addrs[4], 104, ledgercore.AppParamsDelta{Params: &appParams104}, ledgercore.AppLocalStateDelta{LocalState: &appLocalState204})

	baseResources.write(trackerdb.PersistedResourcesData{AcctRef: mockEntryRef{5} /* 4+1 */, Aidx: basics.CreatableIndex(104)}, addrs[4])
	outResourcesDeltas = makeCompactResourceDeltas(stateDeltas, basics.Round(1), true, baseAccounts, baseResources)

	require.Equal(t, 0, len(outResourcesDeltas.misses))
	require.Equal(t, 7, len(outResourcesDeltas.deltas))

	checkNewDeltas(outResourcesDeltas)
	delta, _ = outResourcesDeltas.get(addrs[0], 100)
	require.Equal(t, appLocalState100.KeyValue, delta.newResource.GetAppLocalState().KeyValue)
	require.Equal(t, int(2), delta.nAcctDeltas)

	delta, _ = outResourcesDeltas.get(addrs[4], 104)
	require.Equal(t, appParams104.ApprovalProgram, delta.newResource.GetAppParams().ApprovalProgram)
	require.Equal(t, appLocalState204.KeyValue, delta.newResource.GetAppLocalState().KeyValue)
	require.Equal(t, int(1), delta.nAcctDeltas)
}

// TestAcctUpdatesCachesInitialization test the functionality of the initializeCaches cache.
func TestAcctUpdatesCachesInitialization(t *testing.T) {
	partitiontest.PartitionTest(t)

	// The next operations are heavy on the memory.
	// Garbage collection helps prevent trashing
	runtime.GC()

	protocolVersion := protocol.ConsensusCurrentVersion

	const initialRounds = 1
	accountsCount := 5
	rewardsLevels := []uint64{0}
	accts := setupAccts(accountsCount)

	ml := makeMockLedgerForTracker(t, true, initialRounds, protocolVersion, accts)
	ml.log.SetLevel(logging.Warn)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)

	// cover initialRounds genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < int(initialRounds); i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	recoveredLedgerRound := basics.Round(initialRounds + initializeCachesRoundFlushInterval + conf.MaxAcctLookback + 1)

	for i := basics.Round(initialRounds); i <= recoveredLedgerRound; i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 2

		updates, totals := ledgertesting.RandomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{Round: i},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = protocolVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		ml.trackers.committedUpTo(i)
		ml.trackers.waitAccountsWriting()
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}
	au.close()

	// reset the accounts, since their balances are now changed due to the rewards.
	accts = []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(accountsCount, true)}

	// create another mocked ledger, but this time with a fresh new tracker database.
	ml2 := makeMockLedgerForTracker(t, true, initialRounds, protocolVersion, accts)
	ml2.log.SetLevel(logging.Warn)
	defer ml2.Close()

	// and "fix" it to contain the blocks and deltas from before.
	ml2.blocks = ml.blocks
	ml2.deltas = ml.deltas

	conf = config.GetDefaultLocal()
	au, _ = newAcctUpdates(t, ml2, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	// make sure the deltas array end up containing only the most recent 320 rounds.
	require.Equal(t, int(conf.MaxAcctLookback), len(au.deltas))
	require.Equal(t, recoveredLedgerRound-basics.Round(conf.MaxAcctLookback), au.cachedDBRound)

	// Garbage collection helps prevent trashing for next tests
	runtime.GC()
}

// TestAcctUpdatesSplittingConsensusVersionCommits tests the a sequence of commits that spans over multiple consensus versions works correctly.
func TestAcctUpdatesSplittingConsensusVersionCommits(t *testing.T) {
	partitiontest.PartitionTest(t)

	initProtocolVersion := protocol.ConsensusV20

	const initialRounds = 1

	accountsCount := 5
	rewardsLevels := []uint64{0}
	accts := setupAccts(accountsCount)

	ml := makeMockLedgerForTracker(t, true, initialRounds, initProtocolVersion, accts)
	ml.log.SetLevel(logging.Warn)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	// cover initialRounds genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < int(initialRounds); i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	extraRounds := basics.Round(39)

	// write the extraRounds rounds so that we will fill up the queue.
	for i := basics.Round(initialRounds); i < basics.Round(initialRounds+extraRounds); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 2

		updates, totals := ledgertesting.RandomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = initProtocolVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	newVersionBlocksCount := basics.Round(47)
	newVersion := protocol.ConsensusV21
	maxAcctLookback := basics.Round(conf.MaxAcctLookback)
	// add 47 more rounds that contains blocks using a newer consensus version, and stuff it with maxAcctLookback
	lastRoundToWrite := initialRounds + maxAcctLookback + extraRounds + newVersionBlocksCount
	for i := initialRounds + extraRounds; i < lastRoundToWrite; i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 2

		updates, totals := ledgertesting.RandomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = newVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}
	// now, commit and verify that the produceCommittingTask method broken the range correctly.
	ml.trackers.committedUpTo(lastRoundToWrite)
	ml.trackers.waitAccountsWriting()
	require.Equal(t, basics.Round(initialRounds+extraRounds)-1, au.cachedDBRound)

}

// TestAcctUpdatesSplittingConsensusVersionCommitsBoundary tests the a sequence of commits that spans over multiple consensus versions works correctly, and
// in particular, complements TestAcctUpdatesSplittingConsensusVersionCommits by testing the commit boundary.
func TestAcctUpdatesSplittingConsensusVersionCommitsBoundary(t *testing.T) {
	partitiontest.PartitionTest(t)

	initProtocolVersion := protocol.ConsensusV20

	const initialRounds basics.Round = 1
	accountsCount := 5
	rewardsLevels := []uint64{0}
	accts := setupAccts(accountsCount)

	ml := makeMockLedgerForTracker(t, true, initialRounds, initProtocolVersion, accts)
	ml.log.SetLevel(logging.Warn)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	// cover initialRounds genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < int(initialRounds); i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	const extraRounds basics.Round = 39

	// write extraRounds rounds so that we will fill up the queue.
	for i := initialRounds; i < initialRounds+extraRounds; i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 2

		updates, totals := ledgertesting.RandomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = initProtocolVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	newVersion := protocol.ConsensusV21
	maxAcctLockback := basics.Round(conf.MaxAcctLookback)
	// add maxAcctLockback-extraRounds more rounds that contains blocks using a newer consensus version.
	endOfFirstNewProtocolSegment := initialRounds + extraRounds + maxAcctLockback
	for i := initialRounds + extraRounds; i <= endOfFirstNewProtocolSegment; i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 2

		updates, totals := ledgertesting.RandomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = newVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}
	// now, commit and verify that the produceCommittingTask method broken the range correctly.
	ml.trackers.committedUpTo(endOfFirstNewProtocolSegment)
	ml.trackers.waitAccountsWriting()
	require.Equal(t, basics.Round(initialRounds+extraRounds)-1, au.cachedDBRound)

	// write additional extraRounds elements and verify these can be flushed.
	for i := endOfFirstNewProtocolSegment + 1; i <= initialRounds+2*extraRounds+maxAcctLockback; i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		accountChanges := 2

		updates, totals := ledgertesting.RandomDeltasBalanced(accountChanges, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = newVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}
	ml.trackers.committedUpTo(endOfFirstNewProtocolSegment + basics.Round(extraRounds))
	ml.trackers.waitAccountsWriting()
	require.Equal(t, initialRounds+2*extraRounds, au.cachedDBRound)
}

// TestAcctUpdatesResources checks that created, deleted, and created resource keep
// acct updates' compact deltas in a correct state
func TestAcctUpdatesResources(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := setupAccts(20)
	testProtocolVersion := protocol.ConsensusCurrentVersion
	protoParams := config.Consensus[testProtocolVersion]

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	var addr1 basics.Address
	var addr2 basics.Address
	for addr := range accts[0] {
		if addr != testSinkAddr && addr != testPoolAddr {
			if addr1 == (basics.Address{}) {
				addr1 = addr
			} else if addr2 == (basics.Address{}) {
				addr2 = addr
			} else {
				break
			}
		}
	}

	maxAcctLookback := conf.MaxAcctLookback

	aidx := basics.AssetIndex(1)
	aidx2 := basics.AssetIndex(2)
	aidx3 := basics.AppIndex(3)
	aidx4 := basics.AssetIndex(5)

	rewardLevel := uint64(0)
	knownCreatables := make(map[basics.CreatableIndex]bool)
	// the test 1 requires 3 blocks with different resource state, au requires maxAcctLookback blocks to start persisting
	// the test 2 requires 2 more blocks
	// the test 2 requires 2 more blocks
	for i := basics.Round(1); i <= basics.Round(maxAcctLookback+3+2+2); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		var updates ledgercore.AccountDeltas

		// test 1: modify state as needed for the tests: create, delete, create
		// expect no errors on accounts writing
		if i == 1 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 1}})
			updates.UpsertAssetResource(addr1, aidx, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 100}})
		}
		if i == 2 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 0}})
			updates.UpsertAssetResource(addr1, aidx, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Deleted: true})
		}
		if i == 3 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 1}})
			updates.UpsertAssetResource(addr1, aidx, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 200}})
		}

		// test 2: send back to creator creator
		// expect matching balances at the end
		creatorParams := ledgercore.AssetParamsDelta{Params: &basics.AssetParams{Total: 1000}}
		if i == 4 {
			// create base account to make lookup work
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 2, TotalAssetParams: 1}})
			updates.Upsert(addr2, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 1}})

			// create an asset
			updates.UpsertAssetResource(addr1, aidx2, creatorParams, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 1000}})

			// transfer
			updates.UpsertAssetResource(addr1, aidx2, creatorParams, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 900}})
			updates.UpsertAssetResource(addr2, aidx2, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 100}})
		}
		if i == 5 {
			// transfer back: asset holding record incorrectly clears params record
			updates.UpsertAssetResource(addr2, aidx2, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 99}})
			updates.UpsertAssetResource(addr1, aidx2, creatorParams, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 901}})
		}

		// test 3: own app local state closeout, own empty
		appParams := ledgercore.AppParamsDelta{Params: &basics.AppParams{ApprovalProgram: []byte{2, 0x20, 1, 1, 0x22} /* int 1 */}}
		if i == 6 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 3, TotalAssetParams: 2, TotalAppParams: 1, TotalAppLocalStates: 1}})

			// create an app
			updates.UpsertAppResource(addr1, aidx3, appParams, ledgercore.AppLocalStateDelta{LocalState: &basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}}})
			// create an asset
			updates.UpsertAssetResource(addr1, aidx4, creatorParams, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 1000}})
		}
		if i == 7 {
			// closeout app
			updates.UpsertAppResource(addr1, aidx3, appParams, ledgercore.AppLocalStateDelta{LocalState: nil, Deleted: true})
			// transfer own holdings
			updates.UpsertAssetResource(addr1, aidx4, creatorParams, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 0}})
		}

		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		newTotals := ledgertesting.CalculateNewRoundAccountTotals(t, updates, rewardLevel, protoParams, base, prevTotals)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = testProtocolVersion
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Creatables = creatablesFromUpdates(base, updates, knownCreatables)
		delta.Totals = newTotals

		ml.addBlock(blockEntry{block: blk}, delta)

		// commit changes synchroniously
		_, maxLookback := au.committedUpTo(i)
		dcc := &deferredCommitContext{
			deferredCommitRange: deferredCommitRange{
				lookback: maxLookback,
			},
		}
		cdr := &dcc.deferredCommitRange
		cdr = au.produceCommittingTask(i, ml.trackers.dbRound, cdr)
		if cdr != nil {
			func() {
				dcc.deferredCommitRange = *cdr
				ml.trackers.accountsWriting.Add(1)
				defer ml.trackers.accountsWriting.Done()

				// do not take any locks since all operations are synchronous
				newBase := dcc.newBase()

				err := au.prepareCommit(dcc)
				require.NoError(t, err)
				err = ml.trackers.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
					aw, err := tx.MakeAccountsWriter()
					if err != nil {
						return err
					}

					err = au.commitRound(ctx, tx, dcc)
					if err != nil {
						return err
					}
					err = aw.UpdateAccountsRound(newBase)
					return err
				})
				require.NoError(t, err)
				ml.trackers.dbRound = newBase
				au.postCommit(ml.trackers.ctx, dcc)
			}()

		}
		accts = append(accts, newAccts)
	}

	ad, _, _, err := au.lookupLatest(addr1)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), ad.AssetParams[aidx2].Total)
	require.Equal(t, uint64(901), ad.Assets[aidx2].Amount)

	require.NotEmpty(t, ad.AppParams[aidx3])
	require.NotEmpty(t, ad.AppParams[aidx3].ApprovalProgram)
	require.NotEmpty(t, ad.AssetParams[aidx4])
	h, ok := ad.Assets[aidx4]
	require.True(t, ok)
	require.Empty(t, h)

	ad, _, _, err = au.lookupLatest(addr2)
	require.NoError(t, err)
	require.Equal(t, uint64(99), ad.Assets[aidx2].Amount)
}

// TestConsecutiveVersion tests the consecutiveVersion method correctness.
func TestConsecutiveVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	var au accountUpdates
	au.versions = []protocol.ConsensusVersion{
		protocol.ConsensusV19,
		protocol.ConsensusV20,
		protocol.ConsensusV20,
		protocol.ConsensusV20,
		protocol.ConsensusV20,
		protocol.ConsensusV21,
		protocol.ConsensusV21,
		protocol.ConsensusV21,
		protocol.ConsensusV21,
		protocol.ConsensusV21,
		protocol.ConsensusV21,
		protocol.ConsensusV22,
	}
	for offset := uint64(1); offset < uint64(len(au.versions)); offset++ {
		co := au.consecutiveVersion(offset)
		require.Equal(t, au.versions[1], au.versions[co])
	}
	au.versions = []protocol.ConsensusVersion{
		protocol.ConsensusV19,
		protocol.ConsensusV20,
		protocol.ConsensusV21,
	}
}

func TestAcctUpdatesLookupLatest(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := ledgertesting.RandomAccounts(10, false)
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()
	for addr, acct := range accts {
		acctData, validThrough, withoutRewards, err := au.lookupLatest(addr)
		require.NoError(t, err)
		require.Equal(t, acct, acctData)

		// check "withoutRewards" matches result of LookupWithoutRewards
		d, r, err := au.LookupWithoutRewards(validThrough, addr)
		require.NoError(t, err)
		require.Equal(t, validThrough, r)
		require.Equal(t, withoutRewards, d.MicroAlgos)
	}
}

// This test helper attempts to cover the case when an accountUpdates.lookupX method:
// - can't find the requested address,
// - falls through looking at deltas and the LRU accounts cache,
// - then hits the database (calling accountsDbQueries.lookup)
// only to discover that the round stored in the database (committed in accountUpdates.commitRound)
// is out of sync with accountUpdates.cachedDBRound (updated a little bit later in accountUpdates.postCommit).
//
// In this case it waits on a condition variable and retries when
// commitSyncer/accountUpdates has advanced the cachedDBRound.
func testAcctUpdatesLookupRetry(t *testing.T, assertFn func(au *accountUpdates, accts []map[basics.Address]basics.AccountData, rnd basics.Round, proto config.ConsensusParams, rewardsLevels []uint64)) {
	testProtocolVersion := protocol.ConsensusCurrentVersion
	proto := config.Consensus[testProtocolVersion]

	accts := setupAccts(20)
	rewardsLevels := []uint64{0}

	conf := config.GetDefaultLocal()
	initialBlocksCount := basics.Round(conf.MaxAcctLookback)
	ml := makeMockLedgerForTracker(t, false, initialBlocksCount, testProtocolVersion, accts)
	defer ml.Close()

	au, ao := newAcctUpdates(t, ml, conf)
	// au and ao are closed via ml.Close() -> ml.trackers.close()

	// cover 10 genesis blocks
	rewardLevel := uint64(0)
	for i := basics.Round(1); i < initialBlocksCount; i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	checkAcctUpdates(t, au, ao, 0, basics.Round(initialBlocksCount)-1, accts, rewardsLevels, proto)

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	lastCreatableID := basics.CreatableIndex(crypto.RandUint64() % 512)
	knownCreatables := make(map[basics.CreatableIndex]bool)

	for i := initialBlocksCount; i < basics.Round(conf.MaxAcctLookback+15); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		var updates ledgercore.AccountDeltas
		var totals map[basics.Address]ledgercore.AccountData
		base := accts[i-1]
		updates, totals = ledgertesting.RandomDeltasBalancedFull(
			1, base, rewardLevel, &lastCreatableID)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(base, updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = testProtocolVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Creatables = creatablesFromUpdates(base, updates, knownCreatables)
		delta.Totals = accumulateTotals(t, testProtocolVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)

		checkAcctUpdates(t, au, ao, 0, i, accts, rewardsLevels, proto)
	}

	flushRound := func(i basics.Round) {
		// Clear the timer to ensure a flush
		ml.trackers.lastFlushTime = time.Time{}

		ml.trackers.committedUpTo(basics.Round(conf.MaxAcctLookback) + i)
		ml.trackers.waitAccountsWriting()
	}

	// flush a couple of rounds (indirectly schedules commitSyncer)
	flushRound(0)
	flushRound(1)

	// add stallingTracker to list of trackers
	stallingTracker := &blockingTracker{
		postCommitUnlockedEntryLock:   make(chan struct{}),
		postCommitUnlockedReleaseLock: make(chan struct{}),
		postCommitEntryLock:           make(chan struct{}),
		postCommitReleaseLock:         make(chan struct{}),
	}
	stallingTracker.alwaysLock.Store(true)
	ml.trackers.trackers = append([]ledgerTracker{stallingTracker}, ml.trackers.trackers...)

	// kick off another round
	rnd := basics.Round(2)
	go flushRound(rnd)

	// let stallingTracker enter postCommit() and block (waiting on postCommitReleaseLock)
	// this will prevent accountUpdates.postCommit() from updating au.cachedDBRound = newBase
	<-stallingTracker.postCommitEntryLock

	// prune the baseAccounts cache, so that lookup will fall through to the DB
	au.accountsMu.Lock()
	au.baseAccounts.prune(0)
	au.accountsMu.Unlock()

	defer func() { // allow the postCommitUnlocked() handler to go through, even if test fails
		<-stallingTracker.postCommitUnlockedEntryLock
		stallingTracker.postCommitUnlockedReleaseLock <- struct{}{}
	}()

	// issue a lookupWithoutRewards while persistedData.round != au.cachedDBRound
	// when synchronized=false it will fail fast
	_, _, _, _, err := au.lookupWithoutRewards(rnd, basics.Address{}, false)
	require.Equal(t, &MismatchingDatabaseRoundError{databaseRound: 2, memoryRound: 1}, err)

	// release the postCommit lock, once au.lookupWithoutRewards hits au.accountsReadCond.Wait()
	go func() {
		time.Sleep(200 * time.Millisecond)
		stallingTracker.postCommitReleaseLock <- struct{}{}
	}()

	assertFn(au, accts, rnd, proto, rewardsLevels)
}

func TestAcctUpdatesLookupLatestRetry(t *testing.T) {
	partitiontest.PartitionTest(t)

	testAcctUpdatesLookupRetry(t,
		func(au *accountUpdates, accts []map[basics.Address]basics.AccountData, rnd basics.Round, proto config.ConsensusParams, rewardsLevels []uint64) {
			// grab any address and data to use for call to lookup
			var addr basics.Address
			for a := range accts[rnd] {
				addr = a
				break
			}

			// issue a LookupWithoutRewards while persistedData.round != au.cachedDBRound
			d, validThrough, withoutRewards, err := au.lookupLatest(addr)
			require.NoError(t, err)
			require.Equal(t, accts[validThrough][addr].WithUpdatedRewards(proto.RewardUnit, rewardsLevels[validThrough]), d)
			require.Equal(t, accts[validThrough][addr].MicroAlgos, withoutRewards)
			require.GreaterOrEqualf(t, uint64(validThrough), uint64(rnd), "validThrough: %v rnd :%v", validThrough, rnd)
		})
}

func TestAcctUpdatesLookupRetry(t *testing.T) {
	partitiontest.PartitionTest(t)

	testAcctUpdatesLookupRetry(t,
		func(au *accountUpdates, accts []map[basics.Address]basics.AccountData, rnd basics.Round, proto config.ConsensusParams, rewardsLevels []uint64) {
			// grab any address and data to use for call to lookup
			var addr basics.Address
			var data basics.AccountData
			for a, d := range accts[rnd] {
				addr = a
				data = d
				break
			}

			// issue a LookupWithoutRewards while persistedData.round != au.cachedDBRound
			d, validThrough, _, _, err := au.lookupWithoutRewards(rnd, addr, true)
			require.NoError(t, err)
			require.Equal(t, d, ledgercore.ToAccountData(data))
			// TODO: add online account data check
			require.GreaterOrEqualf(t, uint64(validThrough), uint64(rnd), "validThrough: %v rnd :%v", validThrough, rnd)
		})
}

// auCommitSync is a helper function calling the committing sequence similarly to what tracker registry does
func auCommitSync(t *testing.T, rnd basics.Round, au *accountUpdates, ml *mockLedgerForTracker) {
	_, maxLookback := au.committedUpTo(rnd)
	dcc := &deferredCommitContext{
		deferredCommitRange: deferredCommitRange{
			lookback: maxLookback,
		},
	}
	cdr := &dcc.deferredCommitRange
	cdr = au.produceCommittingTask(rnd, ml.trackers.dbRound, cdr)
	if cdr != nil {
		func() {
			dcc.deferredCommitRange = *cdr
			ml.trackers.accountsWriting.Add(1)
			defer ml.trackers.accountsWriting.Done()

			// do not take any locks since all operations are synchronous
			newBase := dcc.newBase()

			err := au.prepareCommit(dcc)
			require.NoError(t, err)
			err = ml.trackers.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
				aw, err := tx.MakeAccountsWriter()
				if err != nil {
					return err
				}

				err = au.commitRound(ctx, tx, dcc)
				if err != nil {
					return err
				}
				err = aw.UpdateAccountsRound(newBase)
				return err
			})
			require.NoError(t, err)
			ml.trackers.dbRound = newBase
			au.postCommit(ml.trackers.ctx, dcc)
		}()
	}
}

type auNewBlockOpts struct {
	updates         ledgercore.AccountDeltas
	version         protocol.ConsensusVersion
	protoParams     config.ConsensusParams
	knownCreatables map[basics.CreatableIndex]bool
}

func auNewBlock(t *testing.T, rnd basics.Round, au *accountUpdates, base map[basics.Address]basics.AccountData, data auNewBlockOpts, kvMods map[string]ledgercore.KvValueDelta) {
	rewardLevel := uint64(0)
	prevRound, prevTotals, err := au.LatestTotals()
	require.Equal(t, rnd-1, prevRound)
	require.NoError(t, err)

	newTotals := ledgertesting.CalculateNewRoundAccountTotals(t, data.updates, rewardLevel, data.protoParams, base, prevTotals)

	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{Round: rnd},
	}
	blk.RewardsLevel = rewardLevel
	blk.CurrentProtocol = data.version
	delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, data.updates.Len(), 0)
	delta.Accts.MergeAccounts(data.updates)
	delta.Creatables = creatablesFromUpdates(base, data.updates, data.knownCreatables)
	delta.Totals = newTotals
	delta.KvMods = kvMods

	au.newBlock(blk, delta)
}

// TestAcctUpdatesLookupLatestCacheRetry simulates a situation when base account and resources are in a cache but
// account updates advances while calling lookupLatest
// The idea of the test:
// - create some base accounts and an account with resources
// - set that account to be in the caches
// - force cached round to be one less than the real DB round
// - call lookupLatest, ensure it blocks
// - advance lookupLatest and check the content is actual
func TestAcctUpdatesLookupLatestCacheRetry(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := setupAccts(20)

	testProtocolVersion := protocol.ConsensusCurrentVersion
	protoParams := config.Consensus[testProtocolVersion]

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	var addr1 basics.Address
	for addr := range accts[0] {
		if addr != testSinkAddr && addr != testPoolAddr {
			addr1 = addr
			break
		}
	}

	aidx1 := basics.AssetIndex(1)
	aidx2 := basics.AssetIndex(2)
	knownCreatables := make(map[basics.CreatableIndex]bool)

	// the test 1 requires 2 blocks with different resource state, au requires MaxBalLookback block to start persisting
	for i := basics.Round(1); i <= basics.Round(conf.MaxAcctLookback+2); i++ {
		var updates ledgercore.AccountDeltas

		// add data
		if i == 1 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssetParams: 1, TotalAssets: 2}})
			updates.UpsertAssetResource(addr1, aidx1, ledgercore.AssetParamsDelta{Params: &basics.AssetParams{Total: 100}}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 100}})
			updates.UpsertAssetResource(addr1, aidx2, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 200}})
		}

		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		// prepare block
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, i, au, base, opts, nil)

		// commit changes synchroniously
		auCommitSync(t, i, au, ml)
	}

	// ensure rounds
	rnd := au.latest()
	require.Equal(t, basics.Round(conf.MaxAcctLookback+2), rnd)
	require.Equal(t, basics.Round(2), au.cachedDBRound)
	oldCachedDBRound := au.cachedDBRound

	// simulate the following state
	// 1. addr1 and in baseAccounts and its round is less than addr1's data in baseResources
	// 2. au.cachedDBRound is less than actual DB round
	delete(au.accounts, addr1)
	au.cachedDBRound--

	pad, ok := au.baseAccounts.read(addr1)
	require.True(t, ok)
	pad.Round = au.cachedDBRound
	au.baseAccounts.write(pad)

	prd, ok := au.baseResources.read(addr1, basics.CreatableIndex(aidx1))
	require.True(t, ok)
	prd.Round = oldCachedDBRound
	au.baseResources.write(prd, addr1)
	prd, ok = au.baseResources.read(addr1, basics.CreatableIndex(aidx2))
	require.True(t, ok)
	prd.Round = oldCachedDBRound
	au.baseResources.write(prd, addr1)

	var ad basics.AccountData
	var err error

	// lookupLatest blocks on waiting new round. There is no reliable way to say it is blocked,
	// so run it in a goroutine and query it to ensure it is blocked.
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		ad, _, _, err = au.lookupLatest(addr1)
		close(done)
		wg.Done()
	}()

	// wait to ensure lookupLatest is stuck
	maxIterations := 10
	i := 0
	for i < maxIterations {
		select {
		case <-done:
			require.Fail(t, "lookupLatest returns without waiting for new block")
		default:
			i++
			time.Sleep(10 * time.Millisecond)
		}
	}

	// give it a new block and restore the original cachedDBRound value
	au.accountsMu.Lock()
	au.cachedDBRound = oldCachedDBRound
	au.accountsMu.Unlock()
	opts := auNewBlockOpts{ledgercore.AccountDeltas{}, testProtocolVersion, protoParams, knownCreatables}
	auNewBlock(t, rnd+1, au, accts[rnd], opts, nil)
	auCommitSync(t, rnd+1, au, ml)

	wg.Wait()

	require.NoError(t, err)
	require.Equal(t, uint64(1000000), ad.MicroAlgos.Raw)
	require.Equal(t, uint64(100), ad.AssetParams[aidx1].Total)
	require.Equal(t, uint64(100), ad.Assets[aidx1].Amount)
	require.Equal(t, uint64(200), ad.Assets[aidx2].Amount)
}

// TestAcctUpdatesLookupResources creates 3 assets, deletes one
// and checks au.resources with deleted resources are not counted toward totals
func TestAcctUpdatesLookupResources(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := setupAccts(1)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctUpdatesLookupResources")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = 2
	protoParams.SeedLookback = 1
	protoParams.SeedRefreshInterval = 1
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	var addr1 basics.Address
	for addr := range accts[0] {
		if addr != testSinkAddr && addr != testPoolAddr {
			addr1 = addr
			break
		}
	}

	aidx1 := basics.AssetIndex(1)
	aidx2 := basics.AssetIndex(2)
	aidx3 := basics.AssetIndex(3)
	knownCreatables := make(map[basics.CreatableIndex]bool)

	// test requires 5 blocks: 1 with aidx1, protoParams.MaxBalLookback empty blocks to commit the first one
	// and 1 block with aidx2 and aidx3, and another one with aidx2 deleted
	for i := basics.Round(1); i <= basics.Round(protoParams.MaxBalLookback+3); i++ {
		var updates ledgercore.AccountDeltas

		// add data
		if i == 1 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 1}})
			updates.UpsertAssetResource(addr1, aidx1, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 100}})
		}
		if i == basics.Round(protoParams.MaxBalLookback+2) {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 3}})
			updates.UpsertAssetResource(addr1, aidx2, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 200}})
			updates.UpsertAssetResource(addr1, aidx3, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 300}})
		}
		if i == basics.Round(protoParams.MaxBalLookback+3) {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 2}})
			updates.UpsertAssetResource(addr1, aidx2, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Deleted: true})
		}

		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		// prepare block
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, i, au, base, opts, nil)

		if i <= basics.Round(protoParams.MaxBalLookback+1) {
			auCommitSync(t, i, au, ml)
		}
		// do not commit two last blocks to keep data in memory deltas
	}
	data, rnd, _, err := au.lookupLatest(addr1)
	require.NoError(t, err)
	require.Equal(t, basics.Round(protoParams.MaxBalLookback+3), rnd)
	require.Len(t, data.Assets, 2)
	require.Contains(t, data.Assets, aidx1)
	require.Contains(t, data.Assets, aidx3)
	require.NotContains(t, data.Assets, aidx2)
}

// TestAcctUpdatesLookupStateDelta simulates rounds w/ both account and kv changes in them,
// validating that a StateDelta can be retrieved for expected rounds containing the same updates.
func TestAcctUpdatesLookupStateDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	const initialBlocksCount = 1
	accts := setupAccts(1)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctUpdatesLookupStateDelta")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = 2
	protoParams.SeedLookback = 1
	protoParams.SeedRefreshInterval = 1
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	ml := makeMockLedgerForTracker(t, true, initialBlocksCount, testProtocolVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, _ := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	knownCreatables := make(map[basics.CreatableIndex]bool)

	var addr1 basics.Address
	for addr := range accts[0] {
		if addr != testSinkAddr && addr != testPoolAddr {
			addr1 = addr
			break
		}
	}

	aidx1 := basics.AssetIndex(1)
	aidx2 := basics.AssetIndex(2)
	aidx3 := basics.AssetIndex(3)

	// Stores AccountDeltas for each round. These are used as the source of truth for comparing retrieved StateDeltas.
	updatesI := make(map[basics.Round]ledgercore.AccountDeltas)
	// Stores KVMods for each round. These are used as the source of truth for comparing retireved StateDeltas.
	var roundMods = make(map[basics.Round]map[string]ledgercore.KvValueDelta)

	// Sets up random keys & values to trackerdb.
	kvCnt := 1000
	kvsPerBlock := 100
	curKV := 0
	var currentRound basics.Round
	kvMap := make(map[string][]byte)
	for i := 0; i < kvCnt; i++ {
		kvMap[fmt.Sprintf("%d", i)] = []byte(fmt.Sprintf("value%d", i))
	}

	// Iterate through rounds 1..9, creating KvDeltas and modifying some accounts/assets
	for i := 1; i < kvCnt/kvsPerBlock; i++ {
		var updates ledgercore.AccountDeltas
		currentRound = currentRound + 1
		// Construct KvMods for round
		kvMods := make(map[string]ledgercore.KvValueDelta)
		if i < kvCnt/kvsPerBlock {
			for j := 0; j < kvsPerBlock; j++ {
				name := fmt.Sprintf("%d", curKV)
				curKV++
				val := kvMap[name]
				kvMods[name] = ledgercore.KvValueDelta{Data: val, OldData: nil}
			}
		}
		// Stores created kvMods for assertions against StateDeltas
		roundMods[currentRound] = kvMods

		// Construct acct updates. These are arbitrary updates made for a few rounds to ensure they are properly
		// reflected in the retrieved StateDeltas.
		if i == 1 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 1}})
			updates.UpsertAssetResource(addr1, aidx1, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 100}})
		}
		if uint64(i) == protoParams.MaxBalLookback+2 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 3}})
			updates.UpsertAssetResource(addr1, aidx2, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 200}})
			updates.UpsertAssetResource(addr1, aidx3, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 300}})
		}
		if uint64(i) == protoParams.MaxBalLookback+3 {
			updates.Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAssets: 2}})
			updates.UpsertAssetResource(addr1, aidx2, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Deleted: true})
		}
		// Store whatever updates were made for later assertions.
		updatesI[basics.Round(i)] = updates
		base := accts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accts = append(accts, newAccts)

		// Commit the block with the changes
		opts := auNewBlockOpts{updates, testProtocolVersion, protoParams, knownCreatables}
		auNewBlock(t, currentRound, au, base, opts, kvMods)
		auCommitSync(t, currentRound, au, ml)

		// Ensure the db round is what we expect, and the proper amount is in cache versus in ledger.
		rnd := au.latest()
		require.Equal(t, currentRound, rnd)
		if uint64(currentRound) > conf.MaxAcctLookback {
			require.Equal(t, currentRound-basics.Round(conf.MaxAcctLookback), au.cachedDBRound)
		} else {
			require.Equal(t, basics.Round(0), au.cachedDBRound)
		}

		// Iterate backwards through deltas, ensuring proper data exists in StateDelta
		for j := rnd; j > au.cachedDBRound; j-- {
			// fetch StateDelta
			actualDelta, err := au.lookupStateDelta(j)
			require.NoError(t, err)
			actualAccountDeltas := actualDelta.Accts
			actualKvDeltas := actualDelta.KvMods

			// Make sure we know about the expected changes for the delta's round
			expectedAccountDeltas, has := updatesI[j]
			require.True(t, has)
			// Do basic checking on the size and existence of accounts in deltas
			require.Equal(t, expectedAccountDeltas.Len(), actualAccountDeltas.Len())
			require.Equal(t, len(expectedAccountDeltas.Accts), len(actualAccountDeltas.Accts))
			for _, acct := range expectedAccountDeltas.Accts {
				_, has := actualAccountDeltas.GetBasicsAccountData(acct.Addr)
				require.True(t, has)
			}
			// Do basic checking on the existence of asset changes in deltas
			require.Equal(t, len(expectedAccountDeltas.AssetResources), len(actualAccountDeltas.AssetResources))
			for _, asset := range expectedAccountDeltas.AssetResources {
				_, ok := actualAccountDeltas.GetResource(asset.Addr, basics.CreatableIndex(asset.Aidx), basics.AssetCreatable)
				require.True(t, ok)
			}
			require.Equal(t, len(expectedAccountDeltas.AppResources), len(actualAccountDeltas.AppResources))

			// Validate KvDeltas contains updates w/ new/old values.
			startKV := (uint64(j) - 1) * uint64(kvsPerBlock)
			expectedKvDeltas, has := roundMods[j]
			require.True(t, has)
			for kv := 0; kv < kvsPerBlock; kv++ {
				name := fmt.Sprintf("%d", startKV+uint64(kv))
				delta, has := actualKvDeltas[name]
				require.True(t, has)
				expectedDelta, has := expectedKvDeltas[name]
				require.True(t, has)
				require.Equal(t, expectedDelta.Data, delta.Data)
				require.Equal(t, expectedDelta.OldData, delta.OldData)

			}
		}
	}
	// For rounds evicted from cache, perform sanity checks to confirm intended
	// side effects took effect.
	data, rnd, _, err := au.lookupLatest(addr1)
	require.NoError(t, err)
	require.Equal(t, basics.Round(kvCnt/kvsPerBlock-1), rnd)
	require.Len(t, data.Assets, 2)
	require.Contains(t, data.Assets, aidx1)
	require.Contains(t, data.Assets, aidx3)
	require.NotContains(t, data.Assets, aidx2)
}
