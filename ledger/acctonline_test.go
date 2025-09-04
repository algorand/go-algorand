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
	"context"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func commitSync(t *testing.T, oa *onlineAccounts, ml *mockLedgerForTracker, rnd basics.Round) {
	_, maxLookback := oa.committedUpTo(rnd)
	dcc := &deferredCommitContext{
		deferredCommitRange: deferredCommitRange{
			lookback: maxLookback,
		},
	}
	cdr := ml.trackers.produceCommittingTask(rnd, ml.trackers.dbRound, &dcc.deferredCommitRange)
	if cdr != nil {
		func() {
			dcc.deferredCommitRange = *cdr
			ml.trackers.accountsWriting.Add(1)

			// do not take any locks since all operations are synchronous
			err := ml.trackers.commitRound(dcc)
			require.NoError(t, err)
		}()
	}
}

// commitSyncPartial does not call postCommit
func commitSyncPartial(t *testing.T, oa *onlineAccounts, ml *mockLedgerForTracker, rnd basics.Round) *deferredCommitContext {
	_, maxLookback := oa.committedUpTo(rnd)
	dcc := &deferredCommitContext{
		deferredCommitRange: deferredCommitRange{
			lookback: maxLookback,
		},
	}
	cdr := ml.trackers.produceCommittingTask(rnd, ml.trackers.dbRound, &dcc.deferredCommitRange)
	if cdr != nil {
		func() {
			dcc.deferredCommitRange = *cdr
			ml.trackers.accountsWriting.Add(1)

			// do not take any locks since all operations are synchronous
			newBase := dcc.newBase()
			dcc.flushTime = time.Now()

			for _, lt := range ml.trackers.trackers {
				err := lt.prepareCommit(dcc)
				require.NoError(t, err)
			}
			err := ml.trackers.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
				aw, err := tx.MakeAccountsWriter()
				if err != nil {
					return err
				}

				for _, lt := range ml.trackers.trackers {
					err0 := lt.commitRound(ctx, tx, dcc)
					if err0 != nil {
						return err0
					}
				}

				return aw.UpdateAccountsRound(newBase)
			})
			require.NoError(t, err)
		}()
	}

	return dcc
}

func commitSyncPartialComplete(t *testing.T, oa *onlineAccounts, ml *mockLedgerForTracker, dcc *deferredCommitContext) {
	defer ml.trackers.accountsWriting.Done()

	ml.trackers.dbRound = dcc.newBase()
	for _, lt := range ml.trackers.trackers {
		lt.postCommit(ml.trackers.ctx, dcc)
	}
	ml.trackers.lastFlushTime = dcc.flushTime

	for _, lt := range ml.trackers.trackers {
		if lt, ok := lt.(trackerCommitLifetimeHandlers); ok {
			lt.postCommitUnlocked(ml.trackers.ctx, dcc)
		}
	}
}

func newBlockWithRewards(t *testing.T, ml *mockLedgerForTracker, testProtocolVersion protocol.ConsensusVersion, protoParams config.ConsensusParams, rnd basics.Round, base map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, rewardLevel uint64, prevTotals ledgercore.AccountTotals) (newTotals ledgercore.AccountTotals) {
	newTotals = ledgertesting.CalculateNewRoundAccountTotals(t, updates, rewardLevel, protoParams, base, prevTotals)

	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round: basics.Round(rnd),
		},
	}
	blk.RewardsLevel = rewardLevel
	blk.CurrentProtocol = testProtocolVersion
	delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
	delta.Accts.MergeAccounts(updates)
	delta.Totals = newTotals

	ml.addBlock(blockEntry{block: blk}, delta)

	return newTotals
}

func newBlock(t *testing.T, ml *mockLedgerForTracker, testProtocolVersion protocol.ConsensusVersion, protoParams config.ConsensusParams, rnd basics.Round, base map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, prevTotals ledgercore.AccountTotals) (newTotals ledgercore.AccountTotals) {
	return newBlockWithRewards(t, ml, testProtocolVersion, protoParams, rnd, base, updates, 0, prevTotals)
}

// TestAcctOnline checks the online accounts tracker correctly stores accont change history
// 1. Start with 1000 online accounts
// 2. Every round set one of them offline
// 3. Ensure the DB and the base cache are up to date (report them offline)
// 4. Ensure expiration works
func TestAcctOnline(t *testing.T) {
	partitiontest.PartitionTest(t)

	const seedLookback = 2
	const seedInteval = 3
	const maxBalLookback = 2 * seedLookback * seedInteval

	const numAccts = maxBalLookback * 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	for i := 0; i < numAccts; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr:        ledgertesting.RandomAddress(),
			AccountData: ledgertesting.RandomOnlineAccountData(0),
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}

	addSinkAndPoolAccounts(genesisAccts)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctOnline")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = maxBalLookback
	protoParams.SeedLookback = seedLookback
	protoParams.SeedRefreshInterval = seedInteval
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	maxDeltaLookback := conf.MaxAcctLookback

	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	for _, bal := range allAccts {
		data, err := oa.accountsq.LookupOnline(bal.Addr, 0)
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.Addr)
		require.Equal(t, basics.Round(0), data.Round)
		require.Equal(t, bal.AccountData.MicroAlgos, data.AccountData.MicroAlgos)
		require.Equal(t, bal.AccountData.RewardsBase, data.AccountData.RewardsBase)
		require.Equal(t, bal.AccountData.VoteFirstValid, data.AccountData.VoteFirstValid)
		require.Equal(t, bal.AccountData.VoteLastValid, data.AccountData.VoteLastValid)

		oad, err := oa.lookupOnlineAccountData(0, bal.Addr)
		require.NoError(t, err)
		require.NotEmpty(t, oad)
	}

	// online accounts tracker requires maxDeltaLookback block to start persisting
	numPersistedAccounts := numAccts - maxDeltaLookback*2
	targetRound := basics.Round(maxDeltaLookback + numPersistedAccounts)
	for i := basics.Round(1); i <= targetRound; i++ {
		var updates ledgercore.AccountDeltas
		acctIdx := int(i) - 1

		updates.Upsert(allAccts[acctIdx].Addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})

		base := genesisAccts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		genesisAccts = append(genesisAccts, newAccts)

		// prepare block
		totals = newBlock(t, ml, testProtocolVersion, protoParams, i, base, updates, totals)

		// commit changes synchroniously
		commitSync(t, oa, ml, i)

		// check the table data and the cache
		// data gets committed after maxDeltaLookback
		if i > basics.Round(maxDeltaLookback) {
			rnd := i - basics.Round(maxDeltaLookback)
			acctIdx := int(rnd) - 1
			bal := allAccts[acctIdx]
			data, err := oa.accountsq.LookupOnline(bal.Addr, rnd)
			require.NoError(t, err)
			require.Equal(t, bal.Addr, data.Addr)
			require.NotEmpty(t, data.Ref)
			require.Equal(t, oa.cachedDBRoundOnline, data.Round)
			require.Empty(t, data.AccountData)

			data, has := oa.baseOnlineAccounts.read(bal.Addr)
			require.True(t, has)
			require.NotEmpty(t, data.Ref)
			require.Empty(t, data.AccountData)

			oad, err := oa.lookupOnlineAccountData(rnd, bal.Addr)
			require.NoError(t, err)
			require.Empty(t, oad)

			// check the prev original row is still there
			data, err = oa.accountsq.LookupOnline(bal.Addr, rnd-1)
			require.NoError(t, err)
			require.Equal(t, bal.Addr, data.Addr)
			require.NotEmpty(t, data.Ref)
			require.Equal(t, oa.cachedDBRoundOnline, data.Round)
			require.NotEmpty(t, data.AccountData)
		}

		// check data gets expired and removed from the DB
		// account 0 is set to Offline at round 1
		// and set expired at X = 1 + MaxBalLookback (= 13)
		// actual removal happens when X is committed i.e. at round X + maxDeltaLookback (= 21)
		if i > basics.Round(maxBalLookback+maxDeltaLookback) {
			rnd := i - basics.Round(maxBalLookback+maxDeltaLookback)
			acctIdx := int(rnd) - 1
			bal := allAccts[acctIdx]
			data, err := oa.accountsq.LookupOnline(bal.Addr, rnd)
			require.NoError(t, err)
			require.Equal(t, bal.Addr, data.Addr)
			require.Empty(t, data.Ref)
			require.Equal(t, oa.cachedDBRoundOnline, data.Round)
			require.Empty(t, data.AccountData)

			data, has := oa.baseOnlineAccounts.read(bal.Addr)
			require.True(t, has)
			require.NotEmpty(t, data.Ref) // TODO: FIXME: set rowid to empty for these items
			require.Empty(t, data.AccountData)

			// committed round i => dbRound = i - maxDeltaLookback (= 13 for the account 0)
			// dbRound - maxBalLookback (= 1) is the "set offline" round for account 0
			// lookup should correctly return empty data round dbRound - maxBalLookback + 1 (simulate the latest +1)
			oad, err := oa.lookupOnlineAccountData(rnd+1, bal.Addr)
			require.NoError(t, err)
			require.Empty(t, oad)

			// check next account
			// for the account 1, it set to Offline at round 2
			// and set expired at X = 2 + MaxBalLookback (= 14)
			nextAcctIdx := acctIdx + 1
			if nextAcctIdx < int(targetRound) {
				bal := allAccts[nextAcctIdx]
				data, err := oa.accountsq.LookupOnline(bal.Addr, rnd)
				require.NoError(t, err)
				require.Equal(t, bal.Addr, data.Addr)
				require.NotEmpty(t, data.Ref)
				require.Equal(t, oa.cachedDBRoundOnline, data.Round)
				require.NotEmpty(t, data.AccountData)

				// the most recent value is empty because the account is scheduled for removal
				data, has := oa.baseOnlineAccounts.read(bal.Addr)
				require.True(t, has)
				require.NotEmpty(t, data.Ref) // TODO: FIXME: set rowid to empty for these items
				require.Empty(t, data.AccountData)

				// account 1 went offline at round 2 => it offline at requested round 1+1=2
				oad, err := oa.lookupOnlineAccountData(rnd+1, bal.Addr)
				require.NoError(t, err)
				require.Empty(t, oad)
			}
			// check next next account
			// for the account 2, it set to Offline at round 3
			// at round 1 + 1 = 2 it online and should te correctly retrieved from DB and lookup
			nextNextAcctIdx := nextAcctIdx + 1
			if nextNextAcctIdx < int(targetRound) {
				bal := allAccts[nextNextAcctIdx]
				data, err := oa.accountsq.LookupOnline(bal.Addr, rnd)
				require.NoError(t, err)
				require.Equal(t, bal.Addr, data.Addr)
				require.NotEmpty(t, data.Ref)
				require.Equal(t, oa.cachedDBRoundOnline, data.Round)
				require.NotEmpty(t, data.AccountData)

				// the most recent value is empty because the account is scheduled for removal
				data, has := oa.baseOnlineAccounts.read(bal.Addr)
				require.True(t, has)
				require.NotEmpty(t, data.Ref) // TODO: FIXME: set rowid to empty for these items
				require.Empty(t, data.AccountData)

				// account 2 went offline at round 3 => it online at requested round 1+1=2
				oad, err := oa.lookupOnlineAccountData(rnd+1, bal.Addr)
				require.NoError(t, err)
				require.NotEmpty(t, oad)
			}
		}
	}

	// ensure rounds
	require.Equal(t, targetRound, au.latest())
	require.Equal(t, basics.Round(numPersistedAccounts), oa.cachedDBRoundOnline)

	// at this point we should have maxBalLookback last accounts of numPersistedAccounts
	// to be in the DB and in the cache and not yet removed
	for i := numPersistedAccounts - maxBalLookback; i < numPersistedAccounts; i++ {
		bal := allAccts[i]
		// we expire account i at round i+1
		data, err := oa.accountsq.LookupOnline(bal.Addr, basics.Round(i+1))
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.Addr)
		require.NotEmpty(t, data.Ref)
		require.Equal(t, oa.cachedDBRoundOnline, data.Round)
		require.Empty(t, data.AccountData)

		data, has := oa.baseOnlineAccounts.read(bal.Addr)
		require.True(t, has)
		require.NotEmpty(t, data.Ref)
		require.Empty(t, data.AccountData)

		oad, err := oa.lookupOnlineAccountData(basics.Round(i+1), bal.Addr)
		require.NoError(t, err)
		require.Empty(t, oad)

		// ensure the online entry is still in the DB for the round i
		data, err = oa.accountsq.LookupOnline(bal.Addr, basics.Round(i))
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.Addr)
		require.NotEmpty(t, data.Ref)
		require.Equal(t, oa.cachedDBRoundOnline, data.Round)
		require.NotEmpty(t, data.AccountData)
	}

	// check maxDeltaLookback accounts in in-memory deltas, check it
	for i := numPersistedAccounts; i < numPersistedAccounts+maxDeltaLookback; i++ {
		bal := allAccts[i]
		oad, err := oa.lookupOnlineAccountData(basics.Round(i+1), bal.Addr)
		require.NoError(t, err)
		require.Empty(t, oad)

		// the table has old values b/c not committed yet
		data, err := oa.accountsq.LookupOnline(bal.Addr, basics.Round(i))
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.Addr)
		require.NotEmpty(t, data.Ref)
		require.Equal(t, oa.cachedDBRoundOnline, data.Round)
		require.NotEmpty(t, data.AccountData)

		// the base cache also does not have such entires
		data, has := oa.baseOnlineAccounts.read(bal.Addr)
		require.False(t, has)
		require.Empty(t, data)
	}

	// not take some account and modify its stake.
	// ensure it has the valid entries in both deltas and history
	start := targetRound + 1
	end := start + basics.Round(maxDeltaLookback+10)
	mutAccount := allAccts[start]
	ad := ledgercore.ToAccountData(mutAccount.AccountData)
	const delta = 1000
	for i := start; i <= end; i++ {
		newAD := ad.AccountBaseData
		newAD.MicroAlgos.Raw += uint64(i-start+1) * delta
		var updates ledgercore.AccountDeltas
		updates.Upsert(
			mutAccount.Addr,
			ledgercore.AccountData{
				AccountBaseData: newAD,
				VotingData:      ad.VotingData,
			},
		)

		base := genesisAccts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		genesisAccts = append(genesisAccts, newAccts)

		// prepare block
		totals = newBlock(t, ml, testProtocolVersion, protoParams, i, base, updates, totals)

		// flush all old deltas
		if uint64(i-start+1) == maxDeltaLookback {
			commitSync(t, oa, ml, i)
		}
	}
	// flush the mutAccount
	commitSync(t, oa, ml, end)

	for i := start; i <= end; i++ {
		oad, err := oa.lookupOnlineAccountData(basics.Round(i), mutAccount.Addr)
		require.NoError(t, err)
		// rewardLevel is zero => MicroAlgos == MicroAlgosWithRewards
		expected := ad.AccountBaseData.MicroAlgos.Raw + uint64(i-start+1)*delta
		require.Equal(t, expected, oad.MicroAlgosWithRewards.Raw)
	}
}

// TestAcctOnlineCache toggles accounts from being online to offline and verifies
// that the db and cache have the correct data
func TestAcctOnlineCache(t *testing.T) {
	partitiontest.PartitionTest(t)

	const numAccts = 5
	const maxBalLookback = 3 * numAccts

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctOnline")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = maxBalLookback
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	for _, val := range []uint64{4, 8} {
		t.Run(fmt.Sprintf("lookback=%d", val), func(t *testing.T) {
			allAccts := make([]basics.BalanceRecord, numAccts)
			genesisAccts := []map[basics.Address]basics.AccountData{{}}
			genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts+1)
			for i := 0; i < numAccts; i++ {
				allAccts[i] = basics.BalanceRecord{
					Addr:        ledgertesting.RandomAddress(),
					AccountData: ledgertesting.RandomOnlineAccountData(0),
				}
				genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
			}

			addrA := ledgertesting.RandomAddress()
			acctA := ledgertesting.RandomOnlineAccountData(0)
			genesisAccts[0][addrA] = acctA

			addSinkAndPoolAccounts(genesisAccts)

			ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
			defer ml.Close()

			conf := config.GetDefaultLocal()
			conf.MaxAcctLookback = val
			maxDeltaLookback := conf.MaxAcctLookback

			au, oa := newAcctUpdates(t, ml, conf)
			defer oa.close()

			_, totals, err := au.LatestTotals()
			require.NoError(t, err)

			// check cache was initialized with db state
			for _, bal := range allAccts {
				oad, has := oa.onlineAccountsCache.read(bal.Addr, 0)
				require.True(t, has)
				require.NotEmpty(t, oad)
			}

			// online accounts tracker requires maxDeltaLookback block to start persisting
			targetRound := basics.Round(maxDeltaLookback * numAccts * 2)
			for i := basics.Round(1); i <= targetRound; i++ {
				var updates ledgercore.AccountDeltas
				acctIdx := (int(i) - 1) % numAccts

				// put all accts online, then all offline, one each round
				if (int(i)-1)%(numAccts*2) >= numAccts {
					updates.Upsert(allAccts[acctIdx].Addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})
				} else {
					updates.Upsert(allAccts[acctIdx].Addr, ledgercore.ToAccountData(allAccts[acctIdx].AccountData))
				}

				// set acctA online for each round
				updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: basics.VotingData{VoteLastValid: basics.Round(100 * i)}})

				base := genesisAccts[i-1]
				newAccts := applyPartialDeltas(base, updates)
				genesisAccts = append(genesisAccts, newAccts)

				// prepare block
				totals = newBlock(t, ml, testProtocolVersion, protoParams, i, base, updates, totals)

				// commit changes synchroniously
				commitSync(t, oa, ml, i)

				// check the table data and the cache
				// data gets committed after maxDeltaLookback
				if i > basics.Round(maxDeltaLookback) {
					rnd := i - basics.Round(maxDeltaLookback)
					acctIdx := (int(rnd) - 1) % numAccts
					bal := allAccts[acctIdx]
					data, err := oa.accountsq.LookupOnline(bal.Addr, rnd)
					require.NoError(t, err)
					require.Equal(t, bal.Addr, data.Addr)
					require.NotEmpty(t, data.Ref)
					require.Equal(t, oa.cachedDBRoundOnline, data.Round)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, data.AccountData)
					} else {
						require.NotEmpty(t, data.AccountData)
					}

					cachedData, has := oa.onlineAccountsCache.read(bal.Addr, rnd)
					require.True(t, has)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, cachedData.BaseOnlineAccountData)
					} else {
						require.NotEmpty(t, cachedData.BaseOnlineAccountData)
					}

					oad, err := oa.lookupOnlineAccountData(rnd, bal.Addr)
					require.NoError(t, err)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, oad)
					} else {
						require.NotEmpty(t, oad)
					}
				}

				// check data still persisted in cache and db
				if i > basics.Round(maxBalLookback+maxDeltaLookback) {
					rnd := i - basics.Round(maxBalLookback+maxDeltaLookback)
					acctIdx := (int(rnd) - 1) % numAccts
					bal := allAccts[acctIdx]
					data, err := oa.accountsq.LookupOnline(bal.Addr, rnd)
					require.NoError(t, err)
					require.Equal(t, bal.Addr, data.Addr)
					require.Equal(t, oa.cachedDBRoundOnline, data.Round)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, data.AccountData)
						require.Empty(t, data.Ref)
					} else {
						require.NotEmpty(t, data.Ref)
						require.NotEmpty(t, data.AccountData)
					}

					cachedData, has := oa.onlineAccountsCache.read(bal.Addr, rnd)
					require.True(t, has)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, cachedData.BaseOnlineAccountData)
					} else {
						require.NotEmpty(t, cachedData.BaseOnlineAccountData)
					}

					// committed round i => dbRound = i - maxDeltaLookback
					// lookup should correctly return data for earlist round dbRound - maxBalLookback + 1
					oad, err := oa.lookupOnlineAccountData(rnd+1, bal.Addr)
					require.NoError(t, err)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, oad)
					} else {
						require.NotEmpty(t, oad)
					}
				}
			}

			require.Equal(t, targetRound-basics.Round(maxDeltaLookback), oa.cachedDBRoundOnline)
			res, validThrough, err := oa.accountsq.LookupOnlineHistory(addrA)
			require.NoError(t, err)
			require.Equal(t, oa.cachedDBRoundOnline, validThrough)
			// +1 because of deletion before X, and not checking acct state at X
			require.Equal(t, int(maxBalLookback)+1, len(res))
			// ensure the cache length corresponds to DB
			require.Equal(t, len(res), oa.onlineAccountsCache.accounts[addrA].Len())
			for _, entry := range res {
				cached, has := oa.onlineAccountsCache.read(addrA, entry.UpdRound)
				require.True(t, has)
				require.Equal(t, entry.UpdRound, cached.updRound)
				require.Equal(t, entry.AccountData.VoteLastValid, cached.VoteLastValid)
			}

			// ensure correct behavior after deleting cache
			acctIdx := (int(targetRound) - 1) % numAccts
			bal := allAccts[acctIdx]
			delete(oa.onlineAccountsCache.accounts, bal.Addr)
			// the account acctIdx was modified:
			// at round targetRound - 0*numAccts and set offline (see the loop above)
			// at round targetRound - 1*numAccts it was set online
			// at round targetRound - 2*numAccts it was set offline...
			// find the oldest round in DB that is online and not deleted yet
			// 1. thus must be even cycles back
			// 2. this should be some cycles back from persisting round that is targetRound - maxDeltaLookback
			candidate := targetRound - basics.Round(maxDeltaLookback) - maxBalLookback
			cycle := (targetRound - candidate) / numAccts
			oldRound := candidate - candidate%numAccts
			if cycle%4 != 0 {
				oldRound += numAccts
			}
			expectedRound := oldRound
			minLookupRound := targetRound - basics.Round(maxBalLookback+maxDeltaLookback) + 1
			if oldRound < minLookupRound {
				// if below than the min round online accounts support than adjust
				oldRound = minLookupRound
			}

			// cache should be repopulated on this command
			oa.lookupOnlineAccountData(oldRound, bal.Addr)
			cachedData, has := oa.onlineAccountsCache.read(bal.Addr, oldRound)
			require.True(t, has)
			require.Equal(t, expectedRound, cachedData.updRound)
			require.NotEmpty(t, cachedData.BaseOnlineAccountData)

			// cache should contain data for new rounds
			// (the last entry should be offline)
			// check at targetRound - 10 because that is the latest round written to db
			newRound := targetRound - basics.Round(10)
			cachedData, has = oa.onlineAccountsCache.read(bal.Addr, newRound)
			require.True(t, has)
			require.Equal(t, newRound, cachedData.updRound)
			require.Empty(t, cachedData.BaseOnlineAccountData)

		})
	}
}

// TestAcctOnlineRoundParamsOffset checks that roundParamsOffset return the correct indices.
func TestAcctOnlineRoundParamsOffset(t *testing.T) {
	partitiontest.PartitionTest(t)

	ao := onlineAccounts{}

	ao.cachedDBRoundOnline = 0
	ao.deltas = make([]ledgercore.AccountDeltas, 10)
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, 11)
	offset, err := ao.roundParamsOffset(basics.Round(6))
	require.NoError(t, err)
	require.Equal(t, uint64(6), offset)

	ao.cachedDBRoundOnline = 3 // latest = 3 + 10 = 13
	ao.deltas = make([]ledgercore.AccountDeltas, 10)
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, 11)
	offset, err = ao.roundParamsOffset(basics.Round(6))
	require.NoError(t, err)
	require.Equal(t, uint64(3), offset)

	ao.cachedDBRoundOnline = 7 // latest = 9
	ao.deltas = make([]ledgercore.AccountDeltas, 2)
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, 10)
	offset, err = ao.roundParamsOffset(basics.Round(5))
	require.NoError(t, err)
	require.Equal(t, uint64(5), offset)

	ao.cachedDBRoundOnline = 7 // latest = 9
	ao.deltas = make([]ledgercore.AccountDeltas, 2)
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, 7)
	offset, err = ao.roundParamsOffset(basics.Round(5))
	require.NoError(t, err)
	require.Equal(t, uint64(2), offset)

	ao.cachedDBRoundOnline = 400
	ao.deltas = make([]ledgercore.AccountDeltas, 10)
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, 331)
	offset, err = ao.roundParamsOffset(basics.Round(100))
	require.NoError(t, err)
	require.Equal(t, uint64(20), offset)

	ao.cachedDBRoundOnline = 400
	ao.deltas = make([]ledgercore.AccountDeltas, 10)
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, 331)
	offset, err = ao.roundParamsOffset(basics.Round(6))
	require.Error(t, err)
	require.Zero(t, offset)

	ao.cachedDBRoundOnline = 400
	ao.deltas = nil
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, 1)
	offset, err = ao.roundParamsOffset(basics.Round(400))
	require.NoError(t, err)
	require.Equal(t, uint64(0), offset)

	ao.cachedDBRoundOnline = 400
	ao.deltas = nil
	ao.onlineRoundParamsData = nil
	offset, err = ao.roundParamsOffset(basics.Round(400))
	require.Error(t, err)
	require.Zero(t, offset)
}

// TestAcctOnlineRoundParamsCache tests that the ao.onlineRoundParamsData cache and
// the onlineRoundParamsData db are synced and contain the right data after a series
// of new blocks are added to the ledger. Also ensure that these data structures are
// trimmed properly to hold only proto.MaxBalLookback entries.
func TestAcctOnlineRoundParamsCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	const maxBalLookback = 100
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = maxBalLookback
	testProtocolVersion1 := protocol.ConsensusVersion("test-protocol-TestAcctOnline1")
	config.Consensus[testProtocolVersion1] = protoParams
	testProtocolVersion2 := protocol.ConsensusVersion("test-protocol-TestAcctOnline2")
	config.Consensus[testProtocolVersion2] = protoParams
	testProtocolVersion3 := protocol.ConsensusVersion("test-protocol-TestAcctOnline3")
	config.Consensus[testProtocolVersion3] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion1)
		delete(config.Consensus, testProtocolVersion2)
		delete(config.Consensus, testProtocolVersion3)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	addSinkAndPoolAccounts(accts)

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion1, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, ao := newAcctUpdates(t, ml, conf)
	// au and ao are closed via ml.Close() -> ml.trackers.close()

	// cover 10 genesis blocks
	rewardLevel := uint64(0)
	for i := 1; i < 10; i++ {
		accts = append(accts, accts[0])
	}

	allTotals := make(map[basics.Round]ledgercore.AccountTotals)

	start := basics.Round(10)
	end := basics.Round(2*maxBalLookback + 15)
	for i := start; i < end; i++ {
		consensusVersion := testProtocolVersion1
		if i > basics.Round(maxBalLookback) {
			consensusVersion = testProtocolVersion2
		}
		if i > 2*basics.Round(maxBalLookback) {
			consensusVersion = testProtocolVersion3
		}
		rewardLevelDelta := crypto.RandUint64() % 3
		rewardLevel += rewardLevelDelta
		var updates ledgercore.AccountDeltas
		var totals map[basics.Address]ledgercore.AccountData
		base := accts[i-1]
		updates, totals = ledgertesting.RandomDeltasBalanced(1, base, rewardLevel)
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
		blk.CurrentProtocol = consensusVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)

		delta.Totals = accumulateTotals(t, consensusVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		allTotals[i] = delta.Totals
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)

		if i > basics.Round(maxBalLookback) && i%10 == 0 {
			onlineTotal, err := ao.onlineCirculation(i-basics.Round(maxBalLookback), i)
			require.NoError(t, err)
			require.Equal(t, allTotals[i-basics.Round(maxBalLookback)].Online.Money, onlineTotal)
			expectedConsensusVersion := testProtocolVersion1
			if i > 2*basics.Round(maxBalLookback) {
				expectedConsensusVersion = testProtocolVersion2
			}
			roundParamsOffset, err := ao.roundParamsOffset(i - basics.Round(maxBalLookback))
			require.NoError(t, err)
			require.Equal(t, expectedConsensusVersion, ao.onlineRoundParamsData[roundParamsOffset].CurrentProtocol)
			expectedConsensusVersion = testProtocolVersion2
			if i > 2*basics.Round(maxBalLookback) {
				expectedConsensusVersion = testProtocolVersion3
			}
			roundParamsOffset, err = ao.roundParamsOffset(i)
			require.NoError(t, err)
			require.Equal(t, expectedConsensusVersion, ao.onlineRoundParamsData[roundParamsOffset].CurrentProtocol)
		}
	}

	ml.trackers.lastFlushTime = time.Time{}

	ml.trackers.committedUpTo(2*basics.Round(maxBalLookback) + 14)
	ml.trackers.waitAccountsWriting()

	var dbOnlineRoundParams []ledgercore.OnlineRoundParamsData
	var endRound basics.Round
	err := ao.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}

		dbOnlineRoundParams, endRound, err = ar.AccountsOnlineRoundParams()
		return err
	})
	require.NoError(t, err)
	require.Equal(t, ao.cachedDBRoundOnline, endRound)
	require.Equal(t, ao.onlineRoundParamsData[:basics.Round(maxBalLookback)], dbOnlineRoundParams)

	for i := ml.Latest() - basics.Round(maxBalLookback); i < ml.Latest(); i++ {
		onlineTotal, err := ao.onlineCirculation(i, i+basics.Round(maxBalLookback))
		require.NoError(t, err)
		require.Equal(t, allTotals[i].Online.Money, onlineTotal)
	}
}

// TestAcctOnlineCacheDBSync checks if lookup happens in between db commit and the cache update
// the online account tracker returns correct data
func TestAcctOnlineCacheDBSync(t *testing.T) {
	partitiontest.PartitionTest(t)

	const seedLookback = 2
	const seedInteval = 3
	const maxBalLookback = 2 * seedLookback * seedInteval

	const numAccts = maxBalLookback * 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	for i := 0; i < numAccts; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr:        ledgertesting.RandomAddress(),
			AccountData: ledgertesting.RandomOnlineAccountData(0),
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}

	addSinkAndPoolAccounts(genesisAccts)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctOnlineCacheDBSync")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = maxBalLookback
	protoParams.SeedLookback = seedLookback
	protoParams.SeedRefreshInterval = seedInteval
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	addrA := allAccts[0].Addr

	copyGenesisAccts := func() []map[basics.Address]basics.AccountData {
		accounts := []map[basics.Address]basics.AccountData{{}}
		accounts[0] = make(map[basics.Address]basics.AccountData, numAccts)
		maps.Copy(accounts[0], genesisAccts[0])
		return accounts
	}

	// test 1: large deltas, have addrA offline in deltas, ensure it works
	t.Run("large-delta-go-offline", func(t *testing.T) {
		ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
		defer ml.Close()
		conf := config.GetDefaultLocal()
		conf.MaxAcctLookback = maxBalLookback

		au, oa := newAcctUpdates(t, ml, conf)
		defer oa.close()
		_, totals, err := au.LatestTotals()
		require.NoError(t, err)

		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})

		// copy genesisAccts for the test
		accounts := copyGenesisAccts()
		base := accounts[0]
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)

		// prepare block
		totals = newBlock(t, ml, testProtocolVersion, protoParams, 1, base, updates, totals)
		// commit changes synchroniously
		commitSync(t, oa, ml, 1)

		// add maxBalLookback empty blocks
		for i := 2; i <= maxBalLookback; i++ {
			var updates ledgercore.AccountDeltas
			base := accounts[i-1]
			totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
			accounts = append(accounts, newAccts)
			commitSync(t, oa, ml, basics.Round(i))
		}
		// ensure addrA is in deltas
		macct, has := oa.accounts[addrA]
		require.True(t, has)
		require.Equal(t, 1, macct.ndeltas)
		// and the cache has the prev value
		cachedData, has := oa.onlineAccountsCache.read(addrA, 1)
		require.True(t, has)
		require.NotEmpty(t, cachedData.VoteLastValid)
		// lookup and check the value returned is offline
		data, err := oa.lookupOnlineAccountData(1, addrA)
		require.NoError(t, err)
		require.Empty(t, data.VotingData.VoteLastValid)

		// commit the next block
		// and simulate lookup in between committing the db and updating the cache
		updates = ledgercore.AccountDeltas{}
		rnd := maxBalLookback + 1
		base = accounts[rnd-1]
		totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(rnd), base, updates, totals)
		dcc := commitSyncPartial(t, oa, ml, basics.Round(rnd))
		// defer in order to recover from ml.trackers.accountsWriting.Wait()
		defer func() {
			// complete the commit and check lookup again
			commitSyncPartialComplete(t, oa, ml, dcc)
			_, has = oa.accounts[addrA]
			require.False(t, has)
			cachedData, has = oa.onlineAccountsCache.read(addrA, 1)
			require.True(t, has)
			require.Empty(t, cachedData.VoteLastValid)
			data, err = oa.lookupOnlineAccountData(1, addrA)
			require.NoError(t, err)
			require.Empty(t, data.VotingData.VoteLastValid)
		}()

		// ensure the data still in deltas, not in the cache and lookupOnlineAccountData still return a correct value
		macct, has = oa.accounts[addrA]
		require.True(t, has)
		require.Equal(t, 1, macct.ndeltas)
		cachedData, has = oa.onlineAccountsCache.read(addrA, 1)
		require.True(t, has)
		require.NotEmpty(t, cachedData.VoteLastValid)
		data, err = oa.lookupOnlineAccountData(1, addrA)
		require.NoError(t, err)
		require.Empty(t, data.VotingData.VoteLastValid)
	})

	// test 2: small deltas, have addrA offline in DB and in the cache, ensure it works
	t.Run("small-delta-go-offline", func(t *testing.T) {
		ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
		defer ml.Close()
		conf := config.GetDefaultLocal()
		conf.MaxAcctLookback = 4

		au, oa := newAcctUpdates(t, ml, conf)
		defer oa.close()
		_, totals, err := au.LatestTotals()
		require.NoError(t, err)

		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})

		// copy genesisAccts for the test
		accounts := copyGenesisAccts()
		base := accounts[0]
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)

		// prepare block
		totals = newBlock(t, ml, testProtocolVersion, protoParams, 1, base, updates, totals)
		// commit changes synchroniously
		commitSync(t, oa, ml, 1)

		// add maxBalLookback empty blocks
		for i := 2; i <= maxBalLookback; i++ {
			var updates ledgercore.AccountDeltas
			base := accounts[i-1]
			totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
			accounts = append(accounts, newAccts)
			commitSync(t, oa, ml, basics.Round(i))
		}
		// ensure addrA not in deltas, in the cache and lookupOnlineAccountData returns a correct value
		_, has := oa.accounts[addrA]
		require.False(t, has)
		cachedData, has := oa.onlineAccountsCache.read(addrA, 1)
		require.True(t, has)
		require.Empty(t, cachedData.VoteLastValid)
		data, err := oa.lookupOnlineAccountData(1, addrA)
		require.NoError(t, err)
		require.Empty(t, data.VotingData.VoteLastValid)
	})

	// test 3: max deltas size = 1 => all deltas committed but not written to the cache
	// addrA does offline, both online and offline entries gets removed from the DB but the cache
	// must returns a correct value
	t.Run("no-delta-go-offline-delete", func(t *testing.T) {
		ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
		defer ml.Close()
		conf := config.GetDefaultLocal()
		const maxDeltaLookback = 0
		conf.MaxAcctLookback = maxDeltaLookback

		au, oa := newAcctUpdates(t, ml, conf)
		defer oa.close()
		_, totals, err := au.LatestTotals()
		require.NoError(t, err)

		addrB := ledgertesting.RandomAddress()
		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})
		updates.Upsert(addrB, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: basics.VotingData{VoteLastValid: 10000}})

		// copy genesisAccts for the test
		accounts := copyGenesisAccts()
		base := accounts[0]
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)

		// prepare block
		totals = newBlock(t, ml, testProtocolVersion, protoParams, 1, base, updates, totals)
		// commit changes synchroniously
		commitSync(t, oa, ml, 1)

		// add maxDeltaLookback empty blocks
		for i := 2; i <= maxBalLookback; i++ {
			var updates ledgercore.AccountDeltas
			base := accounts[i-1]
			totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
			accounts = append(accounts, newAccts)
			commitSync(t, oa, ml, basics.Round(i))
		}
		// ensure addrA not in deltas, in the cache and lookupOnlineAccountData returns a correct value
		_, has := oa.accounts[addrA]
		require.False(t, has)
		cachedData, has := oa.onlineAccountsCache.read(addrA, 1)
		require.True(t, has)
		require.Empty(t, cachedData.VoteLastValid)
		data, err := oa.lookupOnlineAccountData(1, addrA)
		require.NoError(t, err)
		require.Empty(t, data.VotingData.VoteLastValid)
		// ensure offline entry is in DB as well
		pad, err := oa.accountsq.LookupOnline(addrA, 1)
		require.NoError(t, err)
		require.Equal(t, addrA, pad.Addr)
		require.NotEmpty(t, pad.Ref)
		require.Empty(t, pad.AccountData.VoteLastValid)

		// commit a block to get these entries removed
		// ensure the DB entry gone, the cache has it and lookupOnlineAccountData works as expected
		updates = ledgercore.AccountDeltas{}
		rnd := maxBalLookback + 1
		base = accounts[rnd-1]
		totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(rnd), base, updates, totals)
		dcc := commitSyncPartial(t, oa, ml, basics.Round(rnd))
		// defer in order to recover from ml.trackers.accountsWriting.Wait()
		defer func() {
			// complete the commit and check lookup again
			commitSyncPartialComplete(t, oa, ml, dcc)
			_, has = oa.accounts[addrA]
			require.False(t, has)
			cachedData, has = oa.onlineAccountsCache.read(addrA, 1)
			require.False(t, has)
			require.Empty(t, cachedData.VoteLastValid)
			// round 1 is out of max history
			data, err = oa.lookupOnlineAccountData(1, addrA)
			require.Error(t, err)
			data, err = oa.lookupOnlineAccountData(2, addrA)
			require.NoError(t, err)
			require.Empty(t, data.VotingData.VoteLastValid)

			_, has = oa.onlineAccountsCache.read(addrB, 1)
			require.True(t, has) // full history loaded when looked up addrB prev time
			_, err = oa.lookupOnlineAccountData(1, addrB)
			require.Error(t, err)
			pad, err = oa.accountsq.LookupOnline(addrB, 1)
			require.NoError(t, err)
			require.Equal(t, addrB, pad.Addr)
			require.NotEmpty(t, pad.Ref)
			require.NotEmpty(t, pad.AccountData.VoteLastValid)
		}()

		// ensure the data not in deltas, in the cache and lookupOnlineAccountData still return a correct value
		_, has = oa.accounts[addrA]
		require.False(t, has)
		cachedData, has = oa.onlineAccountsCache.read(addrA, 1)
		require.True(t, has)
		require.Empty(t, cachedData.VoteLastValid)
		data, err = oa.lookupOnlineAccountData(1, addrA)
		require.NoError(t, err)
		require.Empty(t, data.VotingData.VoteLastValid)
		pad, err = oa.accountsq.LookupOnline(addrA, 1)
		require.NoError(t, err)
		require.Equal(t, addrA, pad.Addr)
		require.Empty(t, pad.Ref)
		require.Empty(t, pad.AccountData.VoteLastValid)

		_, has = oa.accounts[addrB]
		require.False(t, has)
		cachedData, has = oa.onlineAccountsCache.read(addrB, 1)
		require.False(t, has) // cache miss, we do not write into the cache non-complete history after updates
		require.Empty(t, cachedData.VoteLastValid)

		data, err = oa.lookupOnlineAccountData(1, addrB)
		require.NoError(t, err)
		require.NotEmpty(t, data.VotingData.VoteLastValid)

		pad, err = oa.accountsq.LookupOnline(addrB, 1)
		require.NoError(t, err)
		require.Equal(t, addrB, pad.Addr)
		require.NotEmpty(t, pad.Ref)
		require.NotEmpty(t, pad.AccountData.VoteLastValid)
	})
}

// TestAcctOnlineBaseAccountCache checks the data correctness for a case when
// some accounts gets online and then offline in the same commit range,
// and then online again in the next range with the same voting data
func TestAcctOnlineBaseAccountCache(t *testing.T) {
	partitiontest.PartitionTest(t)

	const seedLookback = 2
	const seedInteval = 3
	const maxBalLookback = 2 * seedLookback * seedInteval

	const numAccts = 5 // does not matter, some number of accounts
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	var addrA basics.Address
	for i := 0; i < numAccts; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr:        ledgertesting.RandomAddress(),
			AccountData: ledgertesting.RandomOnlineAccountData(0),
		}
		if i == 0 {
			addrA = allAccts[i].Addr
			allAccts[i].AccountData.Status = basics.Offline
			allAccts[i].AccountData.VoteLastValid = 0
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}

	addSinkAndPoolAccounts(genesisAccts)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctOnlineBaseAccountCache")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = maxBalLookback
	protoParams.SeedLookback = seedLookback
	protoParams.SeedRefreshInterval = seedInteval
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
	defer ml.Close()
	conf := config.GetDefaultLocal()
	conf.MaxAcctLookback = maxBalLookback

	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()
	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	accounts := genesisAccts

	acctDatas := [3]ledgercore.AccountData{
		{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: basics.VotingData{VoteLastValid: basics.Round(1000 + maxBalLookback)}},
		{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}},
		{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: basics.VotingData{VoteLastValid: basics.Round(1000 + maxBalLookback)}},
	}
	// set online, offline, online
	for i := 1; i <= 3; i++ {
		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, acctDatas[i-1])
		base := accounts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)
		totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
	}

	// add maxBalLookback + 2 empty blocks and next commit would commit the first two rounds
	for i := 4; i <= maxBalLookback+2; i++ {
		var updates ledgercore.AccountDeltas
		base := accounts[i-1]
		totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
		accounts = append(accounts, base)
	}

	rnd := maxBalLookback + 2
	commitSync(t, oa, ml, basics.Round(rnd))
	poad, has := oa.baseOnlineAccounts.read(addrA)
	require.True(t, has)
	require.Empty(t, poad.AccountData)

	data, err := oa.lookupOnlineAccountData(2, addrA)
	require.NoError(t, err)
	require.Empty(t, data.VotingData.VoteLastValid)

	// add one more and next commit would commit the third rounds
	{
		i := rnd + 1
		var updates ledgercore.AccountDeltas
		base := accounts[i-1]
		totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
		commitSync(t, oa, ml, basics.Round(i))
	}

	poad, has = oa.baseOnlineAccounts.read(addrA)
	require.True(t, has)
	require.NotEmpty(t, poad.AccountData)

	data, err = oa.lookupOnlineAccountData(basics.Round(3), addrA)
	require.NoError(t, err)
	require.NotEmpty(t, data.VotingData.VoteLastValid)

	data, err = oa.lookupOnlineAccountData(basics.Round(rnd+1), addrA)
	require.NoError(t, err)
	require.NotEmpty(t, data.VotingData.VoteLastValid)
}

func TestAcctOnlineVotersLongerHistory(t *testing.T) {
	partitiontest.PartitionTest(t)

	const seedLookback = 3
	const seedInteval = 4
	const maxBalLookback = 2 * seedLookback * seedInteval
	const stateProofRounds = maxBalLookback / 2 // have it less than maxBalLookback but greater than default deltas size (8)
	const stateProofVotersLookback = 2

	const numAccts = maxBalLookback * 5
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	var addrA basics.Address
	for i := 0; i < numAccts; i++ {
		addr := ledgertesting.RandomAddress()
		genesisAccts[0][addr] = ledgertesting.RandomOnlineAccountData(0)
		if addrA.IsZero() {
			addrA = addr
		}
	}

	addSinkAndPoolAccounts(genesisAccts)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestAcctOnlineCacheDBSync")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = maxBalLookback
	protoParams.SeedLookback = seedLookback
	protoParams.SeedRefreshInterval = seedInteval
	protoParams.StateProofInterval = stateProofRounds
	protoParams.StateProofVotersLookback = stateProofVotersLookback
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
	defer ml.Close()
	conf := config.GetDefaultLocal()

	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()
	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	// add maxBalLookback empty blocks
	maxBlocks := maxBalLookback * 5
	for i := 1; i <= maxBlocks; i++ {
		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: basics.VotingData{VoteLastValid: basics.Round(100 * i)}})
		base := genesisAccts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		totals = newBlock(t, ml, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
		genesisAccts = append(genesisAccts, newAccts)
		commitSync(t, oa, ml, basics.Round(i))
	}
	require.Len(t, oa.deltas, int(conf.MaxAcctLookback))
	require.Equal(t, basics.Round(maxBlocks-int(conf.MaxAcctLookback)), oa.cachedDBRoundOnline)
	// voters stalls after the first interval
	lowest := oa.voters.lowestRound(oa.cachedDBRoundOnline)
	require.Equal(t, basics.Round(stateProofRounds-stateProofVotersLookback), lowest)
	require.Equal(t, maxBlocks/stateProofRounds, len(oa.voters.votersForRoundCache))
	retain, lookback := oa.committedUpTo(oa.latest())
	require.Equal(t, lowest, retain)
	require.Equal(t, conf.MaxAcctLookback, uint64(lookback))

	// onlineRoundParamsData does not store more than maxBalLookback + deltas even if voters stall
	require.Equal(t, uint64(len(oa.onlineRoundParamsData)), maxBalLookback+conf.MaxAcctLookback)

	// DB has all the required history tho
	var dbOnlineRoundParams []ledgercore.OnlineRoundParamsData
	var endRound basics.Round
	err = oa.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}

		dbOnlineRoundParams, endRound, err = ar.AccountsOnlineRoundParams()
		return err
	})

	require.NoError(t, err)
	require.Equal(t, oa.latest()-basics.Round(conf.MaxAcctLookback), endRound)
	require.Equal(t, maxBlocks-int(lowest)-int(conf.MaxAcctLookback)+1, len(dbOnlineRoundParams))
	require.Equal(t, endRound, oa.cachedDBRoundOnline)

	_, err = oa.onlineTotalsEx(lowest)
	require.NoError(t, err)

	_, err = oa.onlineTotalsEx(lowest - 1)
	require.ErrorIs(t, err, trackerdb.ErrNotFound)

	// ensure the cache size for addrA does not have more entries than maxBalLookback + 1
	// +1 comes from the deletion before X without checking account state at X
	require.Equal(t, maxBalLookback+1, oa.onlineAccountsCache.accounts[addrA].Len())

	// Test if "excludeBefore" argument works for MakeOnlineAccountsIter & MakeOnlineRoundParamsIter
	// when longer history is being used. Exclude rows older than round=lowest+2
	excludeRound := lowest + 2

	// Test MakeOnlineAccountsIter
	var foundCount int
	err = oa.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) error {
		// read staging = false, excludeBefore = excludeRound
		it, err2 := tx.MakeOrderedOnlineAccountsIter(ctx, false, excludeRound)
		require.NoError(t, err2)
		defer it.Close()

		firstSeen := make(map[basics.Address]basics.Round)
		for it.Next() {
			acct, acctErr := it.GetItem()
			require.NoError(t, acctErr)
			// We expect all rows to either:
			// - have updRound >= excludeRound
			// - or have updRound < excludeRound, and only appear once in the iteration (no updates since excludeRound)
			if acct.UpdateRound < excludeRound {
				require.NotContains(t, firstSeen, acct.Address, "MakeOnlineAccountsIter produced two rows acct %s for dbRound %d updRound %d < excludeRound %d (first seen %d)", acct.Address, endRound, acct.UpdateRound, excludeRound, firstSeen[acct.Address])
			}
			firstSeen[acct.Address] = acct.UpdateRound
			foundCount++
		}
		return nil
	})
	require.NoError(t, err)
	require.True(t, foundCount > 0, "Should see some accounts that satisfy updRound >= excludeRound")

	// Test MakeOnlineRoundParamsIter
	foundCount = 0
	err = oa.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) error {
		it, err2 := tx.MakeOnlineRoundParamsIter(ctx, false, excludeRound)
		require.NoError(t, err2)
		defer it.Close()

		for it.Next() {
			roundParams, roundParamsErr := it.GetItem()
			require.NoError(t, roundParamsErr)
			require.True(t, roundParams.Round >= excludeRound, "MakeOnlineRoundParamsIter produced row for round %d < excludeRound %d", roundParams.Round, excludeRound)
			foundCount++
		}
		return nil
	})
	require.NoError(t, err)
	require.EqualValues(t, endRound-excludeRound+1, foundCount, "Should see all round params for rounds >= excludeRound")
}

// compareTopAccounts makes sure that accounts returned from OnlineTop function are sorted and contains the online accounts on the test
func compareTopAccounts(a *require.Assertions, testingResult []*ledgercore.OnlineAccount, expectedAccountsBalances []basics.BalanceRecord) {
	isSorted := sort.SliceIsSorted(testingResult, func(i, j int) bool {
		return testingResult[i].NormalizedOnlineBalance > testingResult[j].NormalizedOnlineBalance
	})
	a.Equal(true, isSorted)

	var onlineAccoutsFromTests []*ledgercore.OnlineAccount
	for i := 0; i < len(expectedAccountsBalances); i++ {
		if expectedAccountsBalances[i].Status != basics.Online {
			continue
		}
		onlineAccoutsFromTests = append(onlineAccoutsFromTests, &ledgercore.OnlineAccount{
			Address:                 expectedAccountsBalances[i].Addr,
			MicroAlgos:              expectedAccountsBalances[i].MicroAlgos,
			RewardsBase:             0,
			NormalizedOnlineBalance: expectedAccountsBalances[i].AccountData.NormalizedOnlineBalance(config.Consensus[protocol.ConsensusCurrentVersion].RewardUnit),
			VoteFirstValid:          expectedAccountsBalances[i].VoteFirstValid,
			VoteLastValid:           expectedAccountsBalances[i].VoteLastValid})
	}

	sort.Slice(onlineAccoutsFromTests[:], func(i, j int) bool {
		return onlineAccoutsFromTests[i].MicroAlgos.Raw > onlineAccoutsFromTests[j].MicroAlgos.Raw
	})

	for i := 0; i < len(testingResult); i++ {
		a.Equal(*onlineAccoutsFromTests[i], *testingResult[i])
	}

}

func addSinkAndPoolAccounts(genesisAccts []map[basics.Address]basics.AccountData) {
	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 100 * 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	genesisAccts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	genesisAccts[0][testSinkAddr] = sinkdata
}

func newBlockWithUpdates(genesisAccts []map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, prevTotals ledgercore.AccountTotals, t *testing.T, ml *mockLedgerForTracker, round int, oa *onlineAccounts) ledgercore.AccountTotals {
	base := genesisAccts[0]
	proto := ml.GenesisProtoVersion()
	params := ml.GenesisProto()
	newTotals := newBlock(t, ml, proto, params, basics.Round(round), base, updates, prevTotals)
	commitSync(t, oa, ml, basics.Round(round))
	return newTotals
}

func TestAcctOnlineTop(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	algops := MicroAlgoOperations{a: a}

	const numAccts = 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	i := 0
	for ; i < numAccts/2; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr: ledgertesting.RandomAddress(),
			AccountData: basics.AccountData{
				MicroAlgos:  basics.MicroAlgos{Raw: uint64(i + 1)},
				Status:      basics.Offline,
				RewardsBase: 0},
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}
	for ; i < numAccts-1; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr: ledgertesting.RandomAddress(),
			AccountData: basics.AccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: uint64(i + 1)},
				Status:         basics.Online,
				VoteLastValid:  1000,
				VoteFirstValid: 0,
				RewardsBase:    0},
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}
	// offline account with high balance
	allAccts[i] = basics.BalanceRecord{
		Addr: ledgertesting.RandomAddress(),
		AccountData: basics.AccountData{
			MicroAlgos:  basics.MicroAlgos{Raw: uint64(100000)},
			Status:      basics.Offline,
			RewardsBase: 0},
	}
	genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	addSinkAndPoolAccounts(genesisAccts)

	// run this test on ConsensusV37 rules, run TestAcctOnlineTop_ChangeOnlineStake on current
	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusV37, genesisAccts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()
	initialOnlineTotals, err := oa.onlineCirculation(0, basics.Round(oa.maxBalLookback()))
	a.NoError(err)
	top := compareOnlineTotals(a, oa, 0, 0, 5, initialOnlineTotals, initialOnlineTotals)
	compareTopAccounts(a, top, allAccts)

	_, totals, err := au.LatestTotals()
	a.NoError(err)

	// mark one of the top N accounts as offline - we expect that it will be removed form the top N
	var updates ledgercore.AccountDeltas
	ac := allAccts[numAccts-3]
	updates.Upsert(ac.Addr, ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline, MicroAlgos: ac.MicroAlgos}, VotingData: basics.VotingData{}})
	totals = newBlockWithUpdates(genesisAccts, updates, totals, t, ml, 1, oa)
	accountToBeUpdated := ac
	accountToBeUpdated.Status = basics.Offline
	allAccts[numAccts-3] = accountToBeUpdated

	updatedOnlineStake := algops.Sub(initialOnlineTotals, ac.MicroAlgos)
	top = compareOnlineTotals(a, oa, 1, 1, 5, updatedOnlineStake, updatedOnlineStake)
	compareTopAccounts(a, top, allAccts)

	// update an account to have expired keys
	updates = ledgercore.AccountDeltas{}
	updates.Upsert(allAccts[numAccts-2].Addr, ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: allAccts[numAccts-2].MicroAlgos},
		VotingData: basics.VotingData{
			VoteFirstValid: 0,
			VoteLastValid:  1,
		}})
	totals = newBlockWithUpdates(genesisAccts, updates, totals, t, ml, 2, oa)
	// we expect the previous account to be removed from the top N accounts since its keys are expired.
	// remove it from the expected allAccts slice by marking it as offline
	accountToBeUpdated = allAccts[numAccts-2]
	accountToBeUpdated.Status = basics.Offline
	allAccts[numAccts-2] = accountToBeUpdated

	notValidAccountStake := accountToBeUpdated.MicroAlgos
	voteRndExpectedOnlineStake := algops.Sub(updatedOnlineStake, notValidAccountStake)
	top = compareOnlineTotals(a, oa, 2, 2, 5, updatedOnlineStake, voteRndExpectedOnlineStake)
	compareTopAccounts(a, top, allAccts)

	// mark an account with high stake as online - it should be pushed to the top of the list
	updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: allAccts[numAccts-1].MicroAlgos},
		VotingData:      basics.VotingData{VoteLastValid: basics.Round(1000)}})
	totals = newBlockWithUpdates(genesisAccts, updates, totals, t, ml, 3, oa)
	accountToBeUpdated = allAccts[numAccts-1]
	accountToBeUpdated.Status = basics.Online
	accountToBeUpdated.MicroAlgos = allAccts[numAccts-1].MicroAlgos
	accountToBeUpdated.VoteLastValid = basics.Round(1000)
	allAccts[numAccts-1] = accountToBeUpdated

	updatedOnlineStake = algops.Add(updatedOnlineStake, accountToBeUpdated.MicroAlgos)
	voteRndExpectedOnlineStake = algops.Add(voteRndExpectedOnlineStake, accountToBeUpdated.MicroAlgos)
	top = compareOnlineTotals(a, oa, 3, 3, 5, updatedOnlineStake, voteRndExpectedOnlineStake)
	compareTopAccounts(a, top, allAccts)

	a.Equal(top[0].Address, allAccts[numAccts-1].Addr)
}

func TestAcctOnlineTopInBatches(t *testing.T) {
	partitiontest.PartitionTest(t)

	intToAddress := func(n int) basics.Address {
		var addr basics.Address
		pos := 0
		for {
			addr[pos] = byte(n % 10)
			n /= 10
			if n == 0 {
				break
			}
			pos++
		}
		return addr
	}

	const numAccts = 2048
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)

	for i := 0; i < numAccts; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr: intToAddress(i + 1),
			AccountData: basics.AccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: uint64(i + 1)},
				Status:         basics.Online,
				VoteLastValid:  basics.Round(i + 1),
				VoteFirstValid: 0,
				RewardsBase:    0},
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}
	addSinkAndPoolAccounts(genesisAccts)

	for _, proto := range []protocol.ConsensusVersion{protocol.ConsensusV36, protocol.ConsensusFuture} {
		t.Run(string(proto), func(t *testing.T) {
			a := require.New(t)
			params := config.Consensus[proto]
			ml := makeMockLedgerForTracker(t, true, 1, proto, genesisAccts)
			defer ml.Close()

			conf := config.GetDefaultLocal()
			au, oa := newAcctUpdates(t, ml, conf)
			defer oa.close()

			top, totalOnlineStake, err := oa.TopOnlineAccounts(0, 0, numAccts, &params, 0)
			a.NoError(err)
			compareTopAccounts(a, top, allAccts)
			a.Equal(basics.MicroAlgos{Raw: 2048 * 2049 / 2}, totalOnlineStake)

			// add 300 blocks so the first 300 accounts expire
			// at the last block put the 299th account offline to trigger TopOnlineAccounts behavior difference
			_, totals, err := au.LatestTotals()
			a.NoError(err)
			acct299 := allAccts[298]
			for i := 1; i <= 300; i++ {
				var updates ledgercore.AccountDeltas
				if i == 300 {
					updates.Upsert(acct299.Addr, ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline, MicroAlgos: acct299.MicroAlgos},
						VotingData:      basics.VotingData{},
					})
				}
				newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
			}
			a.Equal(basics.Round(300), oa.latest())

			// 299 accts expired at voteRnd = 300
			top, totalOnlineStake, err = oa.TopOnlineAccounts(0, 300, numAccts, &params, 0)
			a.NoError(err)
			compareTopAccounts(a, top, allAccts)
			a.Equal(basics.MicroAlgos{Raw: 2048*2049/2 - 299*300/2}, totalOnlineStake)

			// check the behavior difference between ConsensusV36 and ConsensusFuture
			var correction uint64
			if proto == protocol.ConsensusV36 {
				correction = acct299.MicroAlgos.Raw
			}
			_, totalOnlineStake, err = oa.TopOnlineAccounts(300, 300, numAccts, &params, 0)
			a.NoError(err)
			a.Equal(basics.MicroAlgos{Raw: 2048*2049/2 - 299*300/2 - correction}, totalOnlineStake)
		})
	}
}

func TestAcctOnlineTopBetweenCommitAndPostCommit(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const numAccts = 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)

	for i := 0; i < numAccts; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr: ledgertesting.RandomAddress(),
			AccountData: basics.AccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: uint64(i + 1)},
				Status:         basics.Online,
				VoteLastValid:  1000,
				VoteFirstValid: 0,
				RewardsBase:    0},
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}
	addSinkAndPoolAccounts(genesisAccts)

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, genesisAccts)
	defer ml.Close()

	stallingTracker := &blockingTracker{
		postCommitUnlockedEntryLock:   make(chan struct{}),
		postCommitUnlockedReleaseLock: make(chan struct{}),
		postCommitEntryLock:           make(chan struct{}),
		postCommitReleaseLock:         make(chan struct{}),
	}

	conf := config.GetDefaultLocal()
	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()
	ml.trackers.trackers = append([]ledgerTracker{stallingTracker}, ml.trackers.trackers...)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	top, _, err := oa.TopOnlineAccounts(0, 0, 5, &proto, 0)
	a.NoError(err)
	compareTopAccounts(a, top, allAccts)

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	// apply some rounds so the db round will make progress (not be 0) - i.e since the max lookback in memory is 8. deltas
	// will get committed at round 9
	i := 1
	for ; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})
		newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
	}

	stallingTracker.shouldLockPostCommit.Store(true)

	updateAccountsRoutine := func() {
		var updates ledgercore.AccountDeltas
		updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})
		newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
	}

	// This go routine will trigger a commit producer. we added a special blockingTracker that will case our
	// onlineAccoutsTracker to be "stuck" between commit and Post commit .
	// thus, when we call onlineTop - it should wait for the post commit to happen.
	// in a different go routine we will wait 2 sec and release the commit.
	go updateAccountsRoutine()

	select {
	case <-stallingTracker.postCommitEntryLock:
		go func() {
			time.Sleep(2 * time.Second)
			stallingTracker.postCommitReleaseLock <- struct{}{}
		}()

		top, _, err = oa.TopOnlineAccounts(2, 2, 5, &proto, 0)
		a.NoError(err)

		accountToBeUpdated := allAccts[numAccts-1]
		accountToBeUpdated.Status = basics.Offline
		allAccts[numAccts-1] = accountToBeUpdated

		compareTopAccounts(a, top, allAccts)
	case <-time.After(1 * time.Minute):
		a.FailNow("timedout while waiting for post commit")
	}
}

func TestAcctOnlineTopDBBehindMemRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const numAccts = 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)

	for i := 0; i < numAccts; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr: ledgertesting.RandomAddress(),
			AccountData: basics.AccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: uint64(i + 1)},
				Status:         basics.Online,
				VoteLastValid:  1000,
				VoteFirstValid: 0,
				RewardsBase:    0},
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}
	addSinkAndPoolAccounts(genesisAccts)

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, genesisAccts)
	defer ml.Close()

	stallingTracker := &blockingTracker{
		postCommitUnlockedEntryLock:   make(chan struct{}),
		postCommitUnlockedReleaseLock: make(chan struct{}),
		postCommitEntryLock:           make(chan struct{}),
		postCommitReleaseLock:         make(chan struct{}),
	}

	conf := config.GetDefaultLocal()
	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()
	ml.trackers.trackers = append([]ledgerTracker{stallingTracker}, ml.trackers.trackers...)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	top, _, err := oa.TopOnlineAccounts(0, 0, 5, &proto, 0)
	a.NoError(err)
	compareTopAccounts(a, top, allAccts)

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	// apply some rounds so the db round will make progress (not be 0) - i.e since the max lookback in memory is 8. deltas
	// will get committed at round 9
	i := 1
	for ; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})
		newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
	}

	stallingTracker.shouldLockPostCommit.Store(true)

	updateAccountsRoutine := func() {
		var updates ledgercore.AccountDeltas
		updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: basics.VotingData{}})
		newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
	}

	// This go routine will trigger a commit producer. we added a special blockingTracker that will case our
	// onlineAccoutsTracker to be "stuck" between commit and Post commit .
	// thus, when we call onlineTop - it should wait for the post commit to happen.
	// in a different go routine we will wait 2 sec and release the commit.
	go updateAccountsRoutine()

	select {
	case <-stallingTracker.postCommitEntryLock:
		go func() {
			time.Sleep(2 * time.Second)
			// tweak the database to move backwards
			err = oa.dbs.Batch(func(ctx context.Context, tx trackerdb.BatchScope) (err error) {
				return tx.Testing().ModifyAcctBaseTest()
			})
			stallingTracker.postCommitReleaseLock <- struct{}{}
		}()

		_, _, err = oa.TopOnlineAccounts(2, 2, 5, &proto, 0)
		a.Error(err)
		a.Contains(err.Error(), "is behind in-memory round")

	case <-time.After(1 * time.Minute):
		a.FailNow("timeout while waiting for post commit")
	}
}

func TestAcctOnlineTop_ChangeOnlineStake(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	algops := MicroAlgoOperations{a: a}

	const numAccts = 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	for i := 0; i < numAccts-1; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr: ledgertesting.RandomAddress(),
			AccountData: basics.AccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: uint64(i + 1)},
				Status:         basics.Online,
				VoteLastValid:  1000,
				VoteFirstValid: 0,
				RewardsBase:    0},
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}
	// Online but only valid until round 1
	allAccts[numAccts-1] = basics.BalanceRecord{
		Addr: ledgertesting.RandomAddress(),
		AccountData: basics.AccountData{
			MicroAlgos:     basics.MicroAlgos{Raw: uint64(numAccts)},
			Status:         basics.Online,
			VoteLastValid:  1,
			VoteFirstValid: 0,
			RewardsBase:    0},
	}
	genesisAccts[0][allAccts[numAccts-1].Addr] = allAccts[numAccts-1].AccountData
	acctInvalidFromRnd2 := allAccts[numAccts-1]

	addSinkAndPoolAccounts(genesisAccts)

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, genesisAccts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()

	_, totals, err := au.LatestTotals()
	a.NoError(err)

	// Add 20 blocks (> max lookback) to test both the database and deltas
	for i := 1; i <= 20; i++ {
		var updates ledgercore.AccountDeltas
		if i == 15 { // round 15 should be in deltas (memory)
			// turn account `i` offline
			updates.Upsert(allAccts[i].Addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline, MicroAlgos: allAccts[i].MicroAlgos}, VotingData: basics.VotingData{}})
		}
		if i == 18 {
			updates.Upsert(allAccts[i].Addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: allAccts[i].MicroAlgos}, VotingData: basics.VotingData{VoteLastValid: basics.Round(18)}})
		} // else: insert empty block
		totals = newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
	}

	params := config.Consensus[protocol.ConsensusCurrentVersion]
	initialOnlineStake, err := oa.onlineCirculation(0, basics.Round(params.MaxBalLookback))
	a.NoError(err)
	rnd15TotalOnlineStake := algops.Sub(initialOnlineStake, allAccts[15].MicroAlgos) // 15 is offline

	// Case 1: sanity check
	top := compareOnlineTotals(a, oa, 0, 1, 5, initialOnlineStake, initialOnlineStake)
	compareTopAccounts(a, top, allAccts)

	// Case 2: In db
	voteRndExpectedStake := algops.Sub(initialOnlineStake, acctInvalidFromRnd2.MicroAlgos) // Online on rnd but not valid on voteRnd
	top = compareOnlineTotals(a, oa, 0, 2, 5, initialOnlineStake, voteRndExpectedStake)
	updatedAccts := allAccts[:numAccts-1]
	compareTopAccounts(a, top, updatedAccts)

	// Case 3: In memory (deltas)
	voteRndExpectedStake = algops.Sub(rnd15TotalOnlineStake, acctInvalidFromRnd2.MicroAlgos)
	voteRndExpectedStake = algops.Sub(voteRndExpectedStake, allAccts[18].MicroAlgos) // Online on rnd but not valid on voteRnd
	updatedAccts[15].Status = basics.Offline                                         // Mark account 15 offline for comparison
	updatedAccts[18].Status = basics.Offline                                         // Mark account 18 offline for comparison
	top = compareOnlineTotals(a, oa, 18, 19, 5, voteRndExpectedStake, voteRndExpectedStake)
	compareTopAccounts(a, top, updatedAccts)
}

type MicroAlgoOperations struct {
	a  *require.Assertions
	ot basics.OverflowTracker
}

func (m *MicroAlgoOperations) Sub(x, y basics.MicroAlgos) basics.MicroAlgos {
	res := m.ot.SubA(x, y)
	m.a.False(m.ot.Overflowed)
	return res
}

func (m *MicroAlgoOperations) Add(x, y basics.MicroAlgos) basics.MicroAlgos {
	res := m.ot.AddA(x, y)
	m.a.False(m.ot.Overflowed)
	return res
}

func compareOnlineTotals(a *require.Assertions, oa *onlineAccounts, rnd, voteRnd basics.Round, n uint64, expectedForRnd, expectedForVoteRnd basics.MicroAlgos) []*ledgercore.OnlineAccount {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	top, onlineTotalVoteRnd, err := oa.TopOnlineAccounts(rnd, voteRnd, n, &proto, 0)
	a.NoError(err)
	a.Equal(expectedForVoteRnd, onlineTotalVoteRnd)
	onlineTotalsRnd, err := oa.onlineCirculation(rnd, voteRnd)
	a.NoError(err)
	a.Equal(expectedForRnd, onlineTotalsRnd)
	a.LessOrEqual(onlineTotalVoteRnd.Raw, onlineTotalsRnd.Raw)
	return top
}

// TestAcctOnline_ExpiredOnlineCirculation mutates online state in deltas and DB
// to ensure ExpiredOnlineCirculation returns expected online stake value
// The test exercises all possible combinations for offline, online and expired values for two accounts.
func TestAcctOnline_ExpiredOnlineCirculation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	algops := MicroAlgoOperations{a: a}

	// powInt is a helper function to calculate powers of uint64
	powInt := func(x, y uint64) uint64 {
		ret := uint64(1)
		if x == 0 {
			return ret
		}
		for i := uint64(0); i < y; i++ {
			ret *= x
		}
		return ret
	}

	// add some genesis online accounts with stake 1, 10, 20, 30... in order to see which account stake
	// not included into results while debugging
	const numAccts = 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	totalStake := basics.MicroAlgos{Raw: 0}
	for i := 0; i < numAccts-1; i++ {
		stake := i * 10
		if stake == 0 {
			stake = 1
		}
		allAccts[i] = basics.BalanceRecord{
			Addr: ledgertesting.RandomAddress(),
			AccountData: basics.AccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: uint64(stake)},
				Status:         basics.Online,
				VoteLastValid:  10000,
				VoteFirstValid: 0,
				RewardsBase:    0},
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
		totalStake = algops.Add(totalStake, allAccts[i].MicroAlgos)
	}

	addSinkAndPoolAccounts(genesisAccts)

	proto := protocol.ConsensusFuture
	params := config.Consensus[proto]
	ml := makeMockLedgerForTracker(t, true, 1, proto, genesisAccts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.MaxAcctLookback = 4 // technically the test work for any value of MaxAcctLookback but takes too long
	// t.Logf("Running MaxAcctLookback=%d", conf.MaxAcctLookback)
	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()

	// close commitSyncer goroutine to prevent possible race between commitSyncer and commitSync
	ml.trackers.ctxCancel()
	ml.trackers.ctxCancel = nil
	<-ml.trackers.commitSyncerClosed
	ml.trackers.commitSyncerClosed = nil

	// initial precondition checks on online stake
	_, totals, err := au.LatestTotals()
	a.NoError(err)
	a.Equal(totalStake, totals.Online.Money)
	initialOnlineStake, err := oa.onlineCirculation(0, basics.Round(oa.maxBalLookback()))
	a.NoError(err)
	a.Equal(totalStake, initialOnlineStake)
	initialExpired, err := oa.expiredOnlineCirculation(0, 1000)
	a.NoError(err)
	a.Equal(basics.MicroAlgos{Raw: 0}, initialExpired)

	type dbState uint64
	const (
		dbOffline dbState = iota
		dbOnline
		dbOnlineExpired
	)

	type deltaState uint64
	const (
		deltaNoChange deltaState = iota
		deltaOffpired            // offline (addrA) or expired (addrB)
		deltaOnline
	)

	type acctState uint64
	const (
		acctStateUnknown acctState = iota
		acctStateOffline
		acctStateOnline
		acctStateExpired
	)

	// take two first accounts for the test - 0 and 1 - with stake 1 and 10 correspondingly
	addrA := allAccts[0].Addr
	stakeA := allAccts[0].MicroAlgos
	statesA := map[acctState]ledgercore.AccountData{
		acctStateOffline: {AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline, MicroAlgos: stakeA}, VotingData: basics.VotingData{}},
		acctStateOnline:  {AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: stakeA}, VotingData: basics.VotingData(basics_testing.OnlineAccountData(allAccts[0].AccountData).VotingData)},
	}

	addrB := allAccts[1].Addr
	stakeB := allAccts[1].MicroAlgos
	votingDataB := basics_testing.OnlineAccountData(allAccts[1].AccountData).VotingData
	statesB := map[acctState]ledgercore.AccountData{
		acctStateOffline: {AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline, MicroAlgos: stakeB}, VotingData: basics.VotingData{}},
		acctStateOnline:  {AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: stakeB}, VotingData: basics.VotingData(votingDataB)},
	}
	expStatesB := func(state acctState, voteRnd basics.Round) ledgercore.AccountData {
		vd := basics.VotingData(votingDataB)
		switch state {
		case acctStateExpired:
			vd.VoteLastValid = voteRnd - 1
		case acctStateOnline:
			vd.VoteLastValid = voteRnd + 1
		default:
			a.Fail("invalid acct state")
		}
		return ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: stakeB},
			VotingData:      vd,
		}
	}

	// try all possible online/offline delta states for account A
	// try all possible valid/expired VoteLastValid for account B
	// - generate {offline, online, online-expired} db states (two rounds committed) for account A and B
	// - generate all combinations of deltaState {not changed, offline/expired, online} of size conf.MaxAcctLookback arrays
	// - test all combinations in 3^2 * 3^conf.MaxAcctLookback tests
	rnd := basics.Round(1)
	accounts := []map[basics.Address]basics.AccountData{genesisAccts[0]} // base state
	dbStates := []dbState{dbOffline, dbOnline, dbOnlineExpired}
	deltaStates := []deltaState{deltaNoChange, deltaOffpired, deltaOnline}
	const dbRoundsToCommit = 2
	for dbCombo := uint64(0); dbCombo < powInt(uint64(len(dbStates)), dbRoundsToCommit); dbCombo++ {
		for deltaCombo := uint64(0); deltaCombo < powInt(uint64(len(deltaStates)), conf.MaxAcctLookback); deltaCombo++ {
			var stateA acctState
			var stateB acctState

			ternDb := strconv.FormatUint(dbCombo, 3)
			ternDb = fmt.Sprintf("%0*s", dbRoundsToCommit, ternDb)

			ternDelta := strconv.FormatUint(deltaCombo, 3)
			ternDelta = fmt.Sprintf("%0*s", conf.MaxAcctLookback, ternDelta)
			// uncomment for debugging
			// t.Logf("db=%d|delta=%d <==> older->%s<-db top | first->%s<-last", dbCombo, deltaCombo, ternDb, ternDelta)

			targetVoteRnd := rnd +
				basics.Round(conf.MaxAcctLookback) /* all deltas */ +
				2 /* db state committed */ +
				basics.Round(params.MaxBalLookback)

			// mutate the committed state
			// addrA, addrB: offline, online not expired, online expired
			dbSeed := dbState(9999) // not initialized
			for i := uint64(0); i < dbRoundsToCommit; i++ {
				combo := ternDb[i]
				d, err := strconv.Atoi(string(combo))
				a.NoError(err)
				if i == dbRoundsToCommit-1 {
					dbSeed = dbState(d)
				}

				var updates ledgercore.AccountDeltas
				switch dbState(d) {
				case dbOffline:
					updates.Upsert(addrA, statesA[acctStateOffline])
					updates.Upsert(addrB, statesB[acctStateOffline])
				case dbOnline:
					updates.Upsert(addrA, statesA[acctStateOnline])
					updates.Upsert(addrB, statesB[acctStateOnline])
				case dbOnlineExpired:
					state := statesA[acctStateOnline]
					state.VoteLastValid = targetVoteRnd - 1
					updates.Upsert(addrA, state)
					state = statesB[acctStateOnline]
					state.VoteLastValid = targetVoteRnd - 1
					updates.Upsert(addrB, state)
				default:
					a.Fail("unknown db state")
				}
				base := accounts[rnd-1]
				accounts = append(accounts, applyPartialDeltas(base, updates))
				totals = newBlock(t, ml, proto, params, rnd, base, updates, totals)
				rnd++
			}

			// assert on expected online totals
			switch dbSeed {
			case dbOffline:
				// both accounts are offline, decrease the original stake
				a.Equal(initialOnlineStake.Raw-(stakeA.Raw+stakeB.Raw), totals.Online.Money.Raw)
			case dbOnline, dbOnlineExpired: // being expired does not decrease the stake
				a.Equal(initialOnlineStake, totals.Online.Money)
			}

			// mutate in-memory state
			for i := uint64(0); i < conf.MaxAcctLookback; i++ {
				combo := ternDelta[i]
				d, err := strconv.Atoi(string(combo))
				a.NoError(err)

				var updates ledgercore.AccountDeltas
				switch deltaState(d) {
				case deltaNoChange:
				case deltaOffpired:
					updates.Upsert(addrA, statesA[acctStateOffline])
					updates.Upsert(addrB, expStatesB(acctStateExpired, targetVoteRnd))
					stateA = acctStateOffline
					stateB = acctStateExpired
				case deltaOnline:
					updates.Upsert(addrA, statesA[acctStateOnline])
					updates.Upsert(addrB, expStatesB(acctStateOnline, targetVoteRnd))
					stateA = acctStateOnline
					stateB = acctStateOnline

				default:
					a.Fail("unknown delta seed")
				}
				base := accounts[rnd-1]
				accounts = append(accounts, applyPartialDeltas(base, updates))
				totals = newBlock(t, ml, proto, params, rnd, base, updates, totals)
				rnd++
			}

			commitSync(t, oa, ml, basics.Round(rnd-1))
			a.Equal(int(conf.MaxAcctLookback), len(oa.deltas)) // ensure the only expected deltas are not flushed

			var expiredAccts map[basics.Address]*basics.OnlineAccountData
			err = ml.trackers.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) error {
				reader, err := tx.MakeAccountsReader()
				if err != nil {
					return err
				}
				expiredAccts, err = reader.ExpiredOnlineAccountsForRound(rnd-1, targetVoteRnd, params.RewardUnit, 0)
				if err != nil {
					return err
				}
				return nil
			})
			a.NoError(err)

			if dbSeed == dbOffline || dbSeed == dbOnline {
				a.Empty(expiredAccts)
			} else {
				a.Len(expiredAccts, 2)
				for _, acct := range expiredAccts {
					a.NotZero(acct.VoteLastValid)
				}
			}

			expectedExpiredStake := basics.MicroAlgos{}
			// if both A and B were offline or online in DB then the expired stake is changed only if account is expired in deltas
			// => check if B expired
			// if both A and B were expired in DB then the expired stake is changed when any of them goes offline or online
			// => check if A or B are offline or online
			switch dbSeed {
			case dbOffline, dbOnline:
				if stateB == acctStateExpired {
					expectedExpiredStake.Raw += stakeB.Raw
				}
			case dbOnlineExpired:
				expectedExpiredStake.Raw += stakeA.Raw
				expectedExpiredStake.Raw += stakeB.Raw
				if stateA == acctStateOnline || stateA == acctStateOffline {
					expectedExpiredStake.Raw -= stakeA.Raw
				}
				if stateB == acctStateOnline || stateB == acctStateOffline {
					expectedExpiredStake.Raw -= stakeB.Raw
				}
			default:
				a.Fail("unknown db seed")
			}
			a.Equal(targetVoteRnd, rnd+basics.Round(params.MaxBalLookback))
			_, err := oa.expiredOnlineCirculation(rnd, targetVoteRnd)
			a.Error(err)
			a.Contains(err.Error(), fmt.Sprintf("round %d too high", rnd))
			expiredStake, err := oa.expiredOnlineCirculation(rnd-1, targetVoteRnd)
			a.NoError(err)
			a.Equal(expectedExpiredStake, expiredStake)

			// restore the original state of accounts A and B
			updates := ledgercore.AccountDeltas{}
			base := accounts[rnd-1]
			updates.Upsert(addrA, statesA[acctStateOnline])
			updates.Upsert(addrB, ledgercore.AccountData{
				AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: stakeB}, VotingData: basics.VotingData(votingDataB),
			})
			accounts = append(accounts, applyPartialDeltas(base, updates))
			totals = newBlock(t, ml, proto, params, rnd, base, updates, totals)
			rnd++
			// add conf.MaxAcctLookback empty blocks to flush/restore the original state
			for i := uint64(0); i < conf.MaxAcctLookback; i++ {
				var updates ledgercore.AccountDeltas
				base = accounts[rnd-1]
				accounts = append(accounts, base)
				totals = newBlock(t, ml, proto, params, rnd, base, updates, totals)
				rnd++
			}
			commitSync(t, oa, ml, basics.Round(rnd-1))
			a.Equal(int(conf.MaxAcctLookback), len(oa.deltas))
		}
	}
}

// TestAcctOnline_OnlineAcctsExpiredByRound ensures that onlineAcctsExpiredByRound
// can retrieve data from DB even if trackersDB flushed and the requested round is in
// extended history controlled by voters' lowest round.
// The test uses non-empty rewards in order to ensure onlineAcctsExpiredByRound internally fetches
// actual non-empty rewards data from DB.
func TestAcctOnline_OnlineAcctsExpiredByRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	const seedLookback = 2
	const seedInteval = 3
	const maxBalLookback = 2 * seedLookback * seedInteval

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-OnlineAcctsExpiredByRound")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = maxBalLookback
	protoParams.SeedLookback = seedLookback
	protoParams.SeedRefreshInterval = seedInteval
	protoParams.StateProofInterval = 16
	protoParams.RewardsRateRefreshInterval = 10
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	maxRound := 5*basics.Round(protoParams.StateProofInterval) + 1
	targetRound := basics.Round(protoParams.StateProofInterval * 2)

	const numAccts = 20
	allAccts := make([]basics.BalanceRecord, numAccts)
	genesisAccts := []map[basics.Address]basics.AccountData{{}}
	genesisAccts[0] = make(map[basics.Address]basics.AccountData, numAccts)
	numExpiredAccts := 5
	totalExpiredStake := basics.MicroAlgos{Raw: 0}
	for i := 0; i < numAccts; i++ {
		allAccts[i] = basics.BalanceRecord{
			Addr:        ledgertesting.RandomAddress(),
			AccountData: ledgertesting.RandomOnlineAccountData(0),
		}
		// make some accounts to expire before the targetRound
		if i < numExpiredAccts {
			allAccts[i].AccountData.VoteLastValid = targetRound - 1
			totalExpiredStake.Raw += allAccts[i].MicroAlgos.Raw
		}
		genesisAccts[0][allAccts[i].Addr] = allAccts[i].AccountData
	}

	addSinkAndPoolAccounts(genesisAccts)

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
	defer ml.Close()
	conf := config.GetDefaultLocal()
	conf.MaxAcctLookback = maxBalLookback

	au, oa := newAcctUpdates(t, ml, conf)
	defer oa.close()
	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	accounts := genesisAccts
	var updates ledgercore.AccountDeltas
	base := accounts[0]

	// add some blocks to cover few stateproof periods
	for i := basics.Round(1); i <= maxRound; i++ {
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)
		totals = newBlockWithRewards(t, ml, testProtocolVersion, protoParams, i, base, updates, uint64(i), totals)
		base = newAccts
	}

	// ensure voters kicked in
	require.Greater(t, len(oa.voters.votersForRoundCache), 1)
	lowestRound := oa.voters.lowestRound(maxRound)
	require.Equal(t, basics.Round(protoParams.StateProofInterval), lowestRound)

	// commit max possible number of rounds
	commitSync(t, oa, ml, maxRound)
	// check voters did not allow to remove online accounts and params data after commit
	require.Equal(t, lowestRound, oa.voters.lowestRound(maxRound))

	// check the stateproof interval 2 not in deltas
	offset, err := oa.roundOffset(targetRound)
	require.Error(t, err)
	var roundOffsetError *RoundOffsetError
	require.ErrorAs(t, err, &roundOffsetError)
	require.Zero(t, offset)

	offset, err = oa.roundParamsOffset(targetRound)
	require.Error(t, err)
	require.ErrorAs(t, err, &roundOffsetError)
	require.Zero(t, offset)

	// but the DB has data
	roundParamsData, err := oa.accountsq.LookupOnlineRoundParams(targetRound)
	require.NoError(t, err)
	require.NotEmpty(t, roundParamsData)

	// but still available for lookup via onlineAcctsExpiredByRound
	expAccts, err := oa.onlineAcctsExpiredByRound(targetRound, targetRound+10)
	require.NoError(t, err)
	require.Len(t, expAccts, numExpiredAccts)

	var expiredStake basics.MicroAlgos
	for _, expAcct := range expAccts {
		expiredStake.Raw += expAcct.MicroAlgosWithRewards.Raw
	}

	// ensure onlineAcctsExpiredByRound fetched proto and rewards level and it recalculated
	require.Greater(t, expiredStake.Raw, totalExpiredStake.Raw)
}
