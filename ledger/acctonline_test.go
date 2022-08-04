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
	"context"
	"database/sql"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
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
			newBase := basics.Round(dcc.offset) + dcc.oldBase
			dcc.newBase = newBase
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
			newBase := basics.Round(dcc.offset) + dcc.oldBase
			dcc.newBase = newBase
			dcc.flushTime = time.Now()

			for _, lt := range ml.trackers.trackers {
				err := lt.prepareCommit(dcc)
				require.NoError(t, err)
			}
			err := ml.trackers.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
				for _, lt := range ml.trackers.trackers {
					err0 := lt.commitRound(ctx, tx, dcc)
					if err0 != nil {
						return err0
					}
				}

				return updateAccountsRound(tx, newBase)
			})
			require.NoError(t, err)
		}()
	}

	return dcc
}

func commitSyncPartialComplete(t *testing.T, oa *onlineAccounts, ml *mockLedgerForTracker, dcc *deferredCommitContext) {
	defer ml.trackers.accountsWriting.Done()

	ml.trackers.dbRound = dcc.newBase
	for _, lt := range ml.trackers.trackers {
		lt.postCommit(ml.trackers.ctx, dcc)
	}
	ml.trackers.lastFlushTime = dcc.flushTime

	for _, lt := range ml.trackers.trackers {
		lt.postCommitUnlocked(ml.trackers.ctx, dcc)
	}
}

func newBlock(t *testing.T, ml *mockLedgerForTracker, totals ledgercore.AccountTotals, testProtocolVersion protocol.ConsensusVersion, protoParams config.ConsensusParams, rnd basics.Round, base map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, prevTotals ledgercore.AccountTotals) (newTotals ledgercore.AccountTotals) {
	rewardLevel := uint64(0)
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
	delta.Totals = totals

	ml.trackers.newBlock(blk, delta)

	return newTotals
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

	au, oa := newAcctUpdates(t, ml, conf, ".")
	defer oa.close()

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	for _, bal := range allAccts {
		data, err := oa.accountsq.lookupOnline(bal.Addr, 0)
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.addr)
		require.Equal(t, basics.Round(0), data.round)
		require.Equal(t, bal.AccountData.MicroAlgos, data.accountData.MicroAlgos)
		require.Equal(t, bal.AccountData.RewardsBase, data.accountData.RewardsBase)
		require.Equal(t, bal.AccountData.VoteFirstValid, data.accountData.VoteFirstValid)
		require.Equal(t, bal.AccountData.VoteLastValid, data.accountData.VoteLastValid)

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

		updates.Upsert(allAccts[acctIdx].Addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})

		base := genesisAccts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		genesisAccts = append(genesisAccts, newAccts)

		// prepare block
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, i, base, updates, totals)

		// commit changes synchroniously
		commitSync(t, oa, ml, i)

		// check the table data and the cache
		// data gets committed after maxDeltaLookback
		if i > basics.Round(maxDeltaLookback) {
			rnd := i - basics.Round(maxDeltaLookback)
			acctIdx := int(rnd) - 1
			bal := allAccts[acctIdx]
			data, err := oa.accountsq.lookupOnline(bal.Addr, rnd)
			require.NoError(t, err)
			require.Equal(t, bal.Addr, data.addr)
			require.NotEmpty(t, data.rowid)
			require.Equal(t, oa.cachedDBRoundOnline, data.round)
			require.Empty(t, data.accountData)

			data, has := oa.baseOnlineAccounts.read(bal.Addr)
			require.True(t, has)
			require.NotEmpty(t, data.rowid)
			require.Empty(t, data.accountData)

			oad, err := oa.lookupOnlineAccountData(rnd, bal.Addr)
			require.NoError(t, err)
			require.Empty(t, oad)

			// check the prev original row is still there
			data, err = oa.accountsq.lookupOnline(bal.Addr, rnd-1)
			require.NoError(t, err)
			require.Equal(t, bal.Addr, data.addr)
			require.NotEmpty(t, data.rowid)
			require.Equal(t, oa.cachedDBRoundOnline, data.round)
			require.NotEmpty(t, data.accountData)
		}

		// check data gets expired and removed from the DB
		// account 0 is set to Offline at round 1
		// and set expired at X = 1 + MaxBalLookback (= 13)
		// actual removal happens when X is committed i.e. at round X + maxDeltaLookback (= 21)
		if i > basics.Round(maxBalLookback+maxDeltaLookback) {
			rnd := i - basics.Round(maxBalLookback+maxDeltaLookback)
			acctIdx := int(rnd) - 1
			bal := allAccts[acctIdx]
			data, err := oa.accountsq.lookupOnline(bal.Addr, rnd)
			require.NoError(t, err)
			require.Equal(t, bal.Addr, data.addr)
			require.Empty(t, data.rowid)
			require.Equal(t, oa.cachedDBRoundOnline, data.round)
			require.Empty(t, data.accountData)

			data, has := oa.baseOnlineAccounts.read(bal.Addr)
			require.True(t, has)
			require.NotEmpty(t, data.rowid) // TODO: FIXME: set rowid to empty for these items
			require.Empty(t, data.accountData)

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
				data, err := oa.accountsq.lookupOnline(bal.Addr, rnd)
				require.NoError(t, err)
				require.Equal(t, bal.Addr, data.addr)
				require.NotEmpty(t, data.rowid)
				require.Equal(t, oa.cachedDBRoundOnline, data.round)
				require.NotEmpty(t, data.accountData)

				// the most recent value is empty because the account is scheduled for removal
				data, has := oa.baseOnlineAccounts.read(bal.Addr)
				require.True(t, has)
				require.NotEmpty(t, data.rowid) // TODO: FIXME: set rowid to empty for these items
				require.Empty(t, data.accountData)

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
				data, err := oa.accountsq.lookupOnline(bal.Addr, rnd)
				require.NoError(t, err)
				require.Equal(t, bal.Addr, data.addr)
				require.NotEmpty(t, data.rowid)
				require.Equal(t, oa.cachedDBRoundOnline, data.round)
				require.NotEmpty(t, data.accountData)

				// the most recent value is empty because the account is scheduled for removal
				data, has := oa.baseOnlineAccounts.read(bal.Addr)
				require.True(t, has)
				require.NotEmpty(t, data.rowid) // TODO: FIXME: set rowid to empty for these items
				require.Empty(t, data.accountData)

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
		data, err := oa.accountsq.lookupOnline(bal.Addr, basics.Round(i+1))
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.addr)
		require.NotEmpty(t, data.rowid)
		require.Equal(t, oa.cachedDBRoundOnline, data.round)
		require.Empty(t, data.accountData)

		data, has := oa.baseOnlineAccounts.read(bal.Addr)
		require.True(t, has)
		require.NotEmpty(t, data.rowid)
		require.Empty(t, data.accountData)

		oad, err := oa.lookupOnlineAccountData(basics.Round(i+1), bal.Addr)
		require.NoError(t, err)
		require.Empty(t, oad)

		// ensure the online entry is still in the DB for the round i
		data, err = oa.accountsq.lookupOnline(bal.Addr, basics.Round(i))
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.addr)
		require.NotEmpty(t, data.rowid)
		require.Equal(t, oa.cachedDBRoundOnline, data.round)
		require.NotEmpty(t, data.accountData)
	}

	// check maxDeltaLookback accounts in in-memory deltas, check it
	for i := numPersistedAccounts; i < numPersistedAccounts+maxDeltaLookback; i++ {
		bal := allAccts[i]
		oad, err := oa.lookupOnlineAccountData(basics.Round(i+1), bal.Addr)
		require.NoError(t, err)
		require.Empty(t, oad)

		// the table has old values b/c not committed yet
		data, err := oa.accountsq.lookupOnline(bal.Addr, basics.Round(i))
		require.NoError(t, err)
		require.Equal(t, bal.Addr, data.addr)
		require.NotEmpty(t, data.rowid)
		require.Equal(t, oa.cachedDBRoundOnline, data.round)
		require.NotEmpty(t, data.accountData)

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
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, i, base, updates, totals)

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

			au, oa := newAcctUpdates(t, ml, conf, ".")
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
					updates.Upsert(allAccts[acctIdx].Addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})
				} else {
					updates.Upsert(allAccts[acctIdx].Addr, ledgercore.ToAccountData(allAccts[acctIdx].AccountData))
				}

				// set acctA online for each round
				updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: ledgercore.VotingData{VoteLastValid: basics.Round(100 * i)}})

				base := genesisAccts[i-1]
				newAccts := applyPartialDeltas(base, updates)
				genesisAccts = append(genesisAccts, newAccts)

				// prepare block
				totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, i, base, updates, totals)

				// commit changes synchroniously
				commitSync(t, oa, ml, i)

				// check the table data and the cache
				// data gets committed after maxDeltaLookback
				if i > basics.Round(maxDeltaLookback) {
					rnd := i - basics.Round(maxDeltaLookback)
					acctIdx := (int(rnd) - 1) % numAccts
					bal := allAccts[acctIdx]
					data, err := oa.accountsq.lookupOnline(bal.Addr, rnd)
					require.NoError(t, err)
					require.Equal(t, bal.Addr, data.addr)
					require.NotEmpty(t, data.rowid)
					require.Equal(t, oa.cachedDBRoundOnline, data.round)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, data.accountData)
					} else {
						require.NotEmpty(t, data.accountData)
					}

					cachedData, has := oa.onlineAccountsCache.read(bal.Addr, rnd)
					require.True(t, has)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, cachedData.baseOnlineAccountData)
					} else {
						require.NotEmpty(t, cachedData.baseOnlineAccountData)
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
					data, err := oa.accountsq.lookupOnline(bal.Addr, rnd)
					require.NoError(t, err)
					require.Equal(t, bal.Addr, data.addr)
					require.Equal(t, oa.cachedDBRoundOnline, data.round)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, data.accountData)
						require.Empty(t, data.rowid)
					} else {
						require.NotEmpty(t, data.rowid)
						require.NotEmpty(t, data.accountData)
					}

					cachedData, has := oa.onlineAccountsCache.read(bal.Addr, rnd)
					require.True(t, has)
					if (rnd-1)%(numAccts*2) >= numAccts {
						require.Empty(t, cachedData.baseOnlineAccountData)
					} else {
						require.NotEmpty(t, cachedData.baseOnlineAccountData)
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
			res, validThrough, err := oa.accountsq.lookupOnlineHistory(addrA)
			require.NoError(t, err)
			require.Equal(t, oa.cachedDBRoundOnline, validThrough)
			// +1 because of deletion before X, and not checking acct state at X
			require.Equal(t, int(maxBalLookback)+1, len(res))
			// ensure the cache length corresponds to DB
			require.Equal(t, len(res), oa.onlineAccountsCache.accounts[addrA].Len())
			for _, entry := range res {
				cached, has := oa.onlineAccountsCache.read(addrA, entry.updRound)
				require.True(t, has)
				require.Equal(t, entry.updRound, cached.updRound)
				require.Equal(t, entry.accountData.VoteLastValid, cached.VoteLastValid)
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
			require.NotEmpty(t, cachedData.baseOnlineAccountData)

			// cache should contain data for new rounds
			// (the last entry should be offline)
			// check at targetRound - 10 because that is the latest round written to db
			newRound := targetRound - basics.Round(10)
			cachedData, has = oa.onlineAccountsCache.read(bal.Addr, newRound)
			require.True(t, has)
			require.Equal(t, newRound, cachedData.updRound)
			require.Empty(t, cachedData.baseOnlineAccountData)

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
	au, ao := newAcctUpdates(t, ml, conf, ".")
	defer au.close()
	defer ao.close()

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
		ml.trackers.newBlock(blk, delta)
		accts = append(accts, newAccts)

		if i > basics.Round(maxBalLookback) && i%10 == 0 {
			onlineTotal, err := ao.OnlineTotals(i - basics.Round(maxBalLookback))
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
	err := ao.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		dbOnlineRoundParams, endRound, err = accountsOnlineRoundParams(tx)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, ao.cachedDBRoundOnline, endRound)
	require.Equal(t, ao.onlineRoundParamsData[:basics.Round(maxBalLookback)], dbOnlineRoundParams)

	for i := ml.Latest() - basics.Round(maxBalLookback); i < ml.Latest(); i++ {
		onlineTotal, err := ao.OnlineTotals(i)
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
		for addr, ad := range genesisAccts[0] {
			accounts[0][addr] = ad
		}
		return accounts
	}

	// test 1: large deltas, have addrA offline in deltas, ensure it works
	t.Run("large-delta-go-offline", func(t *testing.T) {
		ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
		defer ml.Close()
		conf := config.GetDefaultLocal()
		conf.MaxAcctLookback = maxBalLookback

		au, oa := newAcctUpdates(t, ml, conf, ".")
		defer oa.close()
		_, totals, err := au.LatestTotals()
		require.NoError(t, err)

		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})

		// copy genesisAccts for the test
		accounts := copyGenesisAccts()
		base := accounts[0]
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)

		// prepare block
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, 1, base, updates, totals)
		// commit changes synchroniously
		commitSync(t, oa, ml, 1)

		// add maxBalLookback empty blocks
		for i := 2; i <= maxBalLookback; i++ {
			var updates ledgercore.AccountDeltas
			base := accounts[i-1]
			totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
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
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, basics.Round(rnd), base, updates, totals)
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

		au, oa := newAcctUpdates(t, ml, conf, ".")
		defer oa.close()
		_, totals, err := au.LatestTotals()
		require.NoError(t, err)

		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})

		// copy genesisAccts for the test
		accounts := copyGenesisAccts()
		base := accounts[0]
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)

		// prepare block
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, 1, base, updates, totals)
		// commit changes synchroniously
		commitSync(t, oa, ml, 1)

		// add maxBalLookback empty blocks
		for i := 2; i <= maxBalLookback; i++ {
			var updates ledgercore.AccountDeltas
			base := accounts[i-1]
			totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
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

		au, oa := newAcctUpdates(t, ml, conf, ".")
		defer oa.close()
		_, totals, err := au.LatestTotals()
		require.NoError(t, err)

		addrB := ledgertesting.RandomAddress()
		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})
		updates.Upsert(addrB, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: ledgercore.VotingData{VoteLastValid: 10000}})

		// copy genesisAccts for the test
		accounts := copyGenesisAccts()
		base := accounts[0]
		newAccts := applyPartialDeltas(base, updates)
		accounts = append(accounts, newAccts)

		// prepare block
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, 1, base, updates, totals)
		// commit changes synchroniously
		commitSync(t, oa, ml, 1)

		// add maxDeltaLookback empty blocks
		for i := 2; i <= maxBalLookback; i++ {
			var updates ledgercore.AccountDeltas
			base := accounts[i-1]
			totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
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
		pad, err := oa.accountsq.lookupOnline(addrA, 1)
		require.NoError(t, err)
		require.Equal(t, addrA, pad.addr)
		require.NotEmpty(t, pad.rowid)
		require.Empty(t, pad.accountData.VoteLastValid)

		// commit a block to get these entries removed
		// ensure the DB entry gone, the cache has it and lookupOnlineAccountData works as expected
		updates = ledgercore.AccountDeltas{}
		rnd := maxBalLookback + 1
		base = accounts[rnd-1]
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, basics.Round(rnd), base, updates, totals)
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
			pad, err = oa.accountsq.lookupOnline(addrB, 1)
			require.NoError(t, err)
			require.Equal(t, addrB, pad.addr)
			require.NotEmpty(t, pad.rowid)
			require.NotEmpty(t, pad.accountData.VoteLastValid)
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
		pad, err = oa.accountsq.lookupOnline(addrA, 1)
		require.NoError(t, err)
		require.Equal(t, addrA, pad.addr)
		require.Empty(t, pad.rowid)
		require.Empty(t, pad.accountData.VoteLastValid)

		_, has = oa.accounts[addrB]
		require.False(t, has)
		cachedData, has = oa.onlineAccountsCache.read(addrB, 1)
		require.False(t, has) // cache miss, we do not write into the cache non-complete history after updates
		require.Empty(t, cachedData.VoteLastValid)

		data, err = oa.lookupOnlineAccountData(1, addrB)
		require.NoError(t, err)
		require.NotEmpty(t, data.VotingData.VoteLastValid)

		pad, err = oa.accountsq.lookupOnline(addrB, 1)
		require.NoError(t, err)
		require.Equal(t, addrB, pad.addr)
		require.NotEmpty(t, pad.rowid)
		require.NotEmpty(t, pad.accountData.VoteLastValid)
	})
}

func TestAcctOnlineVotersLongerHistory(t *testing.T) {
	partitiontest.PartitionTest(t)

	const seedLookback = 3
	const seedInteval = 4
	const maxBalLookback = 2 * seedLookback * seedInteval
	const compactCertRounds = maxBalLookback / 2 // have it less than maxBalLookback but greater than default deltas size (8)
	const compactCertVotersLookback = 2
	const compactCertSecKQ = compactCertRounds / 2

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
	protoParams := config.Consensus[protocol.ConsensusFuture]
	protoParams.MaxBalLookback = maxBalLookback
	protoParams.SeedLookback = seedLookback
	protoParams.SeedRefreshInterval = seedInteval
	protoParams.CompactCertRounds = compactCertRounds
	protoParams.CompactCertVotersLookback = compactCertVotersLookback
	protoParams.CompactCertSecKQ = compactCertSecKQ
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	ml := makeMockLedgerForTracker(t, true, 1, testProtocolVersion, genesisAccts)
	defer ml.Close()
	conf := config.GetDefaultLocal()

	au, oa := newAcctUpdates(t, ml, conf, ".")
	defer oa.close()
	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	// add maxBalLookback empty blocks
	maxBlocks := maxBalLookback * 5
	for i := 1; i <= maxBlocks; i++ {
		var updates ledgercore.AccountDeltas
		updates.Upsert(addrA, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online}, VotingData: ledgercore.VotingData{VoteLastValid: basics.Round(100 * i)}})
		base := genesisAccts[i-1]
		newAccts := applyPartialDeltas(base, updates)
		totals = newBlock(t, ml, totals, testProtocolVersion, protoParams, basics.Round(i), base, updates, totals)
		genesisAccts = append(genesisAccts, newAccts)
		commitSync(t, oa, ml, basics.Round(i))
	}
	require.Len(t, oa.deltas, int(conf.MaxAcctLookback))
	require.Equal(t, basics.Round(maxBlocks-int(conf.MaxAcctLookback)), oa.cachedDBRoundOnline)
	// voters stalls after the first interval
	lowest := oa.voters.lowestRound(oa.cachedDBRoundOnline)
	require.Equal(t, basics.Round(compactCertRounds-compactCertVotersLookback), lowest)
	require.Equal(t, maxBlocks/compactCertRounds, len(oa.voters.round))
	retain, lookback := oa.committedUpTo(oa.latest())
	require.Equal(t, lowest, retain)
	require.Equal(t, conf.MaxAcctLookback, uint64(lookback))

	// onlineRoundParamsData does not store more than maxBalLookback + deltas even if voters stall
	require.Equal(t, uint64(len(oa.onlineRoundParamsData)), maxBalLookback+conf.MaxAcctLookback)

	// DB has all the required history tho
	var dbOnlineRoundParams []ledgercore.OnlineRoundParamsData
	var endRound basics.Round
	err = oa.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		dbOnlineRoundParams, endRound, err = accountsOnlineRoundParams(tx)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, oa.latest()-basics.Round(conf.MaxAcctLookback), endRound)
	require.Equal(t, maxBlocks-int(lowest)-int(conf.MaxAcctLookback)+1, len(dbOnlineRoundParams))

	// ensure the cache size for addrA does not have more entries than maxBalLookback + 1
	// +1 comes from the deletion before X without checking account state at X
	require.Equal(t, maxBalLookback+1, oa.onlineAccountsCache.accounts[addrA].Len())
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
			NormalizedOnlineBalance: expectedAccountsBalances[i].NormalizedOnlineBalance(config.Consensus[protocol.ConsensusCurrentVersion]),
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

func newBlockWithUpdates(genesisAccts []map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, totals ledgercore.AccountTotals, t *testing.T, ml *mockLedgerForTracker, round int, oa *onlineAccounts) {
	base := genesisAccts[0]
	totals = newBlock(t, ml, totals, protocol.ConsensusCurrentVersion, config.Consensus[protocol.ConsensusCurrentVersion], basics.Round(round), base, updates, totals)
	commitSync(t, oa, ml, basics.Round(round))
}

func TestAcctOnlineTop(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

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

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, genesisAccts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au, oa := newAcctUpdates(t, ml, conf, ".")
	defer oa.close()

	top, err := oa.onlineTop(0, 0, 5)
	a.NoError(err)
	compareTopAccounts(a, top, allAccts)

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	// mark one of the top N accounts as offline - we expect that it will be removed form the top N
	var updates ledgercore.AccountDeltas
	updates.Upsert(allAccts[numAccts-3].Addr, ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})
	newBlockWithUpdates(genesisAccts, updates, totals, t, ml, 1, oa)

	accountToBeUpdated := allAccts[numAccts-3]
	accountToBeUpdated.Status = basics.Offline
	allAccts[numAccts-3] = accountToBeUpdated

	top, err = oa.onlineTop(1, 1, 5)
	a.NoError(err)
	compareTopAccounts(a, top, allAccts)

	// update an account to have expired keys
	updates = ledgercore.AccountDeltas{}
	updates.Upsert(allAccts[numAccts-2].Addr, ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online},
		VotingData: ledgercore.VotingData{
			VoteFirstValid: 0,
			VoteLastValid:  1,
		}})
	newBlockWithUpdates(genesisAccts, updates, totals, t, ml, 2, oa)

	// we expect the previous account to be removed from the top N accounts since its keys are expired.
	// remove it from the expected allAccts slice by marking it as offline
	accountToBeUpdated = allAccts[numAccts-2]
	accountToBeUpdated.Status = basics.Offline
	allAccts[numAccts-2] = accountToBeUpdated

	top, err = oa.onlineTop(2, 2, 5)
	a.NoError(err)
	compareTopAccounts(a, top, allAccts)

	// mark an account with high stake as online - it should be pushed to the top of the list
	updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{Status: basics.Online, MicroAlgos: allAccts[numAccts-1].MicroAlgos},
		VotingData:      ledgercore.VotingData{VoteLastValid: basics.Round(1000)}})
	newBlockWithUpdates(genesisAccts, updates, totals, t, ml, 3, oa)

	accountToBeUpdated = allAccts[numAccts-1]
	accountToBeUpdated.Status = basics.Online
	accountToBeUpdated.MicroAlgos = allAccts[numAccts-1].MicroAlgos
	accountToBeUpdated.VoteLastValid = basics.Round(1000)
	allAccts[numAccts-1] = accountToBeUpdated

	top, err = oa.onlineTop(3, 3, 5)
	a.NoError(err)
	compareTopAccounts(a, top, allAccts)

	a.Equal(top[0].Address, allAccts[numAccts-1].Addr)

}

func TestAcctOnlineTopInBatches(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const numAccts = 2048
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

	conf := config.GetDefaultLocal()
	_, oa := newAcctUpdates(t, ml, conf, ".")
	defer oa.close()

	top, err := oa.onlineTop(0, 0, 2048)
	a.NoError(err)
	compareTopAccounts(a, top, allAccts)
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
		alwaysLock:                    false,
		shouldLockPostCommit:          false,
	}

	conf := config.GetDefaultLocal()
	au, oa := newAcctUpdates(t, ml, conf, ".")
	defer oa.close()
	ml.trackers.trackers = append([]ledgerTracker{stallingTracker}, ml.trackers.trackers...)

	top, err := oa.onlineTop(0, 0, 5)
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
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})
		newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
	}

	stallingTracker.shouldLockPostCommit = true

	updateAccountsRoutine := func() {
		var updates ledgercore.AccountDeltas
		updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})
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
		top, err = oa.onlineTop(2, 2, 5)
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
		alwaysLock:                    false,
		shouldLockPostCommit:          false,
	}

	conf := config.GetDefaultLocal()
	au, oa := newAcctUpdates(t, ml, conf, ".")
	defer oa.close()
	ml.trackers.trackers = append([]ledgerTracker{stallingTracker}, ml.trackers.trackers...)

	top, err := oa.onlineTop(0, 0, 5)
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
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})
		newBlockWithUpdates(genesisAccts, updates, totals, t, ml, i, oa)
	}

	stallingTracker.shouldLockPostCommit = true

	updateAccountsRoutine := func() {
		var updates ledgercore.AccountDeltas
		updates.Upsert(allAccts[numAccts-1].Addr, ledgercore.AccountData{
			AccountBaseData: ledgercore.AccountBaseData{Status: basics.Offline}, VotingData: ledgercore.VotingData{}})
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
			err = oa.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
				_, err = tx.Exec("update acctrounds set rnd = 1 WHERE id='acctbase' ")
				return
			})
			stallingTracker.postCommitReleaseLock <- struct{}{}
		}()
		_, err = oa.onlineTop(2, 2, 5)
		a.Error(err)
		a.Contains(err.Error(), "is behind in-memory round")

	case <-time.After(1 * time.Minute):
		a.FailNow("timedout while waiting for post commit")
	}
}
