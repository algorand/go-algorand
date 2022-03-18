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
	"container/heap"
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/metrics"
)

// onlineAccounts tracks history of online accounts
type onlineAccounts struct {
	// Connection to the database.
	dbs db.Pair

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq *accountsDbQueries

	// cachedDBRoundOnline is always exactly tracker DB round (and therefore, onlineAccountsRound()),
	// cached to use in lookup functions
	cachedDBRoundOnline basics.Round

	// deltas stores updates for every round after dbRound.
	deltas []ledgercore.AccountDeltas

	// accounts stores the most recent account state for every
	// address that appears in deltas.
	accounts map[basics.Address]modifiedAccount

	// versions stores consensus version dbRound and every
	// round after it; i.e., versions is one longer than deltas.
	versions []protocol.ConsensusVersion

	// totals stores the totals for dbRound and every round after it;
	// i.e., totals is one longer than deltas.
	roundTotals []ledgercore.AccountTotals

	// log copied from ledger
	log logging.Logger

	// ledger is the source ledger, which is used to synchronize
	// the rounds at which we need to flush the balances to disk
	// in favor of the catchpoint to be generated.
	ledger ledgerForTracker

	// deltasAccum stores the accumulated deltas for every round starting dbRound-1.
	deltasAccum []int

	// accountsMu is the synchronization mutex for accessing the various non-static variables.
	accountsMu deadlock.RWMutex

	// accountsReadCond used to synchronize read access to the internal data structures.
	accountsReadCond *sync.Cond

	// voters keeps track of Merkle trees of online accounts, used for compact certificates.
	voters *votersTracker

	// baseAccounts stores the most recently used accounts, at exactly dbRound
	baseAccounts lruAccounts
}

// initialize initializes the accountUpdates structure
func (ao *onlineAccounts) initialize() {
	ao.accountsReadCond = sync.NewCond(ao.accountsMu.RLocker())
}

// loadFromDisk is the 2nd level initialization, and is required before the accountUpdates becomes functional
// The close function is expected to be call in pair with loadFromDisk
func (ao *onlineAccounts) loadFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) error {
	ao.accountsMu.Lock()
	defer ao.accountsMu.Unlock()

	ao.cachedDBRoundOnline = lastBalancesRound
	ao.ledger = l
	err := ao.initializeFromDisk(l, lastBalancesRound)
	if err != nil {
		return err
	}
	return nil
}

// initializeFromDisk performs the atomic operation of loading the accounts data information from disk
// and preparing the accountUpdates for operation.
func (ao *onlineAccounts) initializeFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) (err error) {
	ao.dbs = l.trackerDB()
	ao.log = l.trackerLog()

	err = ao.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		totals, err0 := accountsTotals(tx, false)
		if err0 != nil {
			return err0
		}

		ao.roundTotals = []ledgercore.AccountTotals{totals}
		return nil
	})
	if err != nil {
		return
	}

	ao.accountsq, err = accountsInitDbQueries(ao.dbs.Rdb.Handle, ao.dbs.Wdb.Handle)
	if err != nil {
		return
	}

	hdr, err := l.BlockHdr(lastBalancesRound)
	if err != nil {
		return
	}

	ao.versions = []protocol.ConsensusVersion{hdr.CurrentProtocol}
	ao.deltas = nil
	ao.accounts = make(map[basics.Address]modifiedAccount)
	ao.deltasAccum = []int{0}

	ao.baseAccounts.init(ao.log, baseAccountsPendingAccountsBufferSize, baseAccountsPendingAccountsWarnThreshold)
	return
}

// latest returns the latest round
func (ao *onlineAccounts) latest() basics.Round {
	return ao.cachedDBRoundOnline + basics.Round(len(ao.deltas))
}

// close closes the accountUpdates, waiting for all the child go-routine to complete
func (ao *onlineAccounts) close() {
	if ao.accountsq != nil {
		ao.accountsq.close()
		ao.accountsq = nil
	}
	if ao.voters != nil {
		ao.voters.close()
		ao.voters = nil
	}

	ao.baseAccounts.prune(0)
}

// newBlock is the accountUpdates implementation of the ledgerTracker interface. This is the "external" facing function
// which invokes the internal implementation after taking the lock.
func (ao *onlineAccounts) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	ao.accountsMu.Lock()
	ao.newBlockImpl(blk, delta)
	ao.accountsMu.Unlock()
	ao.accountsReadCond.Broadcast()
}

// newBlockImpl is the accountUpdates implementation of the ledgerTracker interface. This is the "internal" facing function
// which assumes that no lock need to be taken.
func (ao *onlineAccounts) newBlockImpl(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	rnd := blk.Round()

	if rnd <= ao.latest() {
		// Duplicate, ignore.
		return
	}

	if rnd != ao.latest()+1 {
		ao.log.Panicf("onlineAccounts: newBlockImpl %d too far in the future, dbRound %d, deltas %d", rnd, ao.cachedDBRoundOnline, len(ao.deltas))
	}
	ao.deltas = append(ao.deltas, delta.Accts)
	ao.versions = append(ao.versions, blk.CurrentProtocol)
	ao.deltasAccum = append(ao.deltasAccum, delta.Accts.Len()+ao.deltasAccum[len(ao.deltasAccum)-1])

	ao.baseAccounts.flushPendingWrites()

	for i := 0; i < delta.Accts.Len(); i++ {
		addr, data := delta.Accts.GetByIdx(i)
		macct := ao.accounts[addr]
		macct.ndeltas++
		macct.data = data
		ao.accounts[addr] = macct
	}

	ao.roundTotals = append(ao.roundTotals, delta.Totals)

	// calling prune would drop old entries from the base accounts.
	newBaseAccountSize := (len(ao.accounts) + 1) + baseAccountsPendingAccountsBufferSize
	ao.baseAccounts.prune(newBaseAccountSize)

	if ao.voters != nil {
		ao.voters.newBlock(blk.BlockHeader)
	}
}

// committedUpTo implements the ledgerTracker interface for accountUpdates.
// The method informs the tracker that committedRound and all it's previous rounds have
// been committed to the block database. The method returns what is the oldest round
// number that can be removed from the blocks database as well as the lookback that this
// tracker maintains.
func (ao *onlineAccounts) committedUpTo(committedRound basics.Round) (retRound, lookback basics.Round) {
	ao.accountsMu.RLock()
	defer ao.accountsMu.RUnlock()

	retRound = basics.Round(0)
	lookback = basics.Round(config.Consensus[ao.versions[len(ao.versions)-1]].MaxBalLookback)
	if committedRound < lookback {
		return
	}

	retRound = ao.cachedDBRoundOnline
	return
}

// produceCommittingTask enqueues committing the balances for round committedRound-lookback.
// The deferred committing is done so that we could calculate the historical balances lookback rounds back.
// Since we don't want to hold off the tracker's mutex for too long, we'll defer the database persistence of this
// operation to a syncer goroutine. The one caveat is that when storing a catchpoint round, we would want to
// wait until the catchpoint creation is done, so that the persistence of the catchpoint file would have an
// uninterrupted view of the balances at a given point of time.
func (ao *onlineAccounts) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	var offset uint64
	ao.accountsMu.RLock()
	defer ao.accountsMu.RUnlock()

	// repeat logic from account updates
	// TODO: after clean up removing 320 rounds lookback
	if committedRound < dcr.lookback {
		return nil
	}

	newBase := committedRound - dcr.lookback
	if newBase <= dbRound {
		// Already forgotten
		return nil
	}

	if newBase > dbRound+basics.Round(len(ao.deltas)) {
		ao.log.Panicf("produceCommittingTask: block %d too far in the future, lookback %d, dbRound %d (cached %d), deltas %d", committedRound, dcr.lookback, dbRound, ao.cachedDBRoundOnline, len(ao.deltas))
	}

	if ao.voters != nil {
		newBase = ao.voters.lowestRound(newBase)
	}

	offset = uint64(newBase - dbRound)

	offset = ao.consecutiveVersion(offset)

	// submit committing task only if offset is non-zero in addition to
	// 1) no pending catchpoint writes
	// 2) batching requirements meet or catchpoint round
	dcr.oldBaseOnline = dbRound
	dcr.offsetOnline = offset

	// TODO: remove
	// synchronize base and offset with account updates
	if dcr.offset < dcr.offsetOnline {
		dcr.offsetOnline = dcr.offset
	}
	if dcr.offsetOnline < dcr.offset {
		dcr.offset = dcr.offsetOnline
	}
	return dcr
}

func (ao *onlineAccounts) consecutiveVersion(offset uint64) uint64 {
	// check if this update chunk spans across multiple consensus versions. If so, break it so that each update would tackle only a single
	// consensus version.
	if ao.versions[1] != ao.versions[offset] {
		// find the tip point.
		tipPoint := sort.Search(int(offset), func(i int) bool {
			// we're going to search here for version inequality, with the assumption that consensus versions won't repeat.
			// that allow us to support [ver1, ver1, ..., ver2, ver2, ..., ver3, ver3] but not [ver1, ver1, ..., ver2, ver2, ..., ver1, ver3].
			return ao.versions[1] != ao.versions[1+i]
		})
		// no need to handle the case of "no found", or tipPoint==int(offset), since we already know that it's there.
		offset = uint64(tipPoint)
	}
	return offset
}

func (ao *onlineAccounts) handleUnorderedCommit(dcc *deferredCommitContext) {
}

// prepareCommit prepares data to write to the database a "chunk" of rounds, and update the cached dbRound accordingly.
func (ao *onlineAccounts) prepareCommit(dcc *deferredCommitContext) error {
	offset := dcc.offsetOnline

	ao.accountsMu.RLock()

	// create a copy of the deltas, round totals and protos for the range we're going to flush.
	deltas := make([]ledgercore.AccountDeltas, offset)
	copy(deltas, ao.deltas[:offset])

	// verify version correctness : all the entries in the au.versions[1:offset+1] should have the *same* version, and the committedUpTo should be enforcing that.
	if ao.versions[1] != ao.versions[offset] {
		ao.accountsMu.RUnlock()

		// in scheduleCommit, we expect that this function to update the catchpointWriting when
		// it's on a catchpoint round and the node is configured to generate catchpoints. Doing this in a deferred function
		// here would prevent us from "forgetting" to update this variable later on.
		// The same is repeated in commitRound on errors.
		if dcc.isCatchpointRound && dcc.enableGeneratingCatchpointFiles {
			atomic.StoreInt32(dcc.catchpointWriting, 0)
		}
		return fmt.Errorf("attempted to commit series of rounds with non-uniform consensus versions")
	}

	// once the consensus upgrade to resource separation is complete, all resources/accounts are also tagged with
	// their corresponding update round.
	setUpdateRound := config.Consensus[ao.versions[1]].EnableAccountDataResourceSeparation

	// compact all the deltas - when we're trying to persist multiple rounds, we might have the same account
	// being updated multiple times. When that happen, we can safely omit the intermediate updates.
	dcc.compactAccountDeltasOnline = makeCompactAccountDeltas(deltas, dcc.oldBaseOnline, setUpdateRound, ao.baseAccounts)

	ao.accountsMu.RUnlock()

	dcc.genesisProto = ao.ledger.GenesisProto()

	return nil
}

// commitRound closure is called within the same transaction for all trackers
// it receives current offset and dbRound
func (ao *onlineAccounts) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	offset := dcc.offsetOnline
	dbRound := dcc.oldBaseOnline

	_, err = db.ResetTransactionWarnDeadline(ctx, tx, time.Now().Add(accountsUpdatePerRoundHighWatermark*time.Duration(offset)))
	if err != nil {
		return err
	}

	err = dcc.compactAccountDeltasOnline.accountsLoadOld(tx, "onlineaccounts")
	if err != nil {
		return err
	}

	// the updates of the actual account data is done last since the accountsNewRound would modify the compactDeltas old values
	// so that we can update the base account back.
	dcc.updatedPersistedAccountsOnline, err = onlineAccountsNewRound(tx, dcc.compactAccountDeltasOnline, dcc.genesisProto, dbRound+basics.Round(offset))
	if err != nil {
		return err
	}

	return
}

func (ao *onlineAccounts) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	offset := dcc.offsetOnline
	newBase := dcc.newBaseOnline

	ao.accountsMu.Lock()
	// Drop reference counts to modified accounts, and evict them
	// from in-memory cache when no references remain.
	for i := 0; i < dcc.compactAccountDeltasOnline.len(); i++ {
		acctUpdate := dcc.compactAccountDeltasOnline.getByIdx(i)
		cnt := acctUpdate.nAcctDeltas
		macct, ok := ao.accounts[acctUpdate.address]
		if !ok {
			ao.log.Panicf("inconsistency: flushed %d changes to %s, but not in au.accounts", cnt, acctUpdate.address)
		}

		if cnt > macct.ndeltas {
			ao.log.Panicf("inconsistency: flushed %d changes to %s, but au.accounts had %d", cnt, acctUpdate.address, macct.ndeltas)
		} else if cnt == macct.ndeltas {
			delete(ao.accounts, acctUpdate.address)
		} else {
			macct.ndeltas -= cnt
			ao.accounts[acctUpdate.address] = macct
		}
	}

	for _, persistedAcct := range dcc.updatedPersistedAccountsOnline {
		ao.baseAccounts.write(persistedAcct)
	}

	ao.deltas = ao.deltas[offset:]
	ao.deltasAccum = ao.deltasAccum[offset:]
	ao.versions = ao.versions[offset:]
	ao.roundTotals = ao.roundTotals[offset:]
	ao.cachedDBRoundOnline = newBase

	ao.accountsMu.Unlock()

	ao.accountsReadCond.Broadcast()
}

func (ao *onlineAccounts) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
}

// LookupOnlineAccountData returns the online account data for a given address at a given round.
func (ao *onlineAccounts) LookupOnlineAccountData(rnd basics.Round, addr basics.Address) (data basics.OnlineAccountData, err error) {
	return ao.lookupOnlineAccountData(rnd, addr)
}

// roundOffset calculates the offset of the given round compared to the current dbRound. Requires that the lock would be taken.
func (ao *onlineAccounts) roundOffset(rnd basics.Round) (offset uint64, err error) {
	if rnd < ao.cachedDBRoundOnline {
		err = &RoundOffsetError{
			round:   rnd,
			dbRound: ao.cachedDBRoundOnline,
		}
		return
	}

	off := uint64(rnd - ao.cachedDBRoundOnline)
	if off > uint64(len(ao.deltas)) {
		err = fmt.Errorf("round %d too high: dbRound %d, deltas %d", rnd, ao.cachedDBRoundOnline, len(ao.deltas))
		return
	}

	return off, nil
}

// lookupOnlineAccountData returns the online account data for a given address at a given round.
func (ao *onlineAccounts) lookupOnlineAccountData(rnd basics.Round, addr basics.Address) (data basics.OnlineAccountData, err error) {
	ao.accountsMu.RLock()
	needUnlock := true
	defer func() {
		if needUnlock {
			ao.accountsMu.RUnlock()
		}
	}()
	var offset uint64
	var rewardsProto config.ConsensusParams
	var rewardsLevel uint64
	var persistedData persistedAccountData
	for {
		currentDbRound := ao.cachedDBRoundOnline
		currentDeltaLen := len(ao.deltas)
		offset, err = ao.roundOffset(rnd)
		if err != nil {
			return
		}

		rewardsProto = config.Consensus[ao.versions[offset]]
		rewardsLevel = ao.roundTotals[offset].RewardsLevel

		// check if we've had this address modified in the past rounds. ( i.e. if it's in the deltas )
		macct, indeltas := ao.accounts[addr]
		if indeltas {
			// Check if this is the most recent round, in which case, we can
			// use a cache of the most recent account state.
			if offset == uint64(len(ao.deltas)) {
				return macct.data.OnlineAccountData(rewardsProto, rewardsLevel), nil
			}
			// the account appears in the deltas, but we don't know if it appears in the
			// delta range of [0..offset], so we'll need to check :
			// Traverse the deltas backwards to ensure that later updates take
			// priority if present.
			for offset > 0 {
				offset--
				d, ok := ao.deltas[offset].GetData(addr)
				if ok {
					return d.OnlineAccountData(rewardsProto, rewardsLevel), nil
				}
			}
		}

		// check the baseAccounts -
		if macct, has := ao.baseAccounts.read(addr); has && macct.round == currentDbRound {
			// we don't technically need this, since it's already in the baseAccounts, however, writing this over
			// would ensure that we promote this field.
			ao.baseAccounts.writePending(macct)
			u := macct.accountData.GetLedgerCoreAccountData()
			return u.OnlineAccountData(rewardsProto, rewardsLevel), nil
		}

		ao.accountsMu.RUnlock()
		needUnlock = false

		// No updates of this account in the in-memory deltas; use on-disk DB.
		// The check in roundOffset() made sure the round is exactly the one
		// present in the on-disk DB.  As an optimization, we avoid creating
		// a separate transaction here, and directly use a prepared SQL query
		// against the database.
		persistedData, err = ao.accountsq.lookupOnline(addr)
		if persistedData.round == currentDbRound {
			var u ledgercore.AccountData
			if persistedData.rowid != 0 {
				// if we read actual data return it
				ao.baseAccounts.writePending(persistedData)
				u = persistedData.accountData.GetLedgerCoreAccountData()
			}
			// otherwise return empty
			return u.OnlineAccountData(rewardsProto, rewardsLevel), err
		}

		if persistedData.round < currentDbRound {
			ao.log.Errorf("accountUpdates.lookupOnlineAccountData: database round %d is behind in-memory round %d", persistedData.round, currentDbRound)
			return basics.OnlineAccountData{}, &StaleDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
		}
		ao.accountsMu.RLock()
		needUnlock = true
		for currentDbRound >= ao.cachedDBRoundOnline && currentDeltaLen == len(ao.deltas) {
			ao.accountsReadCond.Wait()
		}
	}
}

// onlineTop returns the top n online accounts, sorted by their normalized
// balance and address, whose voting keys are valid in voteRnd.  See the
// normalization description in AccountData.NormalizedOnlineBalance().
func (ao *onlineAccounts) onlineTop(rnd basics.Round, voteRnd basics.Round, n uint64) ([]*ledgercore.OnlineAccount, error) {
	genesisProto := ao.ledger.GenesisProto()
	ao.accountsMu.RLock()
	for {
		currentDbRound := ao.cachedDBRoundOnline
		currentDeltaLen := len(ao.deltas)
		offset, err := ao.roundOffset(rnd)
		if err != nil {
			ao.accountsMu.RUnlock()
			return nil, err
		}

		// Determine how many accounts have been modified in-memory,
		// so that we obtain enough top accounts from disk (accountdb).
		// If the *onlineAccount is nil, that means the account is offline
		// as of the most recent change to that account, or its vote key
		// is not valid in voteRnd.  Otherwise, the *onlineAccount is the
		// representation of the most recent state of the account, and it
		// is online and can vote in voteRnd.
		modifiedAccounts := make(map[basics.Address]*ledgercore.OnlineAccount)
		for o := uint64(0); o < offset; o++ {
			for i := 0; i < ao.deltas[o].Len(); i++ {
				addr, d := ao.deltas[o].GetByIdx(i)
				if d.Status != basics.Online {
					modifiedAccounts[addr] = nil
					continue
				}

				if !(d.VoteFirstValid <= voteRnd && voteRnd <= d.VoteLastValid) {
					modifiedAccounts[addr] = nil
					continue
				}

				modifiedAccounts[addr] = accountDataToOnline(addr, &d, genesisProto)
			}
		}

		ao.accountsMu.RUnlock()

		// Build up a set of candidate accounts.  Start by loading the
		// top N + len(modifiedAccounts) accounts from disk (accountdb).
		// This ensures that, even if the worst case if all in-memory
		// changes are deleting the top accounts in accountdb, we still
		// will have top N left.
		//
		// Keep asking for more accounts until we get the desired number,
		// or there are no more accounts left.
		candidates := make(map[basics.Address]*ledgercore.OnlineAccount)
		batchOffset := uint64(0)
		batchSize := uint64(1024)
		var dbRound basics.Round
		for uint64(len(candidates)) < n+uint64(len(modifiedAccounts)) {
			var accts map[basics.Address]*ledgercore.OnlineAccount
			start := time.Now()
			ledgerAccountsonlinetopCount.Inc(nil)
			err = ao.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
				accts, err = accountsOnlineTop(tx, batchOffset, batchSize, genesisProto)
				if err != nil {
					return
				}
				dbRound, err = onlineAccountsRound(tx)
				return
			})
			ledgerAccountsonlinetopMicros.AddMicrosecondsSince(start, nil)
			if err != nil {
				return nil, err
			}

			if dbRound != currentDbRound {
				break
			}

			for addr, data := range accts {
				if !(data.VoteFirstValid <= voteRnd && voteRnd <= data.VoteLastValid) {
					continue
				}
				candidates[addr] = data
			}

			// If we got fewer than batchSize accounts, there are no
			// more accounts to look at.
			if uint64(len(accts)) < batchSize {
				break
			}

			batchOffset += batchSize
		}
		if dbRound != currentDbRound && dbRound != basics.Round(0) {
			// database round doesn't match the last au.dbRound we sampled.
			ao.accountsMu.RLock()
			for currentDbRound >= ao.cachedDBRoundOnline && currentDeltaLen == len(ao.deltas) {
				ao.accountsReadCond.Wait()
			}
			continue
		}

		// Now update the candidates based on the in-memory deltas.
		for addr, oa := range modifiedAccounts {
			if oa == nil {
				delete(candidates, addr)
			} else {
				candidates[addr] = oa
			}
		}

		// Get the top N accounts from the candidate set, by inserting all of
		// the accounts into a heap and then pulling out N elements from the
		// heap.
		topHeap := &onlineTopHeap{
			accts: nil,
		}

		for _, data := range candidates {
			heap.Push(topHeap, data)
		}

		var res []*ledgercore.OnlineAccount
		for topHeap.Len() > 0 && uint64(len(res)) < n {
			acct := heap.Pop(topHeap).(*ledgercore.OnlineAccount)
			res = append(res, acct)
		}

		return res, nil
	}
}

var ledgerAccountsonlinetopCount = metrics.NewCounter("ledger_accountsonlinetop_count", "calls")
var ledgerAccountsonlinetopMicros = metrics.NewCounter("ledger_accountsonlinetop_micros", "µs spent")
