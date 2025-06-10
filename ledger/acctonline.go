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
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

type modifiedOnlineAccount struct {
	// data stores the most recent ledgercore.AccountData for this modified
	// account.
	data ledgercore.AccountData

	// ndelta keeps track of how many times this account appears in
	// accountUpdates.deltas.  This is used to evict modifiedAccount
	// entries when all changes to an account have been reflected in
	// the account DB, and no outstanding modifications remain.
	ndeltas int
}

// cachedOnlineAccount is a light-weight version of persistedOnlineAccountData suitable for in-memory caching
//
//msgp:ignore cachedOnlineAccount
type cachedOnlineAccount struct {
	trackerdb.BaseOnlineAccountData
	updRound basics.Round
}

// onlineAccounts tracks history of online accounts
type onlineAccounts struct {
	// Connection to the database.
	dbs trackerdb.Store

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq trackerdb.OnlineAccountsReader

	// cachedDBRoundOnline is always exactly tracker DB round (and therefore, onlineAccountsRound()),
	// cached to use in lookup functions
	cachedDBRoundOnline basics.Round

	// deltas stores updates for every round after dbRound.
	deltas []ledgercore.AccountDeltas

	// accounts stores the most recent account state for every
	// address that appears in deltas.
	accounts map[basics.Address]modifiedOnlineAccount

	// onlineRoundParamsData stores onlineMoney, rewards from rounds
	// dbRound + 1 - maxLookback to current round, where maxLookback is max(proto.MaxBalLookback, votersLookback)
	// It behaves as delta storage and a cache.
	onlineRoundParamsData []ledgercore.OnlineRoundParamsData

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
	voters votersTracker

	// baseAccounts stores the most recently used accounts, at exactly dbRound
	baseOnlineAccounts lruOnlineAccounts

	// onlineAccountsCache contains up to onlineAccountsCacheMaxSize accounts with their complete history
	// for the range [Lastest - MaxBalLookback - X, Latest - lookback], where X = [0, commit range]
	// and alway containing an entry for Lastest - MaxBalLookback + 1 if some account is cached.
	// The invariant is held by
	// 1) loading a full history when new accounts get added
	// 2) adding online accounts state changes when flushing to disk
	// 3) pruning the history by removing older than Lastest - MaxBalLookback non-online entries
	onlineAccountsCache onlineAccountsCache

	// maxAcctLookback sets the minimim deltas size to keep in memory
	acctLookback uint64

	// disableCache (de)activates the LRU cache use in onlineAccounts
	disableCache bool

	// cache for expired online circulation stake since the underlying query is quite heavy
	expiredCirculationCache *expiredCirculationCache
}

// initialize initializes the accountUpdates structure
func (ao *onlineAccounts) initialize(cfg config.Local) {
	ao.accountsReadCond = sync.NewCond(ao.accountsMu.RLocker())
	ao.acctLookback = cfg.MaxAcctLookback
	ao.disableCache = cfg.DisableLedgerLRUCache
	// 2 pages * 256 entries look large enough to handle
	// both early and late votes, and well as a current and previous stateproof periods
	ao.expiredCirculationCache = makeExpiredCirculationCache(256)
}

// loadFromDisk is the 2nd level initialization, and is required before the onlineAccounts becomes functional
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

	err = ao.voters.loadFromDisk(l, ao, lastBalancesRound)
	if err != nil {
		err = fmt.Errorf("voters tracker failed to loadFromDisk : %w", err)
	}
	return err
}

// initializeFromDisk performs the atomic operation of loading the accounts data information from disk
// and preparing the onlineAccounts for operation.
func (ao *onlineAccounts) initializeFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) (err error) {
	ao.dbs = l.trackerDB()
	ao.log = l.trackerLog()

	err = ao.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) error {
		ar, makeErr := tx.MakeAccountsReader()
		if makeErr != nil {
			return makeErr
		}

		var err0 error
		var endRound basics.Round
		ao.onlineRoundParamsData, endRound, err0 = ar.AccountsOnlineRoundParams()
		if err0 != nil {
			return err0
		}
		if endRound != ao.cachedDBRoundOnline {
			return fmt.Errorf("last onlineroundparams round %d does not match dbround %d", endRound, ao.cachedDBRoundOnline)
		}

		onlineAccounts, err0 := ar.OnlineAccountsAll(onlineAccountsCacheMaxSize)
		if err0 != nil {
			return err0
		}
		ao.onlineAccountsCache.init(onlineAccounts, onlineAccountsCacheMaxSize)

		return nil
	})
	if err != nil {
		return
	}

	ao.accountsq, err = ao.dbs.MakeOnlineAccountsOptimizedReader()
	if err != nil {
		return
	}

	ao.deltas = nil
	ao.accounts = make(map[basics.Address]modifiedOnlineAccount)
	ao.deltasAccum = []int{0}

	if !ao.disableCache {
		ao.baseOnlineAccounts.init(ao.log, baseAccountsPendingAccountsBufferSize, baseAccountsPendingAccountsWarnThreshold)
	} else {
		ao.baseOnlineAccounts.init(ao.log, 0, 1)
	}
	return
}

// latest returns the latest round
func (ao *onlineAccounts) latest() basics.Round {
	return ao.cachedDBRoundOnline + basics.Round(len(ao.deltas))
}

// close closes the accountUpdates, waiting for all the child go-routine to complete
func (ao *onlineAccounts) close() {
	// ao.voters' loadTree might use ao.accountsq if looking up DB
	// so it must be closed before ao.accountsq
	ao.voters.close()

	if ao.accountsq != nil {
		ao.accountsq.Close()
		ao.accountsq = nil
	}

	ao.baseOnlineAccounts.prune(0)
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
	ao.deltasAccum = append(ao.deltasAccum, delta.Accts.Len()+ao.deltasAccum[len(ao.deltasAccum)-1])

	ao.baseOnlineAccounts.flushPendingWrites()

	for i := 0; i < delta.Accts.Len(); i++ {
		addr, data := delta.Accts.GetByIdx(i)
		macct := ao.accounts[addr]
		macct.ndeltas++
		macct.data = data
		ao.accounts[addr] = macct
	}

	ao.onlineRoundParamsData = append(ao.onlineRoundParamsData, ledgercore.OnlineRoundParamsData{
		OnlineSupply:    delta.Totals.Online.Money.Raw,
		RewardsLevel:    delta.Totals.RewardsLevel,
		CurrentProtocol: blk.CurrentProtocol,
	})

	// calling prune would drop old entries from the base accounts.
	newBaseAccountSize := (len(ao.accounts) + 1) + baseAccountsPendingAccountsBufferSize
	ao.baseOnlineAccounts.prune(newBaseAccountSize)

	ao.voters.newBlock(blk.BlockHeader)

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
	lookback = basics.Round(ao.acctLookback)
	if committedRound < lookback {
		return
	}

	retRound = ao.cachedDBRoundOnline
	lowestRound := ao.voters.lowestRound(ao.cachedDBRoundOnline)
	if lowestRound > 0 && lowestRound < retRound {
		retRound = lowestRound
	}
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

	lowestRound := ao.voters.lowestRound(newBase)

	offset = uint64(newBase - dbRound)
	offset = ao.consecutiveVersion(offset)

	// synchronize base and offset with account updates
	if offset < dcr.offset {
		dcr.offset = offset
	}
	dcr.oldBase = dbRound
	dcr.lowestRound = lowestRound
	return dcr
}

func (ao *onlineAccounts) consecutiveVersion(offset uint64) uint64 {
	// Index that corresponds to the data at dbRound,
	startIndex := len(ao.onlineRoundParamsData) - len(ao.deltas) - 1
	// check if this update chunk spans across multiple consensus versions. If so, break it so that each update would tackle only a single
	// consensus version.
	// startIndex + 1 is the first delta's data, startIndex+int(offset) is the las delta's index from the commit range
	if ao.onlineRoundParamsData[startIndex+1].CurrentProtocol != ao.onlineRoundParamsData[startIndex+int(offset)].CurrentProtocol {
		// find the tip point.
		tipPoint := sort.Search(int(offset), func(i int) bool {
			// we're going to search here for version inequality, with the assumption that consensus versions won't repeat.
			// that allow us to support [ver1, ver1, ..., ver2, ver2, ..., ver3, ver3] but not [ver1, ver1, ..., ver2, ver2, ..., ver1, ver3].
			return ao.onlineRoundParamsData[startIndex+1].CurrentProtocol != ao.onlineRoundParamsData[startIndex+1+i].CurrentProtocol
		})
		// no need to handle the case of "no found", or tipPoint==int(offset), since we already know that it's there.
		offset = uint64(tipPoint)
	}
	return offset
}

func (ao *onlineAccounts) maxBalLookback() uint64 {
	lastProtoVersion := ao.onlineRoundParamsData[len(ao.onlineRoundParamsData)-1].CurrentProtocol
	return config.Consensus[lastProtoVersion].MaxBalLookback
}

// prepareCommit prepares data to write to the database a "chunk" of rounds, and update the cached dbRound accordingly.
func (ao *onlineAccounts) prepareCommit(dcc *deferredCommitContext) error {
	err := ao.prepareCommitInternal(dcc)
	if err != nil {
		return err
	}

	return ao.voters.prepareCommit(dcc)
}

// prepareCommitInternal preforms prepareCommit's logic without locking the tracker's mutex.
func (ao *onlineAccounts) prepareCommitInternal(dcc *deferredCommitContext) error {
	offset := dcc.offset

	ao.accountsMu.RLock()
	defer ao.accountsMu.RUnlock()

	// create a copy of the deltas, round totals and protos for the range we're going to flush.
	deltas := make([]ledgercore.AccountDeltas, offset)
	copy(deltas, ao.deltas[:offset])

	// verify version correctness : all the entries in the au.versions[1:offset+1] should have the *same* version, and the committedUpTo should be enforcing that.
	// Index that corresponds to the oldest round still in deltas
	startIndex := len(ao.onlineRoundParamsData) - len(ao.deltas) - 1
	if ao.onlineRoundParamsData[startIndex+1].CurrentProtocol != ao.onlineRoundParamsData[startIndex+int(offset)].CurrentProtocol {
		return fmt.Errorf("attempted to commit series of rounds with non-uniform consensus versions")
	}

	// compact all the deltas - when we're trying to persist multiple rounds, we might have the same account
	// being updated multiple times. When that happen, we can safely omit the intermediate updates.
	dcc.compactOnlineAccountDeltas = makeCompactOnlineAccountDeltas(deltas, dcc.oldBase, ao.baseOnlineAccounts)

	dcc.genesisProto = ao.ledger.GenesisProto()

	start, err := ao.roundParamsOffset(dcc.oldBase)
	if err != nil {
		return err
	}
	end, err := ao.roundParamsOffset(dcc.newBase())
	if err != nil {
		return err
	}
	// write for rounds oldbase+1 up to and including newbase
	dcc.onlineRoundParams = ao.onlineRoundParamsData[start+1 : end+1]

	maxOnlineLookback := basics.Round(ao.maxBalLookback())
	dcc.onlineAccountsForgetBefore = (dcc.newBase() + 1).SubSaturate(maxOnlineLookback)
	if dcc.lowestRound > 0 && dcc.lowestRound < dcc.onlineAccountsForgetBefore {
		// extend history as needed
		dcc.onlineAccountsForgetBefore = dcc.lowestRound
	}

	return nil
}

// commitRound closure is called within the same transaction for all trackers
// it receives current offset and dbRound
func (ao *onlineAccounts) commitRound(ctx context.Context, tx trackerdb.TransactionScope, dcc *deferredCommitContext) (err error) {
	offset := dcc.offset
	dbRound := dcc.oldBase

	_, err = tx.ResetTransactionWarnDeadline(ctx, time.Now().Add(accountsUpdatePerRoundHighWatermark*time.Duration(offset)))
	if err != nil {
		return err
	}

	err = dcc.compactOnlineAccountDeltas.accountsLoadOld(tx)
	if err != nil {
		return err
	}

	// the updates of the actual account data is done last since the accountsNewRound would modify the compactDeltas old values
	// so that we can update the base account back.
	dcc.updatedPersistedOnlineAccounts, err = onlineAccountsNewRound(tx, dcc.compactOnlineAccountDeltas, dcc.genesisProto, dbRound+basics.Round(offset))
	if err != nil {
		return err
	}

	aw, err := tx.MakeAccountsWriter()
	if err != nil {
		return err
	}

	err = aw.OnlineAccountsDelete(dcc.onlineAccountsForgetBefore)
	if err != nil {
		return err
	}

	err = aw.AccountsPutOnlineRoundParams(dcc.onlineRoundParams, dcc.oldBase+1)
	if err != nil {
		return err
	}

	// delete all entries all older than maxBalLookback (or votersLookback) rounds ago
	err = aw.AccountsPruneOnlineRoundParams(dcc.onlineAccountsForgetBefore)

	return
}

func (ao *onlineAccounts) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	offset := dcc.offset
	newBase := dcc.newBase()

	ao.accountsMu.Lock()
	// Drop reference counts to modified accounts, and evict them
	// from in-memory cache when no references remain.
	for i := 0; i < dcc.compactOnlineAccountDeltas.len(); i++ {
		acctUpdate := dcc.compactOnlineAccountDeltas.getByIdx(i)
		cnt := acctUpdate.nOnlineAcctDeltas
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

	for _, persistedAcct := range dcc.updatedPersistedOnlineAccounts {
		ao.baseOnlineAccounts.write(persistedAcct)
		// add account into onlineAccountsCache only if prior history exists
		ao.onlineAccountsCache.writeFrontIfExist(
			persistedAcct.Addr,
			cachedOnlineAccount{
				BaseOnlineAccountData: persistedAcct.AccountData,
				updRound:              persistedAcct.UpdRound,
			})
	}

	// clear the backing array to let GC collect data
	// see the comment in acctupdates.go
	const deltasClearThreshold = 500
	if offset > deltasClearThreshold {
		for i := uint64(0); i < offset; i++ {
			ao.deltas[i] = ledgercore.AccountDeltas{}
		}
	}

	ao.deltas = ao.deltas[offset:]
	ao.deltasAccum = ao.deltasAccum[offset:]
	ao.cachedDBRoundOnline = newBase

	// onlineRoundParamsData does not require extended history since it is not used in top online accounts
	maxOnlineLookback := int(ao.maxBalLookback()) + len(ao.deltas)
	if len(ao.onlineRoundParamsData) > maxOnlineLookback {
		ao.onlineRoundParamsData = ao.onlineRoundParamsData[len(ao.onlineRoundParamsData)-maxOnlineLookback:]
	}

	// online accounts defines deletion round as
	// dcc.onlineAccountsForgetBefore = (dcc.newBase + 1).SubSaturate(maxOnlineLookback)
	// maxOnlineLookback can be greater than proto.MaxBalLookback because of voters
	// the cache is not used by top accounts (voters) so keep up to proto.MaxBalLookback rounds back
	forgetBefore := (newBase + 1).SubSaturate(basics.Round(ao.maxBalLookback()))
	ao.onlineAccountsCache.prune(forgetBefore)

	ao.accountsMu.Unlock()

	ao.accountsReadCond.Broadcast()

	ao.voters.postCommit(dcc)
}

// onlineCirculation return the total online balance for the given round, for use by agreement.
func (ao *onlineAccounts) onlineCirculation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	// Get cached total stake for rnd
	totalStake, proto, err := ao.onlineTotals(rnd)
	if err != nil {
		return basics.MicroAlgos{}, err
	}

	// Check if we need to subtract expired stake
	if params := config.Consensus[proto]; params.ExcludeExpiredCirculation {
		// Handle case when the balanceRound() used by agreement is 0, resulting in rnd=0.
		// Agreement will ask us for the circulation at round 0 for the first 320 blocks.
		// In this case, we don't subtract expired stake, since we are still using genesis balances.
		// Agreement will later ask us for the balance of round 1 when the voteRnd is 321.
		if rnd == 0 {
			return totalStake, nil
		}
		expiredStake, err := ao.expiredOnlineCirculation(rnd, voteRnd)
		if err != nil {
			return basics.MicroAlgos{}, err
		}
		ot := basics.OverflowTracker{}
		totalStake = ot.SubA(totalStake, expiredStake)
		if ot.Overflowed {
			return basics.MicroAlgos{}, fmt.Errorf("onlineTotals: overflow subtracting %v from %v", expiredStake, totalStake)
		}
	}
	return totalStake, nil
}

// roundsParamsEx return the round params for the given round for extended rounds range
// by looking into DB as needed
// locking semantics: requires accountsMu.RLock()
func (ao *onlineAccounts) roundsParamsEx(rnd basics.Round) (ledgercore.OnlineRoundParamsData, error) {
	paramsOffset, err := ao.roundParamsOffset(rnd)
	if err == nil {
		return ao.onlineRoundParamsData[paramsOffset], nil
	}
	var roundOffsetError *RoundOffsetError
	if !errors.As(err, &roundOffsetError) {
		return ledgercore.OnlineRoundParamsData{}, err
	}

	roundParams, err := ao.accountsq.LookupOnlineRoundParams(rnd)
	if err != nil {
		return ledgercore.OnlineRoundParamsData{}, err
	}
	return roundParams, nil
}

// onlineTotalsEx return the total online balance for the given round for extended rounds range
// by looking into DB
func (ao *onlineAccounts) onlineTotalsEx(rnd basics.Round) (basics.MicroAlgos, error) {
	totalsOnline, _, err := ao.onlineTotals(rnd)
	if err == nil {
		return totalsOnline, nil
	}

	var roundOffsetError *RoundOffsetError
	if !errors.As(err, &roundOffsetError) {
		ao.log.Errorf("onlineTotals error: %v", err)
	}

	roundParams, err := ao.accountsq.LookupOnlineRoundParams(rnd)
	if err != nil {
		return basics.MicroAlgos{}, err
	}
	totalsOnline = basics.MicroAlgos{Raw: roundParams.OnlineSupply}
	return totalsOnline, nil
}

// onlineTotals returns the online totals of all accounts at the end of round rnd.
func (ao *onlineAccounts) onlineTotals(rnd basics.Round) (basics.MicroAlgos, protocol.ConsensusVersion, error) {
	ao.accountsMu.RLock()
	defer ao.accountsMu.RUnlock()
	offset, err := ao.roundParamsOffset(rnd)
	if err != nil {
		return basics.MicroAlgos{}, "", err
	}

	onlineRoundParams := ao.onlineRoundParamsData[offset]
	return basics.MicroAlgos{Raw: onlineRoundParams.OnlineSupply}, onlineRoundParams.CurrentProtocol, nil
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

// roundParamsOffset calculates the offset of the given round compared to the onlineRoundParams cache. Requires that the lock would be taken.
func (ao *onlineAccounts) roundParamsOffset(rnd basics.Round) (offset uint64, err error) {
	// the invariant is that the last element of ao.onlineRoundParamsData is for round ao.latest()
	startRound := ao.latest() + 1 - basics.Round(len(ao.onlineRoundParamsData))
	if rnd < startRound {
		err = &RoundOffsetError{
			round:   rnd,
			dbRound: startRound,
		}
		return
	}

	off := uint64(rnd - startRound)
	if off >= uint64(len(ao.onlineRoundParamsData)) {
		err = fmt.Errorf("round %d too high: dbRound %d, onlineRoundParamsData %d", rnd, startRound, len(ao.onlineRoundParamsData))
		return
	}

	return off, nil
}

// lookupOnlineAccountData returns the online account data for a given address at a given round.
func (ao *onlineAccounts) lookupOnlineAccountData(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	needUnlock := false
	defer func() {
		if needUnlock {
			ao.accountsMu.RUnlock()
		}
	}()
	var err error

	var offset uint64
	var paramsOffset uint64
	var rewardsProto config.ConsensusParams
	var rewardsLevel uint64
	var persistedData trackerdb.PersistedOnlineAccountData

	// the loop serves retrying logic if the database advanced while
	// the function was analyzing deltas or caches.
	// a similar approach is used in other lookup- methods in acctupdates as well.
	for {
		ao.accountsMu.RLock()
		needUnlock = true
		currentDbRound := ao.cachedDBRoundOnline
		currentDeltaLen := len(ao.deltas)
		inHistory := false
		offset, err = ao.roundOffset(rnd)
		if err != nil {
			var roundOffsetError *RoundOffsetError
			if !errors.As(err, &roundOffsetError) {
				return basics.OnlineAccountData{}, err
			}
			// the round number cannot be found in deltas, it is in history
			inHistory = true
		}
		paramsOffset, err = ao.roundParamsOffset(rnd)
		if err != nil {
			return basics.OnlineAccountData{}, err
		}

		rewardsProto = config.Consensus[ao.onlineRoundParamsData[paramsOffset].CurrentProtocol]
		rewardsLevel = ao.onlineRoundParamsData[paramsOffset].RewardsLevel

		// check if we've had this address modified in the past rounds. ( i.e. if it's in the deltas )
		if !inHistory {
			macct, indeltas := ao.accounts[addr]
			if indeltas {
				// Check if this is the most recent round, in which case, we can
				// use a cache of the most recent account state.
				if offset == uint64(len(ao.deltas)) {
					return macct.data.OnlineAccountData(rewardsProto.RewardUnit, rewardsLevel), nil
				}
				// the account appears in the deltas, but we don't know if it appears in the
				// delta range of [0..offset], so we'll need to check :
				// Traverse the deltas backwards to ensure that later updates take
				// priority if present.
				// Note the element at offset is handled above.
				for offset > 0 {
					offset--
					d, ok := ao.deltas[offset].GetData(addr)
					if ok {
						return d.OnlineAccountData(rewardsProto.RewardUnit, rewardsLevel), nil
					}
				}
			}
		}

		if macct, has := ao.onlineAccountsCache.read(addr, rnd); has {
			return macct.GetOnlineAccountData(rewardsProto.RewardUnit, rewardsLevel), nil
		}

		ao.accountsMu.RUnlock()
		needUnlock = false

		// No updates of this account in the in-memory deltas; use on-disk DB.
		// As an optimization, we avoid creating
		// a separate transaction here, and directly use a prepared SQL query
		// against the database.
		persistedData, err = ao.accountsq.LookupOnline(addr, rnd)
		if err != nil || persistedData.Ref == nil {
			// no such online account, return empty
			return basics.OnlineAccountData{}, err
		}
		// Now we load the entire history of this account to fill the onlineAccountsCache, so that the
		// next lookup for this online account will not hit the on-disk DB.
		//
		// lookupOnlineHistory fetches the account DB round from the acctrounds table (validThrough) to
		// distinguish between different cases involving the last-observed value of ao.cachedDBRoundOnline.
		// 1. Updates to ao.onlineAccountsCache happen with ao.accountsMu taken below, as well as in postCommit()
		// 2. If we started reading the history (lookupOnlineHistory)
		//   1. before commitRound or while it is running => OK, read what is in DB and then add new entries in postCommit
		//     * if commitRound deletes some history after, the cache has additional entries and updRound comparison gets a right value
		//   2. after commitRound but before postCommit => OK, read full history, ignore the update from postCommit in writeFront's updRound comparison
		//   3. after postCommit => OK, postCommit does not add new entry with writeFrontIfExist, but here all the full history is loaded
		persistedDataHistory, validThrough, err := ao.accountsq.LookupOnlineHistory(addr)
		if err != nil || len(persistedDataHistory) == 0 {
			return basics.OnlineAccountData{}, err
		}
		// 3. After we finished reading the history (lookupOnlineHistory), either
		//   1. The DB round has not advanced (validThrough == currentDbRound) => OK
		//   2. after commitRound but before postCommit (currentDbRound >= ao.cachedDBRoundOnline && currentDeltaLen == len(ao.deltas)) => OK
		//      the cache gets populated and postCommit updates the new entry
		//   3. after commitRound and after postCommit => problem
		//      postCommit does not add a new entry, but the cache that would get constructed would miss the latest entry, retry
		// In order to resolve this lookupOnlineHistory returns dbRound value (as validThrough) and determine what happened
		// So handle cases 3.1 and 3.2 here, and 3.3 below
		ao.accountsMu.Lock()
		if validThrough == currentDbRound || currentDbRound >= ao.cachedDBRoundOnline && currentDeltaLen == len(ao.deltas) {
			// not advanced or postCommit not called yet, write to the cache and return the value
			ao.onlineAccountsCache.clear(addr)
			if ao.onlineAccountsCache.full() {
				ao.log.Info("onlineAccountsCache full, cannot insert")
			} else {
				for _, data := range persistedDataHistory {
					written := ao.onlineAccountsCache.writeFront(
						data.Addr,
						cachedOnlineAccount{
							BaseOnlineAccountData: data.AccountData,
							updRound:              data.UpdRound,
						})
					if !written {
						ao.accountsMu.Unlock()
						err = fmt.Errorf("failed to write history of acct %s for round %d into online accounts cache", data.Addr.String(), data.UpdRound)
						return basics.OnlineAccountData{}, err
					}
				}
				ao.log.Info("inserted new item to onlineAccountsCache")
			}
			ao.accountsMu.Unlock()
			return persistedData.AccountData.GetOnlineAccountData(rewardsProto.RewardUnit, rewardsLevel), nil
		}
		// case 3.3: retry (for loop iterates and queries again)
		ao.accountsMu.Unlock()

		if validThrough < currentDbRound {
			ao.log.Errorf("onlineAccounts.lookupOnlineAccountData: database round %d is behind in-memory round %d", validThrough, currentDbRound)
			return basics.OnlineAccountData{}, &StaleDatabaseRoundError{databaseRound: validThrough, memoryRound: currentDbRound}
		}
	}
}

// TopOnlineAccounts returns the top n online accounts, sorted by their normalized
// balance and address, whose voting keys are valid in voteRnd.
// The second return value represents the total stake that is online for round == rnd, but will
// not participate in round == voteRnd.
// See the normalization description in AccountData.NormalizedOnlineBalance().
// The return value of totalOnlineStake represents the total stake that is online for voteRnd: it is an approximation since voteRnd did not yet occur.
func (ao *onlineAccounts) TopOnlineAccounts(rnd basics.Round, voteRnd basics.Round, n uint64, params *config.ConsensusParams, rewardsLevel uint64) (topOnlineAccounts []*ledgercore.OnlineAccount, totalOnlineStake basics.MicroAlgos, err error) {
	genesisProto := ao.ledger.GenesisProto()
	ao.accountsMu.RLock()
	for {
		currentDbRound := ao.cachedDBRoundOnline
		currentDeltaLen := len(ao.deltas)
		offset, err := ao.roundOffset(rnd)
		inMemory := true
		if err != nil {
			var roundOffsetError *RoundOffsetError
			if !errors.As(err, &roundOffsetError) {
				ao.accountsMu.RUnlock()
				return nil, basics.MicroAlgos{}, err
			}
			// the round number cannot be found in deltas, it is in history
			inMemory = false
		}

		modifiedAccounts := make(map[basics.Address]*ledgercore.OnlineAccount)
		// Online accounts that will not be valid in voteRnd. Used to calculate their total stake,
		// to be removed from the total online stake if required (lower the upper bound of total online stake in voteRnd).
		invalidOnlineAccounts := make(map[basics.Address]*ledgercore.OnlineAccount)
		if inMemory {
			// Determine how many accounts have been modified in-memory,
			// so that we obtain enough top accounts from disk (accountdb).
			// If the *onlineAccount is nil, that means the account is offline
			// as of the most recent change to that account, or its vote key
			// is not valid in voteRnd.  Otherwise, the *onlineAccount is the
			// representation of the most recent state of the account, and it
			// is online and can vote in voteRnd.
			for o := uint64(0); o < offset; o++ {
				for i := 0; i < ao.deltas[o].Len(); i++ {
					addr, d := ao.deltas[o].GetByIdx(i)
					if d.Status != basics.Online {
						modifiedAccounts[addr] = nil
						continue
					}

					if !(d.VoteFirstValid <= voteRnd && voteRnd <= d.VoteLastValid) {
						modifiedAccounts[addr] = nil
						invalidOnlineAccounts[addr] = accountDataToOnline(addr, &d, genesisProto)

						continue
					}

					modifiedAccounts[addr] = accountDataToOnline(addr, &d, genesisProto)
				}
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
			ledgerAccountsOnlineTopCount.Inc(nil)
			err = ao.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
				ar, err := tx.MakeAccountsReader()
				if err != nil {
					return err
				}

				accts, err = ar.AccountsOnlineTop(rnd, batchOffset, batchSize, genesisProto.RewardUnit)
				if err != nil {
					return
				}
				dbRound, err = ar.AccountsRound()
				return
			})
			ledgerAccountsOnlineTopMicros.AddMicrosecondsSince(start, nil)
			if err != nil {
				return nil, basics.MicroAlgos{}, err
			}

			if dbRound != currentDbRound {
				break
			}

			for addr, data := range accts {
				if !(data.VoteFirstValid <= voteRnd && voteRnd <= data.VoteLastValid) {
					// If already exists it originated from the deltas, meaning its data is more recent
					if _, ok := invalidOnlineAccounts[addr]; !ok {
						invalidOnlineAccounts[addr] = data
					}
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
		// If dbRound has advanced beyond the last read of ao.cachedDBRoundOnline, postCommmit has
		// occurred since then, so wait until deltas is consistent with dbRound and try again.
		// dbRound will be zero if all the information needed was already found in deltas, so no DB
		// query was made, and it is safe to let through and return.
		if dbRound > currentDbRound && dbRound != basics.Round(0) {
			// database round doesn't match the last au.dbRound we sampled.
			ao.accountsMu.RLock()
			for currentDbRound >= ao.cachedDBRoundOnline && currentDeltaLen == len(ao.deltas) {
				ao.accountsReadCond.Wait()
			}
			continue
		}
		if dbRound < currentDbRound && dbRound != basics.Round(0) {
			ao.log.Errorf("onlineAccounts.onlineTop: database round %d is behind in-memory round %d", dbRound, currentDbRound)
			return nil, basics.MicroAlgos{}, &StaleDatabaseRoundError{databaseRound: dbRound, memoryRound: currentDbRound}
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

		for topHeap.Len() > 0 && uint64(len(topOnlineAccounts)) < n {
			acct := heap.Pop(topHeap).(*ledgercore.OnlineAccount)
			topOnlineAccounts = append(topOnlineAccounts, acct)
		}

		totalOnlineStake, err = ao.onlineTotalsEx(rnd)
		if err != nil {
			return nil, basics.MicroAlgos{}, err
		}

		// If set, return total online stake minus all future expired stake by voteRnd
		if params.ExcludeExpiredCirculation {
			expiredStake, err := ao.expiredOnlineCirculation(rnd, voteRnd)
			if err != nil {
				return nil, basics.MicroAlgos{}, err
			}
			ot := basics.OverflowTracker{}
			onlineStake := ot.SubA(totalOnlineStake, expiredStake)
			if ot.Overflowed {
				return nil, basics.MicroAlgos{}, fmt.Errorf("TopOnlineAccounts: overflow subtracting ExpiredOnlineCirculation: %d - %d", totalOnlineStake, expiredStake)
			}
			return topOnlineAccounts, onlineStake, nil
		}

		ot := basics.OverflowTracker{}
		for _, oa := range invalidOnlineAccounts {
			totalOnlineStake = ot.SubA(totalOnlineStake, oa.MicroAlgos)
			if ot.Overflowed {
				return nil, basics.MicroAlgos{}, fmt.Errorf("TopOnlineAccounts: overflow in stakeOfflineInVoteRound")
			}
			if params.StateProofExcludeTotalWeightWithRewards {
				rewards := basics.PendingRewards(&ot, params.RewardUnit, oa.MicroAlgos, oa.RewardsBase, rewardsLevel)
				totalOnlineStake = ot.SubA(totalOnlineStake, rewards)
				if ot.Overflowed {
					return nil, basics.MicroAlgos{}, fmt.Errorf("TopOnlineAccounts: overflow in stakeOfflineInVoteRound rewards")
				}
			}
		}

		return topOnlineAccounts, totalOnlineStake, nil
	}
}

func (ao *onlineAccounts) onlineAcctsExpiredByRound(rnd, voteRnd basics.Round) (map[basics.Address]*basics.OnlineAccountData, error) {
	needUnlock := false
	defer func() {
		if needUnlock {
			ao.accountsMu.RUnlock()
		}
	}()

	var expiredAccounts map[basics.Address]*basics.OnlineAccountData
	ao.accountsMu.RLock()
	needUnlock = true
	for {
		currentDbRound := ao.cachedDBRoundOnline
		currentDeltaLen := len(ao.deltas)
		offset, err := ao.roundOffset(rnd)
		if err != nil {
			var roundOffsetError *RoundOffsetError
			if !errors.As(err, &roundOffsetError) {
				return nil, err
			}
			// roundOffsetError was returned, so the round number cannot be found in deltas, it is in history.
			// This means offset will be 0 and ao.deltas[:offset] will be an empty slice.
		}

		roundParams, err := ao.roundsParamsEx(rnd)
		if err != nil {
			return nil, err
		}
		rewardsParams := config.Consensus[roundParams.CurrentProtocol]
		rewardsLevel := roundParams.RewardsLevel

		start := time.Now()
		ledgerAccountExpiredByRoundCount.Inc(nil)

		// Step 1: get all online accounts from DB for rnd
		// Not unlocking ao.accountsMu yet, to stay consistent with Step 2
		var dbRound basics.Round
		err = ao.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
			ar, err := tx.MakeAccountsReader()
			if err != nil {
				return err
			}
			expiredAccounts, err = ar.ExpiredOnlineAccountsForRound(rnd, voteRnd, rewardsParams.RewardUnit, rewardsLevel)
			if err != nil {
				return err
			}
			dbRound, err = ar.AccountsRound()
			return err
		})
		ledgerAccountsExpiredByRoundMicros.AddMicrosecondsSince(start, nil)
		if err != nil {
			return nil, err
		}

		// If dbRound has advanced beyond the last read of ao.cachedDBRoundOnline, postCommmit has
		// occurred since then, so wait until deltas is consistent with dbRound and try again.
		if dbRound > currentDbRound {
			// database round doesn't match the last au.dbRound we sampled.
			for currentDbRound >= ao.cachedDBRoundOnline && currentDeltaLen == len(ao.deltas) {
				ao.accountsReadCond.Wait()
			}
			continue // retry (restart for loop)
		}
		if dbRound < currentDbRound {
			ao.log.Errorf("onlineAccounts.ValidOnlineCirculation: database round %d is behind in-memory round %d", dbRound, currentDbRound)
			return nil, &StaleDatabaseRoundError{databaseRound: dbRound, memoryRound: currentDbRound}
		}

		// Step 2: Apply pending changes for each block in deltas
		// Iterate through per-round deltas up to offset: target round `rnd` is ao.deltas[offset-1].
		for o := uint64(0); o < offset; o++ {
			for i := 0; i < ao.deltas[o].Len(); i++ {
				addr, d := ao.deltas[o].GetByIdx(i)
				// Each round's deltas can insert, update, or delete values in the onlineAccts map.
				// Note, VoteFirstValid is not checked here on purpose since the current implementation does not allow
				// setting VoteFirstValid into future.
				if d.Status == basics.Online && d.VoteLastValid != 0 && voteRnd > d.VoteLastValid {
					// Online expired: insert or overwrite the old data in expiredAccounts.
					oadata := d.OnlineAccountData(rewardsParams.RewardUnit, rewardsLevel)
					expiredAccounts[addr] = &oadata
				} else {
					// addr went offline not expired, so do not report as an expired ONLINE account.
					delete(expiredAccounts, addr)
				}
			}
		}
		break // successfully retrieved onlineAccts from DB & deltas
	}
	ao.accountsMu.RUnlock()
	needUnlock = false

	return expiredAccounts, nil
}

// expiredOnlineCirculation returns the total online stake for accounts with participation keys registered
// at round `rnd` that are expired by round `voteRnd`.
func (ao *onlineAccounts) expiredOnlineCirculation(rnd, voteRnd basics.Round) (basics.MicroAlgos, error) {
	if expiredStake, ok := ao.expiredCirculationCache.get(rnd, voteRnd); ok {
		return expiredStake, nil
	}

	expiredAccounts, err := ao.onlineAcctsExpiredByRound(rnd, voteRnd)
	if err != nil {
		return basics.MicroAlgos{}, err
	}
	ot := basics.OverflowTracker{}
	expiredStake := basics.MicroAlgos{}
	for _, d := range expiredAccounts {
		expiredStake = ot.AddA(expiredStake, d.MicroAlgosWithRewards)
		if ot.Overflowed {
			return basics.MicroAlgos{}, fmt.Errorf("ExpiredOnlineCirculation: overflow totaling expired stake")
		}
	}
	ao.expiredCirculationCache.put(rnd, voteRnd, expiredStake)
	return expiredStake, nil
}

var ledgerAccountsOnlineTopCount = metrics.NewCounter("ledger_accountsonlinetop_count", "calls")
var ledgerAccountsOnlineTopMicros = metrics.NewCounter("ledger_accountsonlinetop_micros", "µs spent")
var ledgerAccountExpiredByRoundCount = metrics.NewCounter("ledger_accountsexpired_count", "calls")
var ledgerAccountsExpiredByRoundMicros = metrics.NewCounter("ledger_accountsexpired_micros", "µs spent")
