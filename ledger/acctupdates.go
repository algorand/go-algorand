// Copyright (C) 2019-2024 Algorand, Inc.
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
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

const (
	// balancesFlushInterval defines how frequently we want to flush our balances to disk.
	balancesFlushInterval = 5 * time.Second
	// pendingDeltasFlushThreshold is the deltas count threshold above we flush the pending balances regardless of the flush interval.
	pendingDeltasFlushThreshold = 128
)

// baseAccountsPendingAccountsBufferSize defines the size of the base account pending accounts buffer size.
// At the beginning of a new round, the entries from this buffer are being flushed into the base accounts map.
const baseAccountsPendingAccountsBufferSize = 100000

// baseAccountsPendingAccountsWarnThreshold defines the threshold at which the lruAccounts would generate a warning
// after we've surpassed a given pending account size. The warning is being generated when the pending accounts data
// is being flushed into the main base account cache.
const baseAccountsPendingAccountsWarnThreshold = 85000

// baseResourcesPendingAccountsBufferSize defines the size of the base resources pending accounts buffer size.
// At the beginning of a new round, the entries from this buffer are being flushed into the base resources map.
const baseResourcesPendingAccountsBufferSize = 10000

// baseResourcesPendingAccountsWarnThreshold defines the threshold at which the lruResources would generate a warning
// after we've surpassed a given pending account resources size. The warning is being generated when the pending accounts data
// is being flushed into the main base resources cache.
const baseResourcesPendingAccountsWarnThreshold = 8500

// baseKVPendingBufferSize defines the size of the base KVs pending buffer size.
// At the beginning of a new round, the entries from this buffer are being flushed into the base KVs map.
const baseKVPendingBufferSize = 5000

// baseKVPendingWarnThreshold defines the threshold at which the lruKV would generate a warning
// after we've surpassed a given pending kv size. The warning is being generated when the pending kv data
// is being flushed into the main base kv cache.
const baseKVPendingWarnThreshold = 4250

// initializeCachesReadaheadBlocksStream defines how many block we're going to attempt to queue for the
// initializeCaches method before it can process and store the account changes to disk.
const initializeCachesReadaheadBlocksStream = 4

// initializeCachesRoundFlushInterval defines the number of rounds between every to consecutive
// attempts to flush the memory account data to disk. Setting this value too high would increase
// memory utilization. Setting this too low, would increase disk i/o.
const initializeCachesRoundFlushInterval = 1000

// initializingAccountCachesMessageTimeout controls the amount of time passes before we
// log "initializingAccount initializing.." message to the log file. This is primarily for
// nodes with slower disk access, where a feedback that the node is functioning correctly is needed.
const initializingAccountCachesMessageTimeout = 3 * time.Second

// accountsUpdatePerRoundHighWatermark is the warning watermark for updating accounts data that takes
// longer than expected. We set it up here for one second per round, so that if we're bulk updating
// four rounds, we would allow up to 4 seconds. This becomes important when supporting balances recovery
// where we end up batching up to 1000 rounds in a single update.
const accountsUpdatePerRoundHighWatermark = 1 * time.Second

// forceCatchpointFileGenerationTrackingMode defines the CatchpointTracking mode that would be used to
// force a node to generate catchpoint files.
const forceCatchpointFileGenerationTrackingMode = 99

// A modifiedAccount represents an account that has been modified since
// the persistent state stored in the account DB (i.e., in the range of
// rounds covered by the accountUpdates tracker).
type modifiedAccount struct {
	// data stores the most recent ledgercore.AccountData for this modified
	// account.
	data ledgercore.AccountData

	// ndelta keeps track of how many times this account appears in
	// accountUpdates.deltas.  This is used to evict modifiedAccount
	// entries when all changes to an account have been reflected in
	// the account DB, and no outstanding modifications remain.
	ndeltas int
}

// accountCreatable is used as a map key.
type accountCreatable struct {
	address basics.Address
	index   basics.CreatableIndex
}

//msgp:ignore modifiedResource
type modifiedResource struct {
	// resource stores concrete information about this particular resource
	resource ledgercore.AccountResource

	// ndelta keeps track of how many times this resource appears in
	// accountUpdates.deltas.  This is used to evict modifiedResource
	// entries when all changes to an account have been reflected in
	// the account DB, and no outstanding modifications remain.
	ndeltas int
}

// A modifiedKvValue represents a kv store change since the persistent state
// stored in the DB (i.e., in the range of rounds covered by the accountUpdates
// tracker).
type modifiedKvValue struct {
	// data stores the most recent value (nil == deleted)
	data []byte

	// oldData stores the previous vlaue (nil == didn't exist)
	oldData []byte

	// ndelta keeps track of how many times the key for this value appears in
	// accountUpdates.deltas.  This is used to evict modifiedValue entries when
	// all changes to a key have been reflected in the kv table, and no
	// outstanding modifications remain.
	ndeltas int
}

type accountUpdates struct {
	// Connection to the database.
	dbs trackerdb.Store

	// Optimized reader for fast accounts DB lookups.
	accountsq trackerdb.AccountsReader

	// cachedDBRound is always exactly tracker DB round (and therefore, accountsRound()),
	// cached to use in lookup functions
	cachedDBRound basics.Round

	// deltas stores updates for every round after dbRound.
	deltas []ledgercore.StateDelta

	// accounts stores the most recent account state for every
	// address that appears in deltas.
	accounts map[basics.Address]modifiedAccount

	// resources stored the most recent resource state for every
	// address&resource that appears in deltas.
	resources resourcesUpdates

	// kvStore has the most recent kv pairs for every write/del that appears in
	// deltas.
	kvStore map[string]modifiedKvValue

	// creatables stores the most recent state for every creatable that
	// appears in creatableDeltas
	creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable

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

	// baseAccounts stores the most recently used accounts, at exactly dbRound
	baseAccounts lruAccounts

	// baseResources stores the most recently used resources, at exactly dbRound
	baseResources lruResources

	// baseKVs stores the most recently used KV, at exactly dbRound
	baseKVs lruKV

	// logAccountUpdatesMetrics is a flag for enable/disable metrics logging
	logAccountUpdatesMetrics bool

	// logAccountUpdatesInterval sets a time interval for metrics logging
	logAccountUpdatesInterval time.Duration

	// lastMetricsLogTime is the time when the previous metrics logging occurred
	lastMetricsLogTime time.Time

	// maxAcctLookback sets the minimim deltas size to keep in memory
	acctLookback uint64

	// disableCache (de)activates the LRU cache use in accountUpdates
	disableCache bool
}

// RoundOffsetError is an error for when requested round is behind earliest stored db entry
type RoundOffsetError struct {
	round   basics.Round
	dbRound basics.Round
}

func (e *RoundOffsetError) Error() string {
	return fmt.Sprintf("round %d before dbRound %d", e.round, e.dbRound)
}

// StaleDatabaseRoundError is generated when we detect that the database round is behind the accountUpdates in-memory dbRound. This
// should never happen, since we update the database first, and only upon a successful update we update the in-memory dbRound.
type StaleDatabaseRoundError struct {
	memoryRound   basics.Round
	databaseRound basics.Round
}

func (e *StaleDatabaseRoundError) Error() string {
	return fmt.Sprintf("database round %d is behind in-memory round %d", e.databaseRound, e.memoryRound)
}

// MismatchingDatabaseRoundError is generated when we detect that the database round is different than the accountUpdates in-memory dbRound. This
// could happen normally when the database and the in-memory dbRound aren't synchronized. However, when we work in non-sync mode, we expect the database to be
// always synchronized with the in-memory data. When that condition is violated, this error is generated.
type MismatchingDatabaseRoundError struct {
	memoryRound   basics.Round
	databaseRound basics.Round
}

func (e *MismatchingDatabaseRoundError) Error() string {
	return fmt.Sprintf("database round %d mismatching in-memory round %d", e.databaseRound, e.memoryRound)
}

// ErrLookupLatestResources is returned if there is an error retrieving an account along with its resources.
var ErrLookupLatestResources = errors.New("couldn't find latest resources")

//msgp:ignore resourcesUpdates
type resourcesUpdates map[accountCreatable]modifiedResource

func (r resourcesUpdates) set(ac accountCreatable, m modifiedResource) { r[ac] = m }

func (r resourcesUpdates) get(ac accountCreatable) (m modifiedResource, ok bool) {
	m, ok = r[ac]
	return
}

func (r resourcesUpdates) getForAddress(addr basics.Address) map[basics.CreatableIndex]modifiedResource {
	res := make(map[basics.CreatableIndex]modifiedResource)

	for k, v := range r {
		if k.address == addr {
			res[k.index] = v
		}
	}

	return res
}

// initialize initializes the accountUpdates structure
func (au *accountUpdates) initialize(cfg config.Local) {
	au.accountsReadCond = sync.NewCond(au.accountsMu.RLocker())

	au.acctLookback = cfg.MaxAcctLookback

	// log metrics
	au.logAccountUpdatesMetrics = cfg.EnableAccountUpdatesStats
	au.logAccountUpdatesInterval = cfg.AccountUpdatesStatsInterval

	au.disableCache = cfg.DisableLedgerLRUCache
}

// loadFromDisk is the 2nd level initialization, and is required before the accountUpdates becomes functional
// The close function is expected to be call in pair with loadFromDisk
func (au *accountUpdates) loadFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) error {
	au.accountsMu.Lock()
	defer au.accountsMu.Unlock()

	au.cachedDBRound = lastBalancesRound
	err := au.initializeFromDisk(l, lastBalancesRound)
	if err != nil {
		return err
	}
	return nil
}

// close closes the accountUpdates, waiting for all the child go-routine to complete
func (au *accountUpdates) close() {
	if au.accountsq != nil {
		au.accountsq.Close()
		au.accountsq = nil
	}
	au.baseAccounts.prune(0)
	au.baseResources.prune(0)
	au.baseKVs.prune(0)
}

// flushCaches flushes any pending data in caches so that it is fully available during future lookups.
func (au *accountUpdates) flushCaches() {
	t0 := time.Now()
	ledgerAccountsMuLockCount.Inc(nil)
	au.accountsMu.Lock()

	au.baseAccounts.flushPendingWrites()
	au.baseResources.flushPendingWrites()
	au.baseKVs.flushPendingWrites()

	au.accountsMu.Unlock()
	ledgerAccountsMuLockMicros.AddMicrosecondsSince(t0, nil)
}

func (au *accountUpdates) LookupResource(rnd basics.Round, addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ledgercore.AccountResource, basics.Round, error) {
	return au.lookupResource(rnd, addr, aidx, ctype, true /* take lock */)
}

func (au *accountUpdates) LookupAssetResources(addr basics.Address, assetIDGT basics.AssetIndex, limit uint64) ([]ledgercore.AssetResourceWithIDs, basics.Round, error) {
	return au.lookupAssetResources(addr, assetIDGT, limit)
}

func (au *accountUpdates) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	return au.lookupKv(rnd, key, true /* take lock */)
}

func (au *accountUpdates) lookupKv(rnd basics.Round, key string, synchronized bool) ([]byte, error) {
	needUnlock := false
	if synchronized {
		au.accountsMu.RLock()
		needUnlock = true
	}
	defer func() {
		if needUnlock {
			au.accountsMu.RUnlock()
		}
	}()

	// TODO: This loop and round handling is copied from other routines like
	// lookupResource. I believe that it is overly cautious, as it always reruns
	// the lookup if the DB round does not match the expected round. However, as
	// long as the db round has not advanced too far (greater than `rnd`), I
	// believe it would be valid to use. In the interest of minimizing changes,
	// I'm not doing that now.

	for {
		currentDbRound := au.cachedDBRound
		currentDeltaLen := len(au.deltas)
		offset, err := au.roundOffset(rnd)
		if err != nil {
			return nil, err
		}

		// check if we have this key in `kvStore`, as that means the change we
		// care about is in kvDeltas (and maybe just kvStore itself)
		mval, indeltas := au.kvStore[key]
		if indeltas {
			// Check if this is the most recent round, in which case, we can
			// use a cache of the most recent kvStore state
			if offset == uint64(len(au.deltas)) {
				return mval.data, nil
			}

			// the key is in the deltas, but we don't know if it appears in the
			// delta range of [0..offset-1], so we'll need to check. Walk deltas
			// backwards so later updates take priority.
			for offset > 0 {
				offset--
				mval, ok := au.deltas[offset].KvMods[key]
				if ok {
					return mval.Data, nil
				}
			}
		} else {
			// we know that the key is not in kvDeltas - so there is no point in scanning it.
			// we've going to fall back to search in the database, but before doing so, we should
			// update the rnd so that it would point to the end of the known delta range.
			// ( that would give us the best validity range )
			rnd = currentDbRound + basics.Round(currentDeltaLen)
		}

		// check the baseKV cache
		if pbd, has := au.baseKVs.read(key); has {
			// we don't technically need this, since it's already in the baseKV, however, writing this over
			// would ensure that we promote this field.
			au.baseKVs.writePending(pbd, key)
			return pbd.Value, nil
		}

		if synchronized {
			au.accountsMu.RUnlock()
			needUnlock = false
		}

		// No updates of this account in kvDeltas; use on-disk DB.  The check in
		// roundOffset() made sure the round is exactly the one present in the
		// on-disk DB.

		persistedData, err := au.accountsq.LookupKeyValue(key)
		if err != nil {
			return nil, err
		}

		if persistedData.Round == currentDbRound {
			// if we read actual data return it. This includes deleted values
			// where persistedData.value == nil to avoid unnecessary db lookups
			// for deleted KVs.
			au.baseKVs.writePending(persistedData, key)
			return persistedData.Value, nil
		}

		// The db round is unexpected...
		if synchronized {
			if persistedData.Round < currentDbRound {
				// Somehow the db is LOWER than it should be.
				au.log.Errorf("accountUpdates.lookupKvPair: database round %d is behind in-memory round %d", persistedData.Round, currentDbRound)
				return nil, &StaleDatabaseRoundError{databaseRound: persistedData.Round, memoryRound: currentDbRound}
			}
			// The db is higher, so a write must have happened.  Try again.
			au.accountsMu.RLock()
			needUnlock = true
			// WHY BOTH - seems the goal is just to wait until the au is aware of progress. au.cachedDBRound should be enough?
			for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
				au.accountsReadCond.Wait()
			}
		} else {
			// in non-sync mode, we don't wait since we already assume that we're synchronized.
			au.log.Errorf("accountUpdates.lookupKvPair: database round %d mismatching in-memory round %d", persistedData.Round, currentDbRound)
			return nil, &MismatchingDatabaseRoundError{databaseRound: persistedData.Round, memoryRound: currentDbRound}
		}

	}
}

func (au *accountUpdates) LookupKeysByPrefix(round basics.Round, keyPrefix string, maxKeyNum uint64) ([]string, error) {
	return au.lookupKeysByPrefix(round, keyPrefix, maxKeyNum, true /* take lock */)
}

func (au *accountUpdates) lookupKeysByPrefix(round basics.Round, keyPrefix string, maxKeyNum uint64, synchronized bool) (resultKeys []string, err error) {
	var results map[string]bool
	// keep track of the number of result key with value
	var resultCount uint64

	needUnlock := false
	if synchronized {
		au.accountsMu.RLock()
		needUnlock = true
	}
	defer func() {
		if needUnlock {
			au.accountsMu.RUnlock()
		}
		// preparation of result happens in deferring function
		// prepare result only when err != nil
		if err == nil {
			resultKeys = make([]string, 0, resultCount)
			for resKey, present := range results {
				if present {
					resultKeys = append(resultKeys, resKey)
				}
			}
		}
	}()

	// TODO: This loop and round handling is copied from other routines like
	// lookupResource. I believe that it is overly cautious, as it always reruns
	// the lookup if the DB round does not match the expected round. However, as
	// long as the db round has not advanced too far (greater than `rnd`), I
	// believe it would be valid to use. In the interest of minimizing changes,
	// I'm not doing that now.

	for {
		currentDBRound := au.cachedDBRound
		currentDeltaLen := len(au.deltas)
		offset, rndErr := au.roundOffset(round)
		if rndErr != nil {
			return nil, rndErr
		}

		// reset `results` to be empty each iteration
		// if db round does not match the round number returned from DB query, start over again
		// NOTE: `results` is maintained as we walk backwards from the latest round, to DB
		// IT IS NOT SIMPLY A SET STORING KEY NAMES!
		// - if the boolean for the key is true: we consider the key is still valid in later round
		// - otherwise, we consider that the key is deleted in later round, and we will not return it as part of result
		// Thus: `resultCount` keeps track of how many VALID keys in the `results`
		// DO NOT TRY `len(results)` TO SEE NUMBER OF VALID KEYS!
		results = map[string]bool{}
		resultCount = 0

		for offset > 0 {
			offset--
			for keyInRound, mv := range au.deltas[offset].KvMods {
				if !strings.HasPrefix(keyInRound, keyPrefix) {
					continue
				}
				// whether it is set or deleted in later round, if such modification exists in later round
				// we just ignore the earlier insert
				if _, ok := results[keyInRound]; ok {
					continue
				}
				if mv.Data == nil {
					results[keyInRound] = false
				} else {
					// set such key to be valid with value
					results[keyInRound] = true
					resultCount++
					// check if the size of `results` reaches `maxKeyNum`
					// if so just return the list of keys
					if resultCount == maxKeyNum {
						return
					}
				}
			}
		}

		round = currentDBRound + basics.Round(currentDeltaLen)

		// after this line, we should dig into DB I guess
		// OTHER LOOKUPS USE "base" caches here.
		if synchronized {
			au.accountsMu.RUnlock()
			needUnlock = false
		}

		// NOTE: the kv cache isn't used here because the data structure doesn't support range
		// queries. It may be preferable to increase the SQLite cache size if these reads become
		// too slow.

		// Finishing searching updates of this account in kvDeltas, keep going: use on-disk DB
		// to find the rest matching keys in DB.
		dbRound, dbErr := au.accountsq.LookupKeysByPrefix(keyPrefix, maxKeyNum, results, resultCount)
		if dbErr != nil {
			return nil, dbErr
		}
		if dbRound == currentDBRound {
			return
		}

		// The DB round is unexpected... '_>'?
		if synchronized {
			if dbRound < currentDBRound {
				// does not make sense if DB round is earlier than it should be
				au.log.Errorf("accountUpdates.lookupKvPair: database round %d is behind in-memory round %d", dbRound, currentDBRound)
				err = &StaleDatabaseRoundError{databaseRound: dbRound, memoryRound: currentDBRound}
				return
			}
			// The DB round is higher than expected, so a write-into-DB must have happened. Start over again.
			au.accountsMu.RLock()
			needUnlock = true
			// WHY BOTH - seems the goal is just to wait until the au is aware of progress. au.cachedDBRound should be enough?
			for currentDBRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
				au.accountsReadCond.Wait()
			}
		} else {
			au.log.Errorf("accountUpdates.lookupKvPair: database round %d mismatching in-memory round %d", dbRound, currentDBRound)
			err = &MismatchingDatabaseRoundError{databaseRound: dbRound, memoryRound: currentDBRound}
			return
		}
	}
}

// LookupWithoutRewards returns the account data for a given address at a given round.
func (au *accountUpdates) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (data ledgercore.AccountData, validThrough basics.Round, err error) {
	data, validThrough, _, _, err = au.lookupWithoutRewards(rnd, addr, true /* take lock*/)
	return
}

// GetCreatorForRound returns the creator for a given asset/app index at a given round
func (au *accountUpdates) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	return au.getCreatorForRound(rnd, cidx, ctype, true /* take the lock */)
}

// committedUpTo implements the ledgerTracker interface for accountUpdates.
// The method informs the tracker that committedRound and all it's previous rounds have
// been committed to the block database. The method returns what is the oldest round
// number that can be removed from the blocks database as well as the lookback that this
// tracker maintains.
func (au *accountUpdates) committedUpTo(committedRound basics.Round) (retRound, lookback basics.Round) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()

	retRound = basics.Round(0)
	lookback = basics.Round(au.acctLookback)
	if committedRound < lookback {
		return
	}

	retRound = au.cachedDBRound
	return
}

// produceCommittingTask enqueues committing the balances for round committedRound-lookback.
// The deferred committing is done so that we could calculate the historical balances lookback rounds back.
// Since we don't want to hold off the tracker's mutex for too long, we'll defer the database persistence of this
// operation to a syncer goroutine. The one caveat is that when storing a catchpoint round, we would want to
// wait until the catchpoint creation is done, so that the persistence of the catchpoint file would have an
// uninterrupted view of the balances at a given point of time.
func (au *accountUpdates) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	var offset uint64
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()

	if committedRound < dcr.lookback {
		return nil
	}

	newBase := committedRound - dcr.lookback
	if newBase <= dbRound {
		// Already forgotten
		return nil
	}

	if newBase > dbRound+basics.Round(len(au.deltas)) {
		au.log.Panicf("produceCommittingTask: block %d too far in the future, lookback %d, dbRound %d (cached %d), deltas %d", committedRound, dcr.lookback, dbRound, au.cachedDBRound, len(au.deltas))
	}

	offset = uint64(newBase - dbRound)

	offset = au.consecutiveVersion(offset)

	// calculate the number of pending deltas
	dcr.pendingDeltas = au.deltasAccum[offset] - au.deltasAccum[0]

	proto := config.Consensus[au.versions[offset]]
	dcr.catchpointLookback = proto.CatchpointLookback
	if dcr.catchpointLookback == 0 {
		dcr.catchpointLookback = proto.MaxBalLookback
	}

	// submit committing task only if offset is non-zero in addition to
	// 1) no pending catchpoint writes
	// 2) batching requirements meet or catchpoint round
	dcr.oldBase = dbRound
	dcr.offset = offset
	return dcr
}

func (au *accountUpdates) consecutiveVersion(offset uint64) uint64 {
	// check if this update chunk spans across multiple consensus versions. If so, break it so that each update would tackle only a single
	// consensus version.
	if au.versions[1] != au.versions[offset] {
		// find the tip point.
		tipPoint := sort.Search(int(offset), func(i int) bool {
			// we're going to search here for version inequality, with the assumption that consensus versions won't repeat.
			// that allow us to support [ver1, ver1, ..., ver2, ver2, ..., ver3, ver3] but not [ver1, ver1, ..., ver2, ver2, ..., ver1, ver3].
			return au.versions[1] != au.versions[1+i]
		})
		// no need to handle the case of "no found", or tipPoint==int(offset), since we already know that it's there.
		offset = uint64(tipPoint)
	}
	return offset
}

// newBlock is the accountUpdates implementation of the ledgerTracker interface. This is the "external" facing function
// which invokes the internal implementation after taking the lock.
func (au *accountUpdates) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	t0 := time.Now()
	ledgerAccountsMuLockCount.Inc(nil)
	au.accountsMu.Lock()
	au.newBlockImpl(blk, delta)
	au.accountsMu.Unlock()
	ledgerAccountsMuLockMicros.AddMicrosecondsSince(t0, nil)
	au.accountsReadCond.Broadcast()
}

// LatestTotals returns the totals of all accounts for the most recent round, as well as the round number
func (au *accountUpdates) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	return au.latestTotalsImpl()
}

// Totals returns the totals of all accounts for the given round
func (au *accountUpdates) Totals(rnd basics.Round) (ledgercore.AccountTotals, error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	return au.totalsImpl(rnd)
}

// ReadCloseSizer interface implements the standard io.Reader and io.Closer as well
// as supporting the Size() function that let the caller know what the size of the stream would be (in bytes).
type ReadCloseSizer interface {
	io.ReadCloser
	Size() (int64, error)
}

// readCloseSizer is an instance of the ReadCloseSizer interface
type readCloseSizer struct {
	io.ReadCloser
	size int64
}

// Size returns the length of the associated stream.
func (r *readCloseSizer) Size() (int64, error) {
	if r.size < 0 {
		return 0, fmt.Errorf("unknown stream size")
	}
	return r.size, nil
}

// functions below this line are all internal functions

// latestTotalsImpl returns the totals of all accounts for the most recent round, as well as the round number
func (au *accountUpdates) latestTotalsImpl() (basics.Round, ledgercore.AccountTotals, error) {
	offset := len(au.deltas)
	rnd := au.cachedDBRound + basics.Round(len(au.deltas))
	return rnd, au.roundTotals[offset], nil
}

// totalsImpl returns the totals of all accounts for the given round
func (au *accountUpdates) totalsImpl(rnd basics.Round) (ledgercore.AccountTotals, error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return ledgercore.AccountTotals{}, err
	}
	return au.roundTotals[offset], nil
}

// initializeFromDisk performs the atomic operation of loading the accounts data information from disk
// and preparing the accountUpdates for operation.
func (au *accountUpdates) initializeFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) error {
	au.dbs = l.trackerDB()
	au.log = l.trackerLog()
	au.ledger = l

	start := time.Now()
	ledgerAccountsinitCount.Inc(nil)
	err := au.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) error {
		ar, err0 := tx.MakeAccountsReader()
		if err0 != nil {
			return err0
		}

		totals, err0 := ar.AccountsTotals(ctx, false)
		if err0 != nil {
			return err0
		}

		au.roundTotals = []ledgercore.AccountTotals{totals}
		return nil
	})

	ledgerAccountsinitMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}

	au.accountsq, err = au.dbs.MakeAccountsOptimizedReader()
	if err != nil {
		return err
	}

	hdr, err := l.BlockHdr(lastBalancesRound)
	if err != nil {
		return err
	}

	au.versions = []protocol.ConsensusVersion{hdr.CurrentProtocol}
	au.deltas = nil
	au.accounts = make(map[basics.Address]modifiedAccount)
	au.resources = make(resourcesUpdates)
	au.kvStore = make(map[string]modifiedKvValue)
	au.creatables = make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	au.deltasAccum = []int{0}

	if !au.disableCache {
		au.baseAccounts.init(au.log, baseAccountsPendingAccountsBufferSize, baseAccountsPendingAccountsWarnThreshold)
		au.baseResources.init(au.log, baseResourcesPendingAccountsBufferSize, baseResourcesPendingAccountsWarnThreshold)
		au.baseKVs.init(au.log, baseKVPendingBufferSize, baseKVPendingWarnThreshold)
	} else {
		au.baseAccounts.init(au.log, 0, 1)
		au.baseResources.init(au.log, 0, 1)
		au.baseKVs.init(au.log, 0, 1)
	}
	return nil
}

// newBlockImpl is the accountUpdates implementation of the ledgerTracker interface. This is the "internal" facing function
// which assumes that no lock need to be taken.
func (au *accountUpdates) newBlockImpl(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	rnd := blk.Round()

	if rnd <= au.latest() {
		// Duplicate, ignore.
		return
	}

	if rnd != au.latest()+1 {
		au.log.Panicf("accountUpdates: newBlockImpl %d too far in the future, dbRound %d, deltas %d", rnd, au.cachedDBRound, len(au.deltas))
	}
	au.deltas = append(au.deltas, delta)
	au.versions = append(au.versions, blk.CurrentProtocol)
	au.deltasAccum = append(au.deltasAccum, delta.Accts.Len()+au.deltasAccum[len(au.deltasAccum)-1])

	au.baseAccounts.flushPendingWrites()
	au.baseResources.flushPendingWrites()
	au.baseKVs.flushPendingWrites()

	for i := 0; i < delta.Accts.Len(); i++ {
		addr, data := delta.Accts.GetByIdx(i)
		macct := au.accounts[addr]
		macct.ndeltas++
		macct.data = data
		au.accounts[addr] = macct
	}
	for _, res := range delta.Accts.GetAllAssetResources() {
		key := accountCreatable{
			address: res.Addr,
			index:   basics.CreatableIndex(res.Aidx),
		}
		mres, _ := au.resources.get(key)
		mres.resource.AssetHolding = res.Holding.Holding
		mres.resource.AssetParams = res.Params.Params
		mres.ndeltas++
		au.resources.set(key, mres)
	}
	for _, res := range delta.Accts.GetAllAppResources() {
		key := accountCreatable{
			address: res.Addr,
			index:   basics.CreatableIndex(res.Aidx),
		}
		mres, _ := au.resources.get(key)
		mres.resource.AppLocalState = res.State.LocalState
		mres.resource.AppParams = res.Params.Params
		mres.ndeltas++
		au.resources.set(key, mres)
	}

	for k, v := range delta.KvMods {
		mvalue := au.kvStore[k]
		mvalue.ndeltas++
		mvalue.data = v.Data
		// leave mvalue.oldData alone
		au.kvStore[k] = mvalue
	}

	for cidx, cdelta := range delta.Creatables {
		mcreat := au.creatables[cidx]
		mcreat.Creator = cdelta.Creator
		mcreat.Created = cdelta.Created
		mcreat.Ctype = cdelta.Ctype
		mcreat.Ndeltas++
		au.creatables[cidx] = mcreat
	}

	au.roundTotals = append(au.roundTotals, delta.Totals)

	// calling prune would drop old entries from the base accounts.
	newBaseAccountSize := (len(au.accounts) + 1) + baseAccountsPendingAccountsBufferSize
	au.baseAccounts.prune(newBaseAccountSize)
	newBaseResourcesSize := (len(au.resources) + 1) + baseResourcesPendingAccountsBufferSize
	au.baseResources.prune(newBaseResourcesSize)
	newBaseKVSize := (len(au.kvStore) + 1) + baseKVPendingBufferSize
	au.baseKVs.prune(newBaseKVSize)
}

// lookupLatest returns the account data for a given address for the latest round.
// The rewards are added to the AccountData before returning.
// Note that the function doesn't update the account with the rewards,
// even while it does return the AccountData which represent the "rewarded" account data.
func (au *accountUpdates) lookupLatest(addr basics.Address) (data basics.AccountData, rnd basics.Round, withoutRewards basics.MicroAlgos, err error) {
	au.accountsMu.RLock()
	needUnlock := true
	defer func() {
		if needUnlock {
			au.accountsMu.RUnlock()
		}
	}()
	var offset uint64
	var rewardsProto config.ConsensusParams
	var rewardsLevel uint64
	var persistedData trackerdb.PersistedAccountData
	var persistedResources []trackerdb.PersistedResourcesData
	var resourceDbRound basics.Round
	withRewards := true

	var foundAccount bool
	var ad ledgercore.AccountData

	var foundResources map[basics.CreatableIndex]basics.Round
	var resourceCount uint64

	addResource := func(cidx basics.CreatableIndex, round basics.Round, res ledgercore.AccountResource) error {
		foundRound, ok := foundResources[cidx]
		if !ok { // first time seeing this cidx
			foundResources[cidx] = round
			if ledgercore.AssignAccountResourceToAccountData(cidx, res, &data) {
				resourceCount++
			}
			return nil
		}
		// is this newer than current "found" rnd for this resource?
		if round > foundRound {
			return fmt.Errorf("error in lookupAllResources, round %v > foundRound %v: %w", round, foundRound, ErrLookupLatestResources)
		}
		// otherwise older than current "found" rnd: ignore, since it's older than what we have
		return nil
	}

	// possibly avoid a trip to the DB for more resources, if we can use totals info
	checkDone := func() bool {
		if foundAccount { // found AccountData
			// no resources
			if ad.TotalAssetParams == 0 && ad.TotalAppParams == 0 &&
				ad.TotalAssets == 0 && ad.TotalAppLocalStates == 0 {
				return true
			}
			// not possible to know how many resources rows to look for: totals conceal possibly overlapping assets/apps
			// but asset params also assume asset holding
			if (ad.TotalAssetParams != 0 && ad.TotalAssets != 0 && ad.TotalAssetParams != ad.TotalAssets) ||
				(ad.TotalAppParams != 0 && ad.TotalAppLocalStates != 0) {
				return false
			}

			// in cases where acct is only a holder of assets/apps, or is just a creator of assets/apps,
			// we can know how many resources rows to look for
			needToFind := uint64(0)
			if ad.TotalAssetParams == 0 { // not a creator of assets
				needToFind += uint64(ad.TotalAssets) // look for N asset holdings
			} else if ad.TotalAssets == 0 { // not a holder of assets
				needToFind += uint64(ad.TotalAssetParams) // look for N asset params
			} else if ad.TotalAssetParams == ad.TotalAssets {
				needToFind += uint64(ad.TotalAssetParams)
			} else {
				return false
			}
			if ad.TotalAppParams == 0 { // not a creator of apps
				needToFind += uint64(ad.TotalAppLocalStates) // look for N AppLocalStates
			} else if ad.TotalAppLocalStates == 0 { // not a user of apps
				needToFind += uint64(ad.TotalAppParams) // look for N AppParams
			} else {
				return false
			}
			return needToFind == resourceCount
		}
		return false
	}

	for {
		currentDbRound := au.cachedDBRound
		currentDeltaLen := len(au.deltas)
		rnd = au.latest()
		offset, err = au.roundOffset(rnd)
		if err != nil {
			return
		}
		// offset should now be len(au.deltas)
		if offset != uint64(len(au.deltas)) {
			return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, fmt.Errorf("offset != len(au.deltas): %w", ErrLookupLatestResources)
		}
		ad = ledgercore.AccountData{}
		foundAccount = false
		foundResources = make(map[basics.CreatableIndex]basics.Round)
		resourceCount = 0

		rewardsProto = config.Consensus[au.versions[offset]]
		rewardsLevel = au.roundTotals[offset].RewardsLevel

		// we're testing the withRewards here and setting the defer function only once, and only if withRewards is true.
		// we want to make this defer only after setting the above rewardsProto/rewardsLevel.
		if withRewards {
			defer func() {
				if err == nil {
					ledgercore.AssignAccountData(&data, ad)
					withoutRewards = data.MicroAlgos // record balance before updating rewards
					data = data.WithUpdatedRewards(rewardsProto, rewardsLevel)
				}
			}()
			withRewards = false
		}

		// check if we've had this address modified in the past rounds. ( i.e. if it's in the deltas )
		if macct, has := au.accounts[addr]; has {
			// This is the most recent round, so we can
			// use a cache of the most recent account state.
			ad = macct.data
			foundAccount = true
		} else if pad, inLRU := au.baseAccounts.read(addr); inLRU && pad.Round == currentDbRound {
			// we don't technically need this, since it's already in the baseAccounts, however, writing this over
			// would ensure that we promote this field.
			au.baseAccounts.writePending(pad)
			ad = pad.AccountData.GetLedgerCoreAccountData()
			foundAccount = true
		}

		if checkDone() {
			return
		}

		// check for resources modified in the past rounds, in the deltas
		for cidx, mr := range au.resources.getForAddress(addr) {
			if addErr := addResource(cidx, rnd, mr.resource); addErr != nil {
				return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, addErr
			}
		}

		if checkDone() {
			return
		}

		// check the baseResources -
		if prds := au.baseResources.readAll(addr); len(prds) > 0 {
			for _, prd := range prds {
				// we don't technically need this, since it's already in the baseResources, however, writing this over
				// would ensure that we promote this field.
				au.baseResources.writePending(prd, addr)
				if prd.AcctRef != nil {
					if addErr := addResource(prd.Aidx, rnd, prd.AccountResource()); addErr != nil {
						return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, addErr
					}
				}
			}
		}
		au.accountsMu.RUnlock()
		needUnlock = false

		if checkDone() {
			return
		}

		// No updates of this account in the in-memory deltas; use on-disk DB.
		// The check in roundOffset() made sure the round is exactly the one
		// present in the on-disk DB.  As an optimization, we avoid creating
		// a separate transaction here, and directly use a prepared SQL query
		// against the database.
		if !foundAccount {
			persistedData, err = au.accountsq.LookupAccount(addr)
			if err != nil {
				return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
			}
			if persistedData.Round == currentDbRound {
				if persistedData.Ref != nil {
					// if we read actual data return it
					au.baseAccounts.writePending(persistedData)
					ad = persistedData.AccountData.GetLedgerCoreAccountData()
				} else {
					ad = ledgercore.AccountData{}
				}

				foundAccount = true
				if checkDone() {
					return
				}
			}

			if persistedData.Round < currentDbRound {
				au.log.Errorf("accountUpdates.lookupLatest: account database round %d is behind in-memory round %d", persistedData.Round, currentDbRound)
				return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, &StaleDatabaseRoundError{databaseRound: persistedData.Round, memoryRound: currentDbRound}
			}
			if persistedData.Round > currentDbRound {
				goto tryAgain
			}
		}

		// Look for resources on disk
		persistedResources, resourceDbRound, err = au.accountsq.LookupAllResources(addr)
		if err != nil {
			return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
		}
		if resourceDbRound == currentDbRound {
			for _, pd := range persistedResources {
				au.baseResources.writePending(pd, addr)
				if addErr := addResource(pd.Aidx, currentDbRound, pd.AccountResource()); addErr != nil {
					return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, addErr
				}
			}
			// We've found all the resources we could find for this address.
			return
		}

		if resourceDbRound < currentDbRound {
			au.log.Errorf("accountUpdates.lookupLatest: resource database round %d is behind in-memory round %d", resourceDbRound, currentDbRound)
			return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, &StaleDatabaseRoundError{databaseRound: resourceDbRound, memoryRound: currentDbRound}
		}

	tryAgain:
		au.accountsMu.RLock()
		needUnlock = true
		for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
			au.accountsReadCond.Wait()
		}
	}
}

func (au *accountUpdates) lookupResource(rnd basics.Round, addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType, synchronized bool) (data ledgercore.AccountResource, validThrough basics.Round, err error) {
	needUnlock := false
	if synchronized {
		au.accountsMu.RLock()
		needUnlock = true
	}
	defer func() {
		if needUnlock {
			au.accountsMu.RUnlock()
		}
	}()
	var offset uint64
	var persistedData trackerdb.PersistedResourcesData
	for {
		currentDbRound := au.cachedDBRound
		currentDeltaLen := len(au.deltas)
		offset, err = au.roundOffset(rnd)
		if err != nil {
			return
		}

		// check if we've had this address modified in the past rounds. ( i.e. if it's in the deltas )
		macct, indeltas := au.resources.get(accountCreatable{address: addr, index: aidx})
		if indeltas {
			// Check if this is the most recent round, in which case, we can
			// use a cache of the most recent account state.
			if offset == uint64(len(au.deltas)) {
				return macct.resource, rnd, nil
			}
			// the account appears in the deltas, but we don't know if it appears in the
			// delta range of [0..offset-1], so we'll need to check. Walk deltas
			// backwards to ensure that later updates take priority if present.
			for offset > 0 {
				offset--
				r, ok := au.deltas[offset].Accts.GetResource(addr, aidx, ctype)
				if ok {
					// the returned validThrough here is not optimal, but it still correct. We could get a more accurate value by scanning
					// the deltas forward, but this would be time consuming loop, which might not pay off.
					return r, rnd, nil
				}
			}
		} else {
			// we know that the account in not in the deltas - so there is no point in scanning it.
			// we've going to fall back to search in the database, but before doing so, we should
			// update the rnd so that it would point to the end of the known delta range.
			// ( that would give us the best validity range )
			rnd = currentDbRound + basics.Round(currentDeltaLen)
		}

		// check the baseResources -
		if macct, has := au.baseResources.read(addr, aidx); has {
			// we don't technically need this, since it's already in the baseResources, however, writing this over
			// would ensure that we promote this field.
			au.baseResources.writePending(macct, addr)
			return macct.AccountResource(), rnd, nil
		}

		// check baseAccoiunts again to see if it does not exist
		if au.baseResources.readNotFound(addr, aidx) {
			// it seems the account doesnt exist
			return ledgercore.AccountResource{}, rnd, nil
		}

		if synchronized {
			au.accountsMu.RUnlock()
			needUnlock = false
		}
		// No updates of this account in the in-memory deltas; use on-disk DB.
		// The check in roundOffset() made sure the round is exactly the one
		// present in the on-disk DB.  As an optimization, we avoid creating
		// a separate transaction here, and directly use a prepared SQL query
		// against the database.
		persistedData, err = au.accountsq.LookupResources(addr, aidx, ctype)
		if err != nil {
			return ledgercore.AccountResource{}, basics.Round(0), err
		}
		if persistedData.Round == currentDbRound {
			if persistedData.AcctRef != nil {
				// if we read actual data return it
				au.baseResources.writePending(persistedData, addr)
				return persistedData.AccountResource(), rnd, nil
			}
			au.baseResources.writeNotFoundPending(addr, aidx)
			// otherwise return empty
			return ledgercore.AccountResource{}, rnd, nil
		}
		if synchronized {
			if persistedData.Round < currentDbRound {
				au.log.Errorf("accountUpdates.lookupResource: database round %d is behind in-memory round %d", persistedData.Round, currentDbRound)
				return ledgercore.AccountResource{}, basics.Round(0), &StaleDatabaseRoundError{databaseRound: persistedData.Round, memoryRound: currentDbRound}
			}
			au.accountsMu.RLock()
			needUnlock = true
			for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
				au.accountsReadCond.Wait()
			}
		} else {
			// in non-sync mode, we don't wait since we already assume that we're synchronized.
			au.log.Errorf("accountUpdates.lookupResource: database round %d mismatching in-memory round %d", persistedData.Round, currentDbRound)
			return ledgercore.AccountResource{}, basics.Round(0), &MismatchingDatabaseRoundError{databaseRound: persistedData.Round, memoryRound: currentDbRound}
		}
	}
}

// lookupAllResources returns all the resources for a given address, solely based on what is persisted to disk. It does not
// take into account any in-memory deltas; the round number returned is the latest round number that is known to the database.
func (au *accountUpdates) lookupAssetResources(addr basics.Address, assetIDGT basics.AssetIndex, limit uint64) (data []ledgercore.AssetResourceWithIDs, validThrough basics.Round, err error) {
	// Look for resources on disk
	persistedResources, resourceDbRound, err0 := au.accountsq.LookupLimitedResources(addr, basics.CreatableIndex(assetIDGT), limit, basics.AssetCreatable)
	if err0 != nil {
		return nil, basics.Round(0), err0
	}

	data = make([]ledgercore.AssetResourceWithIDs, 0, len(persistedResources))
	for _, pd := range persistedResources {
		ah := pd.Data.GetAssetHolding()

		var arwi ledgercore.AssetResourceWithIDs
		if !pd.Creator.IsZero() {
			ap := pd.Data.GetAssetParams()

			arwi = ledgercore.AssetResourceWithIDs{
				AssetID: basics.AssetIndex(pd.Aidx),
				Creator: pd.Creator,

				AssetResource: ledgercore.AssetResource{
					AssetHolding: &ah,
					AssetParams:  &ap,
				},
			}
		} else {
			arwi = ledgercore.AssetResourceWithIDs{
				AssetID: basics.AssetIndex(pd.Aidx),

				AssetResource: ledgercore.AssetResource{
					AssetHolding: &ah,
				},
			}
		}

		data = append(data, arwi)
	}
	// We've found all the resources we could find for this address.
	currentDbRound := resourceDbRound
	// The resourceDbRound will not be set if there are no persisted resources
	if len(data) == 0 {
		au.accountsMu.RLock()
		currentDbRound = au.cachedDBRound
		au.accountsMu.RUnlock()
	}
	return data, currentDbRound, nil
}

func (au *accountUpdates) lookupStateDelta(rnd basics.Round) (ledgercore.StateDelta, error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	var offset uint64
	var delta ledgercore.StateDelta
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return delta, err
	}
	if offset == 0 {
		err = fmt.Errorf("round %d not in deltas: dbRound %d, deltas %d, offset %d", rnd, au.cachedDBRound, len(au.deltas), offset)
		return delta, err
	}
	delta = au.deltas[offset-1]
	return delta, err
}

// lookupWithoutRewards returns the account data for a given address at a given round.
func (au *accountUpdates) lookupWithoutRewards(rnd basics.Round, addr basics.Address, synchronized bool) (data ledgercore.AccountData, validThrough basics.Round, rewardsVersion protocol.ConsensusVersion, rewardsLevel uint64, err error) {
	needUnlock := false
	if synchronized {
		au.accountsMu.RLock()
		needUnlock = true
	}
	defer func() {
		if needUnlock {
			au.accountsMu.RUnlock()
		}
	}()
	var offset uint64
	var persistedData trackerdb.PersistedAccountData
	for {
		currentDbRound := au.cachedDBRound
		currentDeltaLen := len(au.deltas)
		offset, err = au.roundOffset(rnd)
		if err != nil {
			return
		}

		rewardsVersion = au.versions[offset]
		rewardsLevel = au.roundTotals[offset].RewardsLevel

		// check if we've had this address modified in the past rounds. ( i.e. if it's in the deltas )
		macct, indeltas := au.accounts[addr]
		if indeltas {
			// Check if this is the most recent round, in which case, we can
			// use a cache of the most recent account state.
			if offset == uint64(len(au.deltas)) {
				return macct.data, rnd, rewardsVersion, rewardsLevel, nil
			}
			// the account appears in the deltas, but we don't know if it appears in the
			// delta range of [0..offset-1], so we'll need to check. Walk deltas
			// backwards to ensure that later updates take priority if present.
			for offset > 0 {
				offset--
				d, ok := au.deltas[offset].Accts.GetData(addr)
				if ok {
					// the returned validThrough here is not optimal, but it still correct. We could get a more accurate value by scanning
					// the deltas forward, but this would be time consuming loop, which might not pay off.
					return d, rnd, rewardsVersion, rewardsLevel, nil
				}
			}
		} else {
			// we know that the account in not in the deltas - so there is no point in scanning it.
			// we've going to fall back to search in the database, but before doing so, we should
			// update the rnd so that it would point to the end of the known delta range.
			// ( that would give us the best validity range )
			rnd = currentDbRound + basics.Round(currentDeltaLen)
		}

		// check the baseAccounts -
		if macct, has := au.baseAccounts.read(addr); has {
			// we don't technically need this, since it's already in the baseAccounts, however, writing this over
			// would ensure that we promote this field.
			au.baseAccounts.writePending(macct)
			return macct.AccountData.GetLedgerCoreAccountData(), rnd, rewardsVersion, rewardsLevel, nil
		}

		// check baseAccoiunts again to see if it does not exist
		if au.baseAccounts.readNotFound(addr) {
			// it seems the account doesnt exist
			return ledgercore.AccountData{}, rnd, rewardsVersion, rewardsLevel, nil
		}

		if synchronized {
			au.accountsMu.RUnlock()
			needUnlock = false
		}
		// No updates of this account in the in-memory deltas; use on-disk DB.
		// The check in roundOffset() made sure the round is exactly the one
		// present in the on-disk DB.  As an optimization, we avoid creating
		// a separate transaction here, and directly use a prepared SQL query
		// against the database.
		persistedData, err = au.accountsq.LookupAccount(addr)
		if err != nil {
			return ledgercore.AccountData{}, basics.Round(0), "", 0, err
		}
		if persistedData.Round == currentDbRound {
			if persistedData.Ref != nil {
				// if we read actual data return it
				au.baseAccounts.writePending(persistedData)
				return persistedData.AccountData.GetLedgerCoreAccountData(), rnd, rewardsVersion, rewardsLevel, nil
			}
			au.baseAccounts.writeNotFoundPending(addr)
			// otherwise return empty
			return ledgercore.AccountData{}, rnd, rewardsVersion, rewardsLevel, nil
		}
		if synchronized {
			if persistedData.Round < currentDbRound {
				au.log.Errorf("accountUpdates.lookupWithoutRewards: database round %d is behind in-memory round %d", persistedData.Round, currentDbRound)
				return ledgercore.AccountData{}, basics.Round(0), "", 0, &StaleDatabaseRoundError{databaseRound: persistedData.Round, memoryRound: currentDbRound}
			}
			au.accountsMu.RLock()
			needUnlock = true
			for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
				au.accountsReadCond.Wait()
			}
		} else {
			// in non-sync mode, we don't wait since we already assume that we're synchronized.
			au.log.Errorf("accountUpdates.lookupWithoutRewards: database round %d mismatching in-memory round %d", persistedData.Round, currentDbRound)
			return ledgercore.AccountData{}, basics.Round(0), "", 0, &MismatchingDatabaseRoundError{databaseRound: persistedData.Round, memoryRound: currentDbRound}
		}
	}
}

// getCreatorForRound returns the asset/app creator for a given asset/app index at a given round
func (au *accountUpdates) getCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType, synchronized bool) (basics.Address, bool, error) {
	unlock := false
	if synchronized {
		au.accountsMu.RLock()
		unlock = true
	}
	defer func() {
		if unlock {
			au.accountsMu.RUnlock()
		}
	}()
	var dbRound basics.Round
	var offset uint64
	for {
		currentDbRound := au.cachedDBRound
		currentDeltaLen := len(au.deltas)
		var err error
		offset, err = au.roundOffset(rnd)
		if err != nil {
			return basics.Address{}, false, err
		}

		// If this is the most recent round, au.creatables has the latest
		// state and we can skip scanning backwards over creatableDeltas
		if offset == uint64(len(au.deltas)) {
			// Check if we already have the asset/creator in cache
			creatableDelta, ok := au.creatables[cidx]
			if ok {
				if creatableDelta.Created && creatableDelta.Ctype == ctype {
					return creatableDelta.Creator, true, nil
				}
				return basics.Address{}, false, nil
			}
		} else {
			for offset > 0 {
				offset--
				creatableDelta, ok := au.deltas[offset].Creatables[cidx]
				if ok {
					if creatableDelta.Created && creatableDelta.Ctype == ctype {
						return creatableDelta.Creator, true, nil
					}
					return basics.Address{}, false, nil
				}
			}
		}

		if synchronized {
			au.accountsMu.RUnlock()
			unlock = false
		}
		// Check the database
		var ok bool
		var creator basics.Address
		creator, ok, dbRound, err = au.accountsq.LookupCreator(cidx, ctype)
		if err != nil {
			return basics.Address{}, false, err
		}
		if dbRound == currentDbRound {
			return creator, ok, nil
		}
		if synchronized {
			if dbRound < currentDbRound {
				au.log.Errorf("accountUpdates.getCreatorForRound: database round %d is behind in-memory round %d", dbRound, currentDbRound)
				return basics.Address{}, false, &StaleDatabaseRoundError{databaseRound: dbRound, memoryRound: currentDbRound}
			}
			au.accountsMu.RLock()
			unlock = true
			for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
				au.accountsReadCond.Wait()
			}
		} else {
			au.log.Errorf("accountUpdates.getCreatorForRound: database round %d mismatching in-memory round %d", dbRound, currentDbRound)
			return basics.Address{}, false, &MismatchingDatabaseRoundError{databaseRound: dbRound, memoryRound: currentDbRound}
		}
	}
}

// roundOffset calculates the offset of the given round compared to the current dbRound. Requires that the lock would be taken.
func (au *accountUpdates) roundOffset(rnd basics.Round) (offset uint64, err error) {
	if rnd < au.cachedDBRound {
		err = &RoundOffsetError{
			round:   rnd,
			dbRound: au.cachedDBRound,
		}
		return
	}

	off := uint64(rnd - au.cachedDBRound)
	if off > uint64(len(au.deltas)) {
		err = fmt.Errorf("round %d too high: dbRound %d, deltas %d", rnd, au.cachedDBRound, len(au.deltas))
		return
	}

	return off, nil
}

func (au *accountUpdates) handleUnorderedCommit(dcc *deferredCommitContext) {
}
func (au *accountUpdates) handlePrepareCommitError(dcc *deferredCommitContext) {
}
func (au *accountUpdates) handleCommitError(dcc *deferredCommitContext) {
}

// prepareCommit prepares data to write to the database a "chunk" of rounds, and update the cached dbRound accordingly.
func (au *accountUpdates) prepareCommit(dcc *deferredCommitContext) error {
	if au.logAccountUpdatesMetrics {
		now := time.Now()
		if now.Sub(au.lastMetricsLogTime) >= au.logAccountUpdatesInterval {
			dcc.updateStats = true
			au.lastMetricsLogTime = now
		}
	}

	offset := dcc.offset

	au.accountsMu.RLock()

	// create a copy of the round totals and protos for the range we're going to flush.
	dcc.roundTotals = au.roundTotals[offset]

	// verify version correctness : all the entries in the au.versions[1:offset+1] should have the *same* version, and the committedUpTo should be enforcing that.
	if au.versions[1] != au.versions[offset] {
		au.accountsMu.RUnlock()
		return fmt.Errorf("attempted to commit series of rounds with non-uniform consensus versions")
	}

	// once the consensus upgrade to resource separation is complete, all resources/accounts are also tagged with
	// their corresponding update round.
	setUpdateRound := config.Consensus[au.versions[1]].EnableAccountDataResourceSeparation

	// compact all the deltas - when we're trying to persist multiple rounds, we might have the same account
	// being updated multiple times. When that happen, we can safely omit the intermediate updates.
	dcc.compactAccountDeltas = makeCompactAccountDeltas(au.deltas[:offset], dcc.oldBase, setUpdateRound, au.baseAccounts)
	dcc.compactResourcesDeltas = makeCompactResourceDeltas(au.deltas[:offset], dcc.oldBase, setUpdateRound, au.baseAccounts, au.baseResources)
	dcc.compactKvDeltas = compactKvDeltas(au.deltas[:offset])
	dcc.compactCreatableDeltas = compactCreatableDeltas(au.deltas[:offset])

	au.accountsMu.RUnlock()

	dcc.genesisProto = au.ledger.GenesisProto()

	if dcc.updateStats {
		dcc.stats.DatabaseCommitDuration = time.Duration(time.Now().UnixNano())
	}

	return nil
}

// commitRound is called within the same transaction for all trackers it
// receives current offset and dbRound
func (au *accountUpdates) commitRound(ctx context.Context, tx trackerdb.TransactionScope, dcc *deferredCommitContext) (err error) {
	offset := dcc.offset
	dbRound := dcc.oldBase

	_, err = tx.ResetTransactionWarnDeadline(ctx, time.Now().Add(accountsUpdatePerRoundHighWatermark*time.Duration(offset)))
	if err != nil {
		return err
	}

	if dcc.updateStats {
		dcc.stats.OldAccountPreloadDuration = time.Duration(time.Now().UnixNano())
	}
	err = dcc.compactAccountDeltas.accountsLoadOld(tx)
	if err != nil {
		return err
	}

	knownAddresses := make(map[basics.Address]trackerdb.AccountRef, len(dcc.compactAccountDeltas.deltas))
	for _, delta := range dcc.compactAccountDeltas.deltas {
		knownAddresses[delta.oldAcct.Addr] = delta.oldAcct.Ref
	}

	err = dcc.compactResourcesDeltas.resourcesLoadOld(tx, knownAddresses)
	if err != nil {
		return err
	}

	if dcc.updateStats {
		dcc.stats.OldAccountPreloadDuration = time.Duration(time.Now().UnixNano()) - dcc.stats.OldAccountPreloadDuration
	}

	aw, err := tx.MakeAccountsWriter()
	if err != nil {
		return err
	}

	err = aw.AccountsPutTotals(dcc.roundTotals, false)
	if err != nil {
		return err
	}

	if dcc.updateStats {
		dcc.stats.AccountsWritingDuration = time.Duration(time.Now().UnixNano())
	}

	// the updates of the actual account data is done last since the accountsNewRound would modify the compactDeltas old values
	// so that we can update the base account back.
	dcc.updatedPersistedAccounts, dcc.updatedPersistedResources, dcc.updatedPersistedKVs, err = accountsNewRound(tx, dcc.compactAccountDeltas, dcc.compactResourcesDeltas, dcc.compactKvDeltas, dcc.compactCreatableDeltas, dcc.genesisProto, dbRound+basics.Round(offset))
	if err != nil {
		return err
	}

	if dcc.updateStats {
		dcc.stats.AccountsWritingDuration = time.Duration(time.Now().UnixNano()) - dcc.stats.AccountsWritingDuration
	}

	return
}

func (au *accountUpdates) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	if dcc.updateStats {
		spentDuration := dcc.stats.DatabaseCommitDuration + dcc.stats.AccountsWritingDuration + dcc.stats.MerkleTrieUpdateDuration + dcc.stats.OldAccountPreloadDuration
		dcc.stats.DatabaseCommitDuration = time.Duration(time.Now().UnixNano()) - spentDuration
	}

	offset := dcc.offset
	dbRound := dcc.oldBase
	newBase := dcc.newBase()

	dcc.updatingBalancesDuration = time.Since(dcc.flushTime)

	if dcc.updateStats {
		dcc.stats.MemoryUpdatesDuration = time.Duration(time.Now().UnixNano())
	}

	t0 := time.Now()
	ledgerAccountsMuLockCount.Inc(nil)
	au.accountsMu.Lock()
	// Drop reference counts to modified accounts, and evict them
	// from in-memory cache when no references remain.
	for i := 0; i < dcc.compactAccountDeltas.len(); i++ {
		acctUpdate := dcc.compactAccountDeltas.getByIdx(i)
		cnt := acctUpdate.nAcctDeltas
		macct, ok := au.accounts[acctUpdate.address]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to %s, but not in au.accounts", cnt, acctUpdate.address)
		}

		if cnt > macct.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to %s, but au.accounts had %d", cnt, acctUpdate.address, macct.ndeltas)
		} else if cnt == macct.ndeltas {
			delete(au.accounts, acctUpdate.address)
		} else {
			macct.ndeltas -= cnt
			au.accounts[acctUpdate.address] = macct
		}
	}

	for i := 0; i < dcc.compactResourcesDeltas.len(); i++ {
		resUpdate := dcc.compactResourcesDeltas.getByIdx(i)
		cnt := resUpdate.nAcctDeltas
		key := accountCreatable{resUpdate.address, resUpdate.oldResource.Aidx}
		macct, ok := au.resources[key]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to (%s, %d), but not in au.resources", cnt, resUpdate.address, resUpdate.oldResource.Aidx)
		}

		if cnt > macct.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to (%s, %d), but au.resources had %d", cnt, resUpdate.address, resUpdate.oldResource.Aidx, macct.ndeltas)
		} else if cnt == macct.ndeltas {
			delete(au.resources, key)
		} else {
			macct.ndeltas -= cnt
			au.resources[key] = macct
		}
	}

	for _, persistedAcct := range dcc.updatedPersistedAccounts {
		au.baseAccounts.write(persistedAcct)
	}

	for addr, deltas := range dcc.updatedPersistedResources {
		for _, persistedRes := range deltas {
			au.baseResources.write(persistedRes, addr)
		}
	}

	for key, out := range dcc.compactKvDeltas {
		cnt := out.ndeltas
		mval, ok := au.kvStore[key]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to key %s, but not in au.kvStore", cnt, key)
		}
		if cnt > mval.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to key %s, but au.kvStore had %d", cnt, key, mval.ndeltas)
		} else if cnt == mval.ndeltas {
			delete(au.kvStore, key)
		} else {
			mval.ndeltas -= cnt
			au.kvStore[key] = mval
		}
	}

	for key, persistedKV := range dcc.updatedPersistedKVs {
		au.baseKVs.write(persistedKV, key)
	}

	for cidx, modCrt := range dcc.compactCreatableDeltas {
		cnt := modCrt.Ndeltas
		mcreat, ok := au.creatables[cidx]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to creatable %d, but not in au.creatables", cnt, cidx)
		}

		if cnt > mcreat.Ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to creatable %d, but au.creatables had %d", cnt, cidx, mcreat.Ndeltas)
		} else if cnt == mcreat.Ndeltas {
			delete(au.creatables, cidx)
		} else {
			mcreat.Ndeltas -= cnt
			au.creatables[cidx] = mcreat
		}
	}

	// clear the backing array to let GC collect data.
	// this is catchpoint-related optimization if for whatever reason catchpoint generation
	// takes longer than 500 rounds.
	// the number chosen out of the following calculation:
	// 300 bytes per acct in delta * 50,000 accts (full block)  * 500 rounds = 7.5 GB
	const deltasClearThreshold = 500
	if offset > deltasClearThreshold {
		for i := uint64(0); i < offset; i++ {
			au.deltas[i] = ledgercore.StateDelta{}
		}
	}

	au.deltas = au.deltas[offset:]
	au.deltasAccum = au.deltasAccum[offset:]
	au.versions = au.versions[offset:]
	au.roundTotals = au.roundTotals[offset:]
	au.cachedDBRound = newBase

	au.accountsMu.Unlock()
	ledgerAccountsMuLockMicros.AddMicrosecondsSince(t0, nil)

	if dcc.updateStats {
		dcc.stats.MemoryUpdatesDuration = time.Duration(time.Now().UnixNano()) - dcc.stats.MemoryUpdatesDuration
	}

	au.accountsReadCond.Broadcast()

	// log telemetry event
	if dcc.updateStats {
		dcc.stats.StartRound = uint64(dbRound)
		dcc.stats.RoundsCount = offset
		dcc.stats.UpdatedAccountsCount = uint64(len(dcc.updatedPersistedAccounts))
		dcc.stats.UpdatedCreatablesCount = uint64(len(dcc.compactCreatableDeltas))

		dcc.stats.UpdatedResourcesCount = 0
		for _, resData := range dcc.updatedPersistedResources {
			dcc.stats.UpdatedResourcesCount += uint64(len(resData))
		}

		var details struct{}
		au.log.Metrics(telemetryspec.Accounts, dcc.stats, details)
	}
}

func (au *accountUpdates) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
}

// compactKvDeltas takes an array of StateDeltas containing kv deltas (one array entry per round), and
// compacts the array into a single map that contains all the
// changes. Intermediate changes are eliminated.  It counts the number of
// changes per round by specifying it in the ndeltas field of the
// modifiedKv. The modifiedValues in the returned map have the earliest
// mv.oldData, and the newest mv.data.
func compactKvDeltas(stateDeltas []ledgercore.StateDelta) map[string]modifiedKvValue {
	if len(stateDeltas) == 0 {
		return nil
	}
	outKvDeltas := make(map[string]modifiedKvValue)
	for _, stateDelta := range stateDeltas {
		roundKv := stateDelta.KvMods
		for key, current := range roundKv {
			prev, ok := outKvDeltas[key]
			if !ok { // Record only the first OldData
				prev.oldData = current.OldData
			}
			prev.data = current.Data // Replace with newest Data
			prev.ndeltas++
			outKvDeltas[key] = prev
		}
	}
	return outKvDeltas
}

// compactCreatableDeltas takes an array of StateDeltas containing creatables map deltas ( one array entry per round ),
// and compacts the array into a single map that of createable deltas which contains all the deltas changes.
// While doing that, the function eliminate any intermediate changes.
// It counts the number of changes per round by specifying it in the ndeltas field of the modifiedCreatable.
func compactCreatableDeltas(stateDeltas []ledgercore.StateDelta) (outCreatableDeltas map[basics.CreatableIndex]ledgercore.ModifiedCreatable) {
	if len(stateDeltas) == 0 {
		return
	}
	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	outCreatableDeltas = make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable, 1+len(stateDeltas[0].KvMods)*len(stateDeltas))
	for _, stateDelta := range stateDeltas {
		roundCreatable := stateDelta.Creatables
		for creatableIdx, creatable := range roundCreatable {
			if prev, has := outCreatableDeltas[creatableIdx]; has {
				outCreatableDeltas[creatableIdx] = ledgercore.ModifiedCreatable{
					Ctype:   creatable.Ctype,
					Created: creatable.Created,
					Creator: creatable.Creator,
					Ndeltas: prev.Ndeltas + 1,
				}
			} else {
				outCreatableDeltas[creatableIdx] = ledgercore.ModifiedCreatable{
					Ctype:   creatable.Ctype,
					Created: creatable.Created,
					Creator: creatable.Creator,
					Ndeltas: 1,
				}
			}
		}
	}
	return
}

// latest returns the latest round
func (au *accountUpdates) latest() basics.Round {
	return au.cachedDBRound + basics.Round(len(au.deltas))
}

// the vacuumDatabase performs a full vacuum of the accounts database.
func (au *accountUpdates) vacuumDatabase(ctx context.Context) (err error) {
	// vaccumming the database would modify the some of the tables rowid, so we need to make sure any stored in-memory
	// rowid are flushed.
	au.baseAccounts.prune(0)
	au.baseResources.prune(0)
	au.baseKVs.prune(0)

	startTime := time.Now()
	vacuumExitCh := make(chan struct{}, 1)
	vacuumLoggingAbort := sync.WaitGroup{}
	vacuumLoggingAbort.Add(1)
	// vacuuming the database can take a while. A long while. We want to have a logging function running in a separate go-routine that would log the progress to the log file.
	// also, when we're done vacuuming, we should sent an event notifying of the total time it took to vacuum the database.
	go func() {
		defer vacuumLoggingAbort.Done()
		au.log.Infof("Vacuuming accounts database started")
		for {
			select {
			case <-time.After(5 * time.Second):
				au.log.Infof("Vacuuming accounts database in progress")
			case <-vacuumExitCh:
				return
			}
		}
	}()

	ledgerVacuumCount.Inc(nil)
	vacuumStats, err := au.dbs.Vacuum(ctx)
	close(vacuumExitCh)
	vacuumLoggingAbort.Wait()

	if err != nil {
		au.log.Warnf("Vacuuming account database failed : %v", err)
		return err
	}
	vacuumElapsedTime := time.Since(startTime)
	ledgerVacuumMicros.AddUint64(uint64(vacuumElapsedTime.Microseconds()), nil)

	au.log.Infof("Vacuuming accounts database completed within %v, reducing number of pages from %d to %d and size from %d to %d", vacuumElapsedTime, vacuumStats.PagesBefore, vacuumStats.PagesAfter, vacuumStats.SizeBefore, vacuumStats.SizeAfter)

	vacuumTelemetryStats := telemetryspec.BalancesAccountVacuumEventDetails{
		VacuumTimeNanoseconds:  vacuumElapsedTime.Nanoseconds(),
		BeforeVacuumPageCount:  vacuumStats.PagesBefore,
		AfterVacuumPageCount:   vacuumStats.PagesAfter,
		BeforeVacuumSpaceBytes: vacuumStats.SizeBefore,
		AfterVacuumSpaceBytes:  vacuumStats.SizeAfter,
	}

	au.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.BalancesAccountVacuumEvent, vacuumTelemetryStats)
	return
}

var ledgerGetcatchpointCount = metrics.NewCounter("ledger_getcatchpoint_count", "calls")
var ledgerGetcatchpointMicros = metrics.NewCounter("ledger_getcatchpoint_micros", "µs spent")
var ledgerAccountsinitCount = metrics.NewCounter("ledger_accountsinit_count", "calls")
var ledgerAccountsinitMicros = metrics.NewCounter("ledger_accountsinit_micros", "µs spent")
var ledgerCommitroundCount = metrics.NewCounter("ledger_commitround_count", "calls")
var ledgerCommitroundMicros = metrics.NewCounter("ledger_commitround_micros", "µs spent")
var ledgerGeneratecatchpointCount = metrics.NewCounter("ledger_generatecatchpoint_count", "calls")
var ledgerGeneratecatchpointMicros = metrics.NewCounter("ledger_generatecatchpoint_micros", "µs spent")
var ledgerVacuumCount = metrics.NewCounter("ledger_vacuum_count", "calls")
var ledgerVacuumMicros = metrics.NewCounter("ledger_vacuum_micros", "µs spent")
var ledgerAccountsMuLockCount = metrics.NewCounter("ledger_lock_accountsmu_count", "calls")
var ledgerAccountsMuLockMicros = metrics.NewCounter("ledger_lock_accountsmu_micros", "µs spent")
