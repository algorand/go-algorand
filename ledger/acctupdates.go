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
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
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
const baseResourcesPendingAccountsBufferSize = 100000

// baseResourcesPendingAccountsWarnThreshold defines the threshold at which the lruResources would generate a warning
// after we've surpassed a given pending account resources size. The warning is being generated when the pending accounts data
// is being flushed into the main base resources cache.
const baseResourcesPendingAccountsWarnThreshold = 85000

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

// forceCatchpointFileGeneration defines the CatchpointTracking mode that would be used to
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

// A modifiedValue represents the value that has been modified since the
// persistent state stored in the account DB (i.e., in the range of rounds
// covered by the accountUpdates tracker).
type modifiedValue struct {
	// data stores the most recent value (nil == deleted)
	data *string

	// ndelta keeps track of how many times the key for this value appears in
	// accountUpdates.deltas.  This is used to evict modifiedValue entries when
	// all changes to a key have been reflected in the kv table, and no
	// outstanding modifications remain.
	ndeltas int
}

type accountUpdates struct {
	// Connection to the database.
	dbs db.Pair

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq *accountsDbQueries

	// cachedDBRound is always exactly tracker DB round (and therefore, accountsRound()),
	// cached to use in lookup functions
	cachedDBRound basics.Round

	// deltas stores updates for every round after dbRound.
	deltas []ledgercore.AccountDeltas

	// accounts stores the most recent account state for every
	// address that appears in deltas.
	accounts map[basics.Address]modifiedAccount

	// resources stored the most recent resource state for every
	// address&resource that appears in deltas.
	resources resourcesUpdates

	// kvDeltas stores kvPair updates for every round after dbRound.
	kvDeltas []map[string]*string

	// kvStore has the most recent kv pairs for every write/del that appears in
	// deltas.
	kvStore map[string]modifiedValue

	// creatableDeltas stores creatable updates for every round after dbRound.
	creatableDeltas []map[basics.CreatableIndex]ledgercore.ModifiedCreatable

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
		au.accountsq.close()
		au.accountsq = nil
	}
	au.baseAccounts.prune(0)
	au.baseResources.prune(0)
	au.baseKVs.prune(0)
}

func (au *accountUpdates) LookupResource(rnd basics.Round, addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ledgercore.AccountResource, basics.Round, error) {
	return au.lookupResource(rnd, addr, aidx, ctype, true /* take lock */)
}

func (au *accountUpdates) LookupKv(rnd basics.Round, key string) (*string, error) {
	return au.lookupKv(rnd, key, true /* take lock */)
}

func (au *accountUpdates) lookupKv(rnd basics.Round, key string, synchronized bool) (*string, error) {
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
			if offset == uint64(len(au.kvDeltas)) {
				return mval.data, nil
			}

			// the key is in the deltas, but we don't know if it appears in the
			// delta range of [0..offset], so we'll need to check. Walk deltas
			// backwards so later updates take priority.
			for i := offset - 1; i > 0; i-- {
				mval, ok := au.kvDeltas[i][key]
				if ok {
					return mval, nil
				}
			}
		} else {
			// we know that the key in not in kvDeltas - so there is no point in scanning it.
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
			return pbd.value, nil
		}

		if synchronized {
			au.accountsMu.RUnlock()
			needUnlock = false
		}

		// No updates of this account in kvDeltas; use on-disk DB.  The check in
		// roundOffset() made sure the round is exactly the one present in the
		// on-disk DB.

		persistedData, err := au.accountsq.lookupKeyValue(key)
		if err != nil {
			return nil, err
		}

		if persistedData.round == currentDbRound {
			// if we read actual data return it. This includes deleted values
			// where persistedData.value == nil to avoid unnecessary db lookups
			// for deleted KVs.
			au.baseKVs.writePending(persistedData, key)
			return persistedData.value, nil
		}

		// The db round is unexpected...
		if synchronized {
			if persistedData.round < currentDbRound {
				// Somehow the db is LOWER than it should be.
				au.log.Errorf("accountUpdates.lookupKvPair: database round %d is behind in-memory round %d", persistedData.round, currentDbRound)
				return nil, &StaleDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
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
			au.log.Errorf("accountUpdates.lookupKvPair: database round %d mismatching in-memory round %d", persistedData.round, currentDbRound)
			return nil, &MismatchingDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
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
		offset, _err := au.roundOffset(round)
		if _err != nil {
			err = _err
			return
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

		for i := int(offset - 1); i >= 0; i-- {
			for keyInRound, valOp := range au.kvDeltas[i] {
				if !strings.HasPrefix(keyInRound, keyPrefix) {
					continue
				}
				// whether it is set or deleted in later round, if such modification exists in later round
				// we just ignore the earlier insert
				if _, ok := results[keyInRound]; ok {
					continue
				}
				if valOp == nil {
					results[keyInRound] = false
				} else {
					// set such key to be valid with value
					results[keyInRound] = true
					resultCount++
					// check if the size of `results` reaches `maxKeyNum`
					// if so just return the list of keys
					if maxKeyNum > 0 && resultCount == maxKeyNum {
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
		dbRound, _err := au.accountsq.lookupKeysByPrefix(keyPrefix, maxKeyNum, results, resultCount)
		if _err != nil {
			err = _err
			return
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

// ListAssets lists the assets by their asset index, limiting to the first maxResults
func (au *accountUpdates) ListAssets(maxAssetIdx basics.AssetIndex, maxResults uint64) ([]basics.CreatableLocator, error) {
	return au.listCreatables(basics.CreatableIndex(maxAssetIdx), maxResults, basics.AssetCreatable)
}

// ListApplications lists the application by their app index, limiting to the first maxResults
func (au *accountUpdates) ListApplications(maxAppIdx basics.AppIndex, maxResults uint64) ([]basics.CreatableLocator, error) {
	return au.listCreatables(basics.CreatableIndex(maxAppIdx), maxResults, basics.AppCreatable)
}

// listCreatables lists the application/asset by their app/asset index, limiting to the first maxResults
func (au *accountUpdates) listCreatables(maxCreatableIdx basics.CreatableIndex, maxResults uint64, ctype basics.CreatableType) ([]basics.CreatableLocator, error) {
	au.accountsMu.RLock()
	for {
		currentDbRound := au.cachedDBRound
		currentDeltaLen := len(au.deltas)
		// Sort indices for creatables that have been created/deleted. If this
		// turns out to be too inefficient, we could keep around a heap of
		// created/deleted asset indices in memory.
		keys := make([]basics.CreatableIndex, 0, len(au.creatables))
		for cidx, delta := range au.creatables {
			if delta.Ctype != ctype {
				continue
			}
			if cidx <= maxCreatableIdx {
				keys = append(keys, cidx)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })

		// Check for creatables that haven't been synced to disk yet.
		unsyncedCreatables := make([]basics.CreatableLocator, 0, len(keys))
		deletedCreatables := make(map[basics.CreatableIndex]bool, len(keys))
		for _, cidx := range keys {
			delta := au.creatables[cidx]
			if delta.Created {
				// Created but only exists in memory
				unsyncedCreatables = append(unsyncedCreatables, basics.CreatableLocator{
					Type:    delta.Ctype,
					Index:   cidx,
					Creator: delta.Creator,
				})
			} else {
				// Mark deleted creatables for exclusion from the results set
				deletedCreatables[cidx] = true
			}
		}

		au.accountsMu.RUnlock()

		// Check in-memory created creatables, which will always be newer than anything
		// in the database
		if uint64(len(unsyncedCreatables)) >= maxResults {
			return unsyncedCreatables[:maxResults], nil
		}
		res := unsyncedCreatables

		// Fetch up to maxResults - len(res) + len(deletedCreatables) from the database,
		// so we have enough extras in case creatables were deleted
		numToFetch := maxResults - uint64(len(res)) + uint64(len(deletedCreatables))
		dbResults, dbRound, err := au.accountsq.listCreatables(maxCreatableIdx, numToFetch, ctype)
		if err != nil {
			return nil, err
		}

		if dbRound == currentDbRound {
			// Now we merge the database results with the in-memory results
			for _, loc := range dbResults {
				// Check if we have enough results
				if uint64(len(res)) == maxResults {
					return res, nil
				}

				// Creatable was deleted
				if _, ok := deletedCreatables[loc.Index]; ok {
					continue
				}

				// We're OK to include this result
				res = append(res, loc)
			}
			return res, nil
		}
		if dbRound < currentDbRound {
			au.log.Errorf("listCreatables: database round %d is behind in-memory round %d", dbRound, currentDbRound)
			return []basics.CreatableLocator{}, &StaleDatabaseRoundError{databaseRound: dbRound, memoryRound: currentDbRound}
		}
		au.accountsMu.RLock()
		for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
			au.accountsReadCond.Wait()
		}
	}
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
	au.accountsMu.Lock()
	au.newBlockImpl(blk, delta)
	au.accountsMu.Unlock()
	au.accountsReadCond.Broadcast()
}

// LatestTotals returns the totals of all accounts for the most recent round, as well as the round number
func (au *accountUpdates) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	return au.latestTotalsImpl()
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

// accountUpdatesLedgerEvaluator is a "ledger emulator" which is used *only* by initializeCaches, as a way to shortcut
// the locks taken by the real ledger object when making requests that are being served by the accountUpdates.
// Using this struct allow us to take the tracker lock *before* calling the loadFromDisk, and having the operation complete
// without taking any locks. Note that it's not only the locks performance that is gained : by having the loadFrom disk
// not requiring any external locks, we can safely take a trackers lock on the ledger during reloadLedger, which ensures
// that even during catchpoint catchup mode switch, we're still correctly protected by a mutex.
type accountUpdatesLedgerEvaluator struct {
	// au is the associated accountUpdates structure which invoking the trackerEvalVerified function, passing this structure as input.
	// the accountUpdatesLedgerEvaluator would access the underlying accountUpdates function directly, bypassing the balances mutex lock.
	au *accountUpdates
	// ao is onlineAccounts for voters access
	ao *onlineAccounts
	// txtail allows implementation of BlockHdrCached
	tail *txTail
	// prevHeader is the previous header to the current one. The usage of this is only in the context of initializeCaches where we iteratively
	// building the ledgercore.StateDelta, which requires a peek on the "previous" header information.
	prevHeader bookkeeping.BlockHeader
}

// GenesisHash returns the genesis hash
func (aul *accountUpdatesLedgerEvaluator) GenesisHash() crypto.Digest {
	return aul.au.ledger.GenesisHash()
}

// GenesisProto returns the genesis consensus params
func (aul *accountUpdatesLedgerEvaluator) GenesisProto() config.ConsensusParams {
	return aul.au.ledger.GenesisProto()
}

// VotersForStateProof returns the top online accounts at round rnd.
func (aul *accountUpdatesLedgerEvaluator) VotersForStateProof(rnd basics.Round) (voters *ledgercore.VotersForRound, err error) {
	return aul.ao.voters.getVoters(rnd)
}

// BlockHdr returns the header of the given round. When the evaluator is running, it's only referring to the previous header, which is what we
// are providing here. Any attempt to access a different header would get denied.
func (aul *accountUpdatesLedgerEvaluator) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	if r == aul.prevHeader.Round {
		return aul.prevHeader, nil
	}
	return bookkeeping.BlockHeader{}, ledgercore.ErrNoEntry{}
}

// BlockHdrCached returns the header of the given round. We use the txTail
// tracker directly to avoid the tracker registry lock.
func (aul *accountUpdatesLedgerEvaluator) BlockHdrCached(r basics.Round) (bookkeeping.BlockHeader, error) {
	hdr, ok := aul.tail.blockHeader(r)
	if !ok {
		return bookkeeping.BlockHeader{}, fmt.Errorf("no cached header data for round %d", r)
	}
	return hdr, nil
}

// LatestTotals returns the totals of all accounts for the most recent round, as well as the round number
func (aul *accountUpdatesLedgerEvaluator) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return aul.au.latestTotalsImpl()
}

// CheckDup test to see if the given transaction id/lease already exists. It's not needed by the accountUpdatesLedgerEvaluator and implemented as a stub.
func (aul *accountUpdatesLedgerEvaluator) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	// this is a non-issue since this call will never be made on non-validating evaluation
	return fmt.Errorf("accountUpdatesLedgerEvaluator: tried to check for dup during accountUpdates initialization ")
}

// LookupWithoutRewards returns the account balance for a given address at a given round, without the reward
func (aul *accountUpdatesLedgerEvaluator) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	data, validThrough, _, _, err := aul.au.lookupWithoutRewards(rnd, addr, false /*don't sync*/)
	if err != nil {
		return ledgercore.AccountData{}, 0, err
	}

	return data, validThrough, err
}

func (aul *accountUpdatesLedgerEvaluator) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	r, _, err := aul.au.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AppCreatable, false /* don't sync */)
	return ledgercore.AppResource{AppParams: r.AppParams, AppLocalState: r.AppLocalState}, err
}

func (aul *accountUpdatesLedgerEvaluator) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	r, _, err := aul.au.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AssetCreatable, false /* don't sync */)
	return ledgercore.AssetResource{AssetParams: r.AssetParams, AssetHolding: r.AssetHolding}, err
}

func (aul *accountUpdatesLedgerEvaluator) LookupKv(rnd basics.Round, key string) (*string, error) {
	return aul.au.lookupKv(rnd, key, false /* don't sync */)
}

// GetCreatorForRound returns the asset/app creator for a given asset/app index at a given round
func (aul *accountUpdatesLedgerEvaluator) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	return aul.au.getCreatorForRound(rnd, cidx, ctype, false /* don't sync */)
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

// latestTotalsImpl returns the totals of all accounts for the most recent round, as well as the round number
func (au *accountUpdates) latestTotalsImpl() (basics.Round, ledgercore.AccountTotals, error) {
	offset := len(au.deltas)
	rnd := au.cachedDBRound + basics.Round(len(au.deltas))
	return rnd, au.roundTotals[offset], nil
}

// initializeFromDisk performs the atomic operation of loading the accounts data information from disk
// and preparing the accountUpdates for operation.
func (au *accountUpdates) initializeFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) (err error) {
	au.dbs = l.trackerDB()
	au.log = l.trackerLog()
	au.ledger = l

	start := time.Now()
	ledgerAccountsinitCount.Inc(nil)
	err = au.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		totals, err0 := accountsTotals(ctx, tx, false)
		if err0 != nil {
			return err0
		}

		au.roundTotals = []ledgercore.AccountTotals{totals}
		return nil
	})

	ledgerAccountsinitMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return
	}

	au.accountsq, err = accountsInitDbQueries(au.dbs.Rdb.Handle)
	if err != nil {
		return
	}

	hdr, err := l.BlockHdr(lastBalancesRound)
	if err != nil {
		return
	}

	au.versions = []protocol.ConsensusVersion{hdr.CurrentProtocol}
	au.deltas = nil
	au.kvDeltas = nil
	au.creatableDeltas = nil
	au.accounts = make(map[basics.Address]modifiedAccount)
	au.resources = make(resourcesUpdates)
	au.kvStore = make(map[string]modifiedValue)
	au.creatables = make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	au.deltasAccum = []int{0}

	au.baseAccounts.init(au.log, baseAccountsPendingAccountsBufferSize, baseAccountsPendingAccountsWarnThreshold)
	au.baseResources.init(au.log, baseResourcesPendingAccountsBufferSize, baseResourcesPendingAccountsWarnThreshold)
	au.baseKVs.init(au.log, baseKVPendingBufferSize, baseKVPendingWarnThreshold)
	return
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
	au.deltas = append(au.deltas, delta.Accts)
	au.versions = append(au.versions, blk.CurrentProtocol)
	au.creatableDeltas = append(au.creatableDeltas, delta.Creatables)
	au.kvDeltas = append(au.kvDeltas, delta.KvMods)
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
		mvalue.data = v
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
	var persistedData persistedAccountData
	var persistedResources []persistedResourcesData
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
		} else if pad, has := au.baseAccounts.read(addr); has && pad.round == currentDbRound {
			// we don't technically need this, since it's already in the baseAccounts, however, writing this over
			// would ensure that we promote this field.
			au.baseAccounts.writePending(pad)
			ad = pad.accountData.GetLedgerCoreAccountData()
			foundAccount = true
		}

		if checkDone() {
			return
		}

		// check for resources modified in the past rounds, in the deltas
		for cidx, mr := range au.resources.getForAddress(addr) {
			if err := addResource(cidx, rnd, mr.resource); err != nil {
				return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
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
				if prd.addrid != 0 {
					if err := addResource(prd.aidx, rnd, prd.AccountResource()); err != nil {
						return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
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
			persistedData, err = au.accountsq.lookup(addr)
			if err != nil {
				return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
			}
			if persistedData.round == currentDbRound {
				if persistedData.rowid != 0 {
					// if we read actual data return it
					au.baseAccounts.writePending(persistedData)
					ad = persistedData.accountData.GetLedgerCoreAccountData()
				} else {
					ad = ledgercore.AccountData{}
				}

				foundAccount = true
				if checkDone() {
					return
				}
			}

			if persistedData.round < currentDbRound {
				au.log.Errorf("accountUpdates.lookupLatest: account database round %d is behind in-memory round %d", persistedData.round, currentDbRound)
				return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, &StaleDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
			}
			if persistedData.round > currentDbRound {
				goto tryAgain
			}
		}

		// Look for resources on disk
		persistedResources, resourceDbRound, err = au.accountsq.lookupAllResources(addr)
		if err != nil {
			return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
		}
		if resourceDbRound == currentDbRound {
			for _, pd := range persistedResources {
				au.baseResources.writePending(pd, addr)
				if err := addResource(pd.aidx, currentDbRound, pd.AccountResource()); err != nil {
					return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
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
	var persistedData persistedResourcesData
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
			// delta range of [0..offset], so we'll need to check :
			// Traverse the deltas backwards to ensure that later updates take
			// priority if present.
			for offset > 0 {
				offset--
				r, ok := au.deltas[offset].GetResource(addr, aidx, ctype)
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

		if synchronized {
			au.accountsMu.RUnlock()
			needUnlock = false
		}
		// No updates of this account in the in-memory deltas; use on-disk DB.
		// The check in roundOffset() made sure the round is exactly the one
		// present in the on-disk DB.  As an optimization, we avoid creating
		// a separate transaction here, and directly use a prepared SQL query
		// against the database.
		persistedData, err = au.accountsq.lookupResources(addr, aidx, ctype)
		if persistedData.round == currentDbRound {
			if persistedData.addrid != 0 {
				// if we read actual data return it
				au.baseResources.writePending(persistedData, addr)
				return persistedData.AccountResource(), rnd, err
			}
			// otherwise return empty
			return ledgercore.AccountResource{}, rnd, err
		}
		if synchronized {
			if persistedData.round < currentDbRound {
				au.log.Errorf("accountUpdates.lookupResource: database round %d is behind in-memory round %d", persistedData.round, currentDbRound)
				return ledgercore.AccountResource{}, basics.Round(0), &StaleDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
			}
			au.accountsMu.RLock()
			needUnlock = true
			for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
				au.accountsReadCond.Wait()
			}
		} else {
			// in non-sync mode, we don't wait since we already assume that we're synchronized.
			au.log.Errorf("accountUpdates.lookupResource: database round %d mismatching in-memory round %d", persistedData.round, currentDbRound)
			return ledgercore.AccountResource{}, basics.Round(0), &MismatchingDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
		}
	}
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
	var persistedData persistedAccountData
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
			// delta range of [0..offset], so we'll need to check :
			// Traverse the deltas backwards to ensure that later updates take
			// priority if present.
			for offset > 0 {
				offset--
				d, ok := au.deltas[offset].GetData(addr)
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
			return macct.accountData.GetLedgerCoreAccountData(), rnd, rewardsVersion, rewardsLevel, nil
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
		persistedData, err = au.accountsq.lookup(addr)
		if persistedData.round == currentDbRound {
			if persistedData.rowid != 0 {
				// if we read actual data return it
				au.baseAccounts.writePending(persistedData)
				return persistedData.accountData.GetLedgerCoreAccountData(), rnd, rewardsVersion, rewardsLevel, err
			}
			// otherwise return empty
			return ledgercore.AccountData{}, rnd, rewardsVersion, rewardsLevel, err
		}
		if synchronized {
			if persistedData.round < currentDbRound {
				au.log.Errorf("accountUpdates.lookupWithoutRewards: database round %d is behind in-memory round %d", persistedData.round, currentDbRound)
				return ledgercore.AccountData{}, basics.Round(0), rewardsVersion, rewardsLevel, &StaleDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
			}
			au.accountsMu.RLock()
			needUnlock = true
			for currentDbRound >= au.cachedDBRound && currentDeltaLen == len(au.deltas) {
				au.accountsReadCond.Wait()
			}
		} else {
			// in non-sync mode, we don't wait since we already assume that we're synchronized.
			au.log.Errorf("accountUpdates.lookupWithoutRewards: database round %d mismatching in-memory round %d", persistedData.round, currentDbRound)
			return ledgercore.AccountData{}, basics.Round(0), rewardsVersion, rewardsLevel, &MismatchingDatabaseRoundError{databaseRound: persistedData.round, memoryRound: currentDbRound}
		}
	}
}

// getCreatorForRound returns the asset/app creator for a given asset/app index at a given round
func (au *accountUpdates) getCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType, synchronized bool) (creator basics.Address, ok bool, err error) {
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
				creatableDelta, ok := au.creatableDeltas[offset][cidx]
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
		creator, ok, dbRound, err = au.accountsq.lookupCreator(cidx, ctype)

		if dbRound == currentDbRound {
			return
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

		// in scheduleCommit, we expect that this function to update the catchpointWriting when
		// it's on a catchpoint round and the node is configured to generate catchpoints. Doing this in a deferred function
		// here would prevent us from "forgetting" to update this variable later on.
		// The same is repeated in commitRound on errors.
		if dcc.catchpointFirstStage && dcc.enableGeneratingCatchpointFiles {
			atomic.StoreInt32(dcc.catchpointDataWriting, 0)
		}
		return fmt.Errorf("attempted to commit series of rounds with non-uniform consensus versions")
	}

	// once the consensus upgrade to resource separation is complete, all resources/accounts are also tagged with
	// their corresponding update round.
	setUpdateRound := config.Consensus[au.versions[1]].EnableAccountDataResourceSeparation

	// compact all the deltas - when we're trying to persist multiple rounds, we might have the same account
	// being updated multiple times. When that happen, we can safely omit the intermediate updates.
	dcc.compactAccountDeltas = makeCompactAccountDeltas(au.deltas[:offset], dcc.oldBase, setUpdateRound, au.baseAccounts)
	dcc.compactResourcesDeltas = makeCompactResourceDeltas(au.deltas[:offset], dcc.oldBase, setUpdateRound, au.baseAccounts, au.baseResources)
	dcc.compactKvDeltas = compactKvDeltas(au.kvDeltas[:offset])
	dcc.compactCreatableDeltas = compactCreatableDeltas(au.creatableDeltas[:offset])

	au.accountsMu.RUnlock()

	dcc.genesisProto = au.ledger.GenesisProto()

	if dcc.updateStats {
		dcc.stats.DatabaseCommitDuration = time.Duration(time.Now().UnixNano())
	}

	return nil
}

// commitRound is called within the same transaction for all trackers it
// receives current offset and dbRound
func (au *accountUpdates) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	offset := dcc.offset
	dbRound := dcc.oldBase

	defer func() {
		if err != nil {
			if dcc.catchpointFirstStage && dcc.enableGeneratingCatchpointFiles {
				atomic.StoreInt32(dcc.catchpointDataWriting, 0)
			}
		}
	}()

	_, err = db.ResetTransactionWarnDeadline(ctx, tx, time.Now().Add(accountsUpdatePerRoundHighWatermark*time.Duration(offset)))
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

	knownAddresses := make(map[basics.Address]int64, len(dcc.compactAccountDeltas.deltas))
	for _, delta := range dcc.compactAccountDeltas.deltas {
		knownAddresses[delta.oldAcct.addr] = delta.oldAcct.rowid
	}

	err = dcc.compactResourcesDeltas.resourcesLoadOld(tx, knownAddresses)
	if err != nil {
		return err
	}

	if dcc.updateStats {
		dcc.stats.OldAccountPreloadDuration = time.Duration(time.Now().UnixNano()) - dcc.stats.OldAccountPreloadDuration
	}

	err = accountsPutTotals(tx, dcc.roundTotals, false)
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
	newBase := dcc.newBase

	dcc.updatingBalancesDuration = time.Since(dcc.flushTime)

	if dcc.updateStats {
		dcc.stats.MemoryUpdatesDuration = time.Duration(time.Now().UnixNano())
	}

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
		key := accountCreatable{resUpdate.address, resUpdate.oldResource.aidx}
		macct, ok := au.resources[key]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to (%s, %d), but not in au.resources", cnt, resUpdate.address, resUpdate.oldResource.aidx)
		}

		if cnt > macct.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to (%s, %d), but au.resources had %d", cnt, resUpdate.address, resUpdate.oldResource.aidx, macct.ndeltas)
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
		mval := au.kvStore[key]
		if cnt > mval.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to key %d, but au.kvStore had %d", cnt, key, mval.ndeltas)
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
			au.deltas[i] = ledgercore.AccountDeltas{}
			au.creatableDeltas[i] = nil
		}
	}

	au.deltas = au.deltas[offset:]
	au.deltasAccum = au.deltasAccum[offset:]
	au.versions = au.versions[offset:]
	au.roundTotals = au.roundTotals[offset:]
	au.kvDeltas = au.kvDeltas[offset:]
	au.creatableDeltas = au.creatableDeltas[offset:]
	au.cachedDBRound = newBase

	au.accountsMu.Unlock()

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

// compactKvDeltas takes an array of kv deltas (one array entry per round), and
// compacts the array into a single map that contains all the
// changes. Intermediate changes are eliminated.  It counts the number of
// changes per round by specifying it in the ndeltas field of the modifiedKv.
func compactKvDeltas(kvDeltas []map[string]*string) map[string]modifiedValue {
	if len(kvDeltas) == 0 {
		return nil
	}
	outKvDeltas := make(map[string]modifiedValue)
	for _, roundKv := range kvDeltas {
		for key, value := range roundKv {
			prev := outKvDeltas[key] // prev may be the zero value. that's correct.
			outKvDeltas[key] = modifiedValue{
				data:    value,
				ndeltas: prev.ndeltas + 1,
			}
		}
	}
	return outKvDeltas
}

// compactCreatableDeltas takes an array of creatables map deltas ( one array entry per round ), and compact the array into a single
// map that contains all the deltas changes. While doing that, the function eliminate any intermediate changes.
// It counts the number of changes per round by specifying it in the ndeltas field of the modifiedCreatable.
func compactCreatableDeltas(creatableDeltas []map[basics.CreatableIndex]ledgercore.ModifiedCreatable) (outCreatableDeltas map[basics.CreatableIndex]ledgercore.ModifiedCreatable) {
	if len(creatableDeltas) == 0 {
		return
	}
	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	outCreatableDeltas = make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable, 1+len(creatableDeltas[0])*len(creatableDeltas))
	for _, roundCreatable := range creatableDeltas {
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
	vacuumStats, err := au.dbs.Wdb.Vacuum(ctx)
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
