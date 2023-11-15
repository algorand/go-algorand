// Copyright (C) 2019-2023 Algorand, Inc.
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
	"path/filepath"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/pebbledbdriver"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/sqlitedriver"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

// Ledger is a database storing the contents of the ledger.
type Ledger struct {
	// Database connections to the DBs storing blocks and tracker state.
	// We use potentially different databases to avoid SQLite contention
	// during catchup.
	trackerDBs trackerdb.Store
	blockDBs   db.Pair

	// blockQ is the buffer of added blocks that will be flushed to
	// persistent storage
	blockQ *blockQueue

	log logging.Logger

	// archival determines whether the ledger keeps all blocks forever
	// (archival mode) or trims older blocks to save space (non-archival).
	archival bool

	// the synchronous mode that would be used for the ledger databases.
	synchronousMode db.SynchronousMode

	// the synchronous mode that would be used while the accounts database is being rebuilt.
	accountsRebuildSynchronousMode db.SynchronousMode

	// genesisHash stores the genesis hash for this ledger.
	genesisHash crypto.Digest

	genesisAccounts map[basics.Address]basics.AccountData

	genesisProto        config.ConsensusParams
	genesisProtoVersion protocol.ConsensusVersion

	// State-machine trackers
	accts          accountUpdates
	acctsOnline    onlineAccounts
	catchpoint     catchpointTracker
	txTail         txTail
	bulletinDisk   bulletin
	bulletinMem    bulletinMem
	notifier       blockNotifier
	metrics        metricsTracker
	spVerification spVerificationTracker

	trackers  trackerRegistry
	trackerMu deadlock.RWMutex

	// verifiedTxnCache holds all the verified transactions state
	verifiedTxnCache verify.VerifiedTransactionCache

	cfg config.Local

	dirsAndPrefix DirsAndPrefix

	tracer logic.EvalTracer
}

// DirsAndPrefix is a struct that holds the genesis directories and the database file prefix, so ledger can construct full paths to database files
type DirsAndPrefix struct {
	config.ResolvedGenesisDirs
	DBFilePrefix string // the prefix of the database files, appended to genesis directories
}

// OpenLedger creates a Ledger object, using SQLite database filenames
// based on dbPathPrefix (in-memory if dbMem is true). genesisInitState.Blocks and
// genesisInitState.Accounts specify the initial blocks and accounts to use if the
func OpenLedger[T string | DirsAndPrefix](
	// database wasn't initialized before.
	log logging.Logger, dbPathPrefix T, dbMem bool, genesisInitState ledgercore.InitState, cfg config.Local,
) (*Ledger, error) {
	var err error
	verifiedCacheSize := cfg.VerifiedTranscationsCacheSize
	if verifiedCacheSize < cfg.TxPoolSize {
		verifiedCacheSize = cfg.TxPoolSize
		log.Warnf("The VerifiedTranscationsCacheSize in the config file was misconfigured to have smaller size then the TxPoolSize; The verified cache size was adjusted from %d to %d.", cfg.VerifiedTranscationsCacheSize, cfg.TxPoolSize)
	}
	var tracer logic.EvalTracer
	if cfg.EnableTxnEvalTracer {
		tracer = eval.MakeTxnGroupDeltaTracer(cfg.MaxAcctLookback)
	}

	var dirs DirsAndPrefix
	// if only a string path has been supplied for the ledger, use it for all resources
	// don't set the prefix, only tests provide a string for the path, and they manage paths explicitly
	if s, ok := any(dbPathPrefix).(string); ok {
		dirs.HotGenesisDir = s
		dirs.TrackerGenesisDir = s
		dirs.ColdGenesisDir = s
		dirs.BlockGenesisDir = s
		dirs.CatchpointGenesisDir = s
	} else if ds, ok := any(dbPathPrefix).(DirsAndPrefix); ok {
		// if a DirsAndPrefix has been supplied, use it.
		dirs = ds
	}

	l := &Ledger{
		log:                            log,
		archival:                       cfg.Archival,
		genesisHash:                    genesisInitState.GenesisHash,
		genesisAccounts:                genesisInitState.Accounts,
		genesisProto:                   config.Consensus[genesisInitState.Block.CurrentProtocol],
		genesisProtoVersion:            genesisInitState.Block.CurrentProtocol,
		synchronousMode:                db.SynchronousMode(cfg.LedgerSynchronousMode),
		accountsRebuildSynchronousMode: db.SynchronousMode(cfg.AccountsRebuildSynchronousMode),
		verifiedTxnCache:               verify.MakeVerifiedTransactionCache(verifiedCacheSize),
		cfg:                            cfg,
		dirsAndPrefix:                  dirs,
		tracer:                         tracer,
	}

	defer func() {
		if err != nil {
			l.Close()
		}
	}()

	l.trackerDBs, l.blockDBs, err = openLedgerDB(dirs, dbMem, cfg, log)
	if err != nil {
		err = fmt.Errorf("OpenLedger.openLedgerDB %v", err)
		return nil, err
	}

	l.setSynchronousMode(context.Background(), l.synchronousMode)

	start := time.Now()
	ledgerInitblocksdbCount.Inc(nil)
	err = l.blockDBs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return initBlocksDB(tx, l, []bookkeeping.Block{genesisInitState.Block}, cfg.Archival)
	})
	ledgerInitblocksdbMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		err = fmt.Errorf("OpenLedger.initBlocksDB %v", err)
		return nil, err
	}

	if l.genesisAccounts == nil {
		l.genesisAccounts = make(map[basics.Address]basics.AccountData)
	}

	l.blockQ, err = newBlockQueue(l)
	if err != nil {
		return nil, err
	}

	err = l.reloadLedger()
	if err != nil {
		return nil, err
	}

	return l, nil
}

func (l *Ledger) reloadLedger() error {
	// similar to the Close function, we want to start by closing the blockQ first. The
	// blockQ is having a sync goroutine which indirectly calls other trackers. We want to eliminate that go-routine first,
	// and follow up by taking the trackers lock.
	if l.blockQ != nil {
		l.blockQ.stop()
	}

	// take the trackers lock. This would ensure that no other goroutine is using the trackers.
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	// close the trackers.
	l.trackers.close()

	// init block queue
	var err error
	err = l.blockQ.start()
	if err != nil {
		err = fmt.Errorf("reloadLedger.blockQ.start %v", err)
		return err
	}

	// init tracker db
	trackerDBInitParams, err := trackerDBInitialize(l, l.catchpoint.catchpointEnabled(), l.catchpoint.dbDirectory)
	if err != nil {
		return err
	}

	// set account updates tracker as a driver to calculate tracker db round and committing offsets
	trackers := []ledgerTracker{
		&l.accts,          // update the balances
		&l.catchpoint,     // catchpoints tracker : update catchpoint labels, create catchpoint files
		&l.acctsOnline,    // update online account balances history
		&l.txTail,         // update the transaction tail, tracking the recent 1000 txn
		&l.bulletinDisk,   // provide closed channel signaling support for completed rounds on disk
		&l.bulletinMem,    // provide closed channel signaling support for completed rounds in memory
		&l.notifier,       // send OnNewBlocks to subscribers
		&l.metrics,        // provides metrics reporting support
		&l.spVerification, // provides state proof verification support
	}

	l.accts.initialize(l.cfg)
	l.acctsOnline.initialize(l.cfg)

	l.catchpoint.initialize(l.cfg, l.dirsAndPrefix)

	err = l.trackers.initialize(l, trackers, l.cfg)
	if err != nil {
		return err
	}

	err = l.trackers.loadFromDisk(l)
	if err != nil {
		err = fmt.Errorf("reloadLedger.loadFromDisk %w", err)
		return err
	}

	// post-init actions
	if trackerDBInitParams.VacuumOnStartup || l.cfg.OptimizeAccountsDatabaseOnStartup {
		err = l.accts.vacuumDatabase(context.Background())
		if err != nil {
			return err
		}
	}

	// Check that the genesis hash, if present, matches.
	err = l.verifyMatchingGenesisHash()
	if err != nil {
		return err
	}
	return nil
}

// verifyMatchingGenesisHash tests to see that the latest block header pointing to the same genesis hash provided in genesisHash.
func (l *Ledger) verifyMatchingGenesisHash() (err error) {
	// Check that the genesis hash, if present, matches.
	start := time.Now()
	ledgerVerifygenhashCount.Inc(nil)
	err = l.blockDBs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		latest, err := blockdb.BlockLatest(tx)
		if err != nil {
			return err
		}

		hdr, err := blockdb.BlockGetHdr(tx, latest)
		if err != nil {
			return err
		}

		params := config.Consensus[hdr.CurrentProtocol]
		if params.SupportGenesisHash && hdr.GenesisHash != l.genesisHash {
			return fmt.Errorf(
				"latest block %d genesis hash %v does not match expected genesis hash %v",
				latest, hdr.GenesisHash, l.genesisHash,
			)
		}
		return nil
	})
	ledgerVerifygenhashMicros.AddMicrosecondsSince(start, nil)
	return
}

func openLedgerDB(dbPrefixes DirsAndPrefix, dbMem bool, cfg config.Local, log logging.Logger) (trackerDBs trackerdb.Store, blockDBs db.Pair, err error) {
	outErr := make(chan error, 2)
	go func() {
		trackerDBPrefix := filepath.Join(dbPrefixes.ResolvedGenesisDirs.TrackerGenesisDir, dbPrefixes.DBFilePrefix)
		var lerr error
		switch cfg.StorageEngine {
		case "pebbledb":
			dir := trackerDBPrefix + "/tracker.pebble"
			trackerDBs, lerr = pebbledbdriver.Open(dir, dbMem, config.Consensus[protocol.ConsensusCurrentVersion], log)
		// anything else will initialize a sqlite engine.
		case "sqlite":
			fallthrough
		default:
			trackerDBs, lerr = sqlitedriver.Open(trackerDBPrefix+".tracker.sqlite", dbMem, log)
		}

		outErr <- lerr
	}()

	go func() {
		blockDBPrefix := filepath.Join(dbPrefixes.ResolvedGenesisDirs.BlockGenesisDir, dbPrefixes.DBFilePrefix)
		var lerr error
		blockDBs, lerr = db.OpenPair(blockDBPrefix+".block.sqlite", dbMem)
		if lerr != nil {
			outErr <- lerr
			return
		}
		blockDBs.Rdb.SetLogger(log)
		blockDBs.Wdb.SetLogger(log)
		outErr <- nil
	}()

	err = <-outErr
	if err != nil {
		return
	}
	err = <-outErr
	return
}

// setSynchronousMode sets the writing database connections synchronous mode to the specified mode
func (l *Ledger) setSynchronousMode(ctx context.Context, synchronousMode db.SynchronousMode) {
	if synchronousMode < db.SynchronousModeOff || synchronousMode > db.SynchronousModeExtra {
		l.log.Warnf("ledger.setSynchronousMode unable to set synchronous mode : requested value %d is invalid", synchronousMode)
		return
	}

	err := l.blockDBs.Wdb.SetSynchronousMode(ctx, synchronousMode, synchronousMode >= db.SynchronousModeFull)
	if err != nil {
		l.log.Warnf("ledger.setSynchronousMode unable to set synchronous mode on blocks db: %v", err)
		return
	}

	err = l.trackerDBs.SetSynchronousMode(ctx, synchronousMode, synchronousMode >= db.SynchronousModeFull)
	if err != nil {
		l.log.Warnf("ledger.setSynchronousMode unable to set synchronous mode on trackers db: %v", err)
		return
	}
}

// initBlocksDB performs DB initialization:
// - creates and populates it with genesis blocks
// - ensures DB is in good shape for archival mode and resets it if not
func initBlocksDB(tx *sql.Tx, l *Ledger, initBlocks []bookkeeping.Block, isArchival bool) (err error) {
	err = blockdb.BlockInit(tx, initBlocks)
	if err != nil {
		err = fmt.Errorf("initBlocksDB.blockInit %v", err)
		return err
	}

	// in archival mode check if DB contains all blocks up to the latest
	if isArchival {
		earliest, err := blockdb.BlockEarliest(tx)
		if err != nil {
			err = fmt.Errorf("initBlocksDB.blockEarliest %v", err)
			return err
		}

		// Detect possible problem - archival node needs all block but have only subsequence of them
		// So reset the DB and init it again
		if earliest != basics.Round(0) {
			l.log.Warnf("resetting blocks DB (earliest block is %v)", earliest)
			err := blockdb.BlockResetDB(tx)
			if err != nil {
				err = fmt.Errorf("initBlocksDB.blockResetDB %v", err)
				return err
			}
			err = blockdb.BlockInit(tx, initBlocks)
			if err != nil {
				err = fmt.Errorf("initBlocksDB.blockInit 2 %v", err)
				return err
			}
		}
	}

	return nil
}

// Close reclaims resources used by the ledger (namely, the database connection
// and goroutines used by trackers).
func (l *Ledger) Close() {
	// we shut the blockqueue first, since it's sync goroutine dispatches calls
	// back to the trackers.
	if l.blockQ != nil {
		l.blockQ.stop()
	}

	// take the trackers lock. This would ensure that no other goroutine is using the trackers.
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	// then, we shut down the trackers and their corresponding goroutines.
	l.trackers.close()

	// last, we close the underlying database connections.
	l.blockDBs.Close()
	l.trackerDBs.Close()
}

// RegisterBlockListeners registers listeners that will be called when a
// new block is added to the ledger.
func (l *Ledger) RegisterBlockListeners(listeners []ledgercore.BlockListener) {
	l.notifier.register(listeners)
}

// RegisterVotersCommitListener registers a listener that will be called when a
// commit is about to cover a round.
func (l *Ledger) RegisterVotersCommitListener(listener ledgercore.VotersCommitListener) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	l.acctsOnline.voters.registerPrepareCommitListener(listener)
}

// UnregisterVotersCommitListener unregisters the commit listener.
func (l *Ledger) UnregisterVotersCommitListener() {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	l.acctsOnline.voters.unregisterPrepareCommitListener()
}

// notifyCommit informs the trackers that all blocks up to r have been
// written to disk.  Returns the minimum block number that must be kept
// in the database.
func (l *Ledger) notifyCommit(r basics.Round) basics.Round {
	t0 := time.Now()
	l.trackerMu.Lock()
	ledgerTrackerMuLockCount.Inc(nil)
	defer func() {
		l.trackerMu.Unlock()
		ledgerTrackerMuLockMicros.AddMicrosecondsSince(t0, nil)
	}()
	minToSave := l.trackers.committedUpTo(r)

	// Check if additional block history is configured, and adjust minToSave if so.
	if configuredMinToSave := r.SubSaturate(basics.Round(l.cfg.MaxBlockHistoryLookback)); configuredMinToSave < minToSave {
		minToSave = configuredMinToSave
	}

	if l.archival {
		// Do not forget any blocks.
		minToSave = 0
	}

	return minToSave
}

// GetLastCatchpointLabel returns the latest catchpoint label that was written to the
// database.
func (l *Ledger) GetLastCatchpointLabel() string {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.catchpoint.GetLastCatchpointLabel()
}

// GetCreatorForRound takes a CreatableIndex and a CreatableType and tries to
// look up a creator address, setting ok to false if the query succeeded but no
// creator was found.
func (l *Ledger) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.GetCreatorForRound(rnd, cidx, ctype)
}

// GetCreator is like GetCreatorForRound, but for the latest round and race-free
// with respect to ledger.Latest()
func (l *Ledger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.GetCreatorForRound(l.blockQ.latest(), cidx, ctype)
}

// GetStateDeltaForRound retrieves a ledgercore.StateDelta from the accountUpdates cache for the requested rnd
func (l *Ledger) GetStateDeltaForRound(rnd basics.Round) (ledgercore.StateDelta, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.lookupStateDelta(rnd)
}

// GetTracer returns the logic.EvalTracer attached to the ledger--can be nil.
func (l *Ledger) GetTracer() logic.EvalTracer {
	return l.tracer
}

// VotersForStateProof returns the top online accounts at round rnd.
// The result might be nil, even with err=nil, if there are no voters
// for that round because state proofs were not enabled.
func (l *Ledger) VotersForStateProof(rnd basics.Round) (*ledgercore.VotersForRound, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.acctsOnline.voters.VotersForStateProof(rnd)
}

// GetStateProofVerificationContext returns the data required to verify the state proof whose last attested round is
// stateProofLastAttestedRound.
func (l *Ledger) GetStateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.spVerification.LookupVerificationContext(stateProofLastAttestedRound)
}

// LookupLatest uses the accounts tracker to return the account state (including
// resources) for a given address, for the latest round. The returned account values
// reflect the changes of all blocks up to and including the returned round number.
func (l *Ledger) LookupLatest(addr basics.Address) (basics.AccountData, basics.Round, basics.MicroAlgos, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	// Intentionally apply (pending) rewards up to rnd.
	data, rnd, withoutRewards, err := l.accts.lookupLatest(addr)
	if err != nil {
		return basics.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
	}
	return data, rnd, withoutRewards, nil
}

// LookupAccount uses the accounts tracker to return the account state (without
// resources) for a given address, for a given round. The returned account values
// reflect the changes of all blocks up to and including the returned round number.
// The returned AccountData contains the rewards applied up to that round number,
// and the additional withoutRewards return value contains the value before rewards
// were applied.
func (l *Ledger) LookupAccount(round basics.Round, addr basics.Address) (data ledgercore.AccountData, validThrough basics.Round, withoutRewards basics.MicroAlgos, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	data, rnd, rewardsVersion, rewardsLevel, err := l.accts.lookupWithoutRewards(round, addr, true /* take lock */)
	if err != nil {
		return ledgercore.AccountData{}, basics.Round(0), basics.MicroAlgos{}, err
	}

	// Intentionally apply (pending) rewards up to rnd, remembering the old value
	withoutRewards = data.MicroAlgos
	data = data.WithUpdatedRewards(config.Consensus[rewardsVersion], rewardsLevel)
	return data, rnd, withoutRewards, nil
}

// LookupApplication loads an application resource that matches the request parameters from the ledger.
func (l *Ledger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	r, err := l.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AppCreatable)
	return ledgercore.AppResource{AppParams: r.AppParams, AppLocalState: r.AppLocalState}, err
}

// LookupAsset loads an asset resource that matches the request parameters from the ledger.
func (l *Ledger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	r, err := l.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AssetCreatable)
	return ledgercore.AssetResource{AssetParams: r.AssetParams, AssetHolding: r.AssetHolding}, err
}

// lookupResource loads a resource that matches the request parameters from the accounts update
func (l *Ledger) lookupResource(rnd basics.Round, addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ledgercore.AccountResource, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	// Intentionally apply (pending) rewards up to rnd.
	res, _, err := l.accts.LookupResource(rnd, addr, aidx, ctype)
	if err != nil {
		return ledgercore.AccountResource{}, err
	}

	return res, nil
}

// LookupKv loads a KV pair from the accounts update
func (l *Ledger) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	return l.accts.LookupKv(rnd, key)
}

// LookupKeysByPrefix searches keys with specific prefix, up to `maxKeyNum`
// if `maxKeyNum` == 0, then it loads all keys with such prefix
func (l *Ledger) LookupKeysByPrefix(round basics.Round, keyPrefix string, maxKeyNum uint64) ([]string, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	return l.accts.LookupKeysByPrefix(round, keyPrefix, maxKeyNum)
}

// LookupAgreement returns account data used by agreement.
func (l *Ledger) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	// Intentionally apply (pending) rewards up to rnd.
	data, err := l.acctsOnline.LookupOnlineAccountData(rnd, addr)
	if err != nil {
		return basics.OnlineAccountData{}, err
	}

	return data, nil
}

// LookupWithoutRewards is like Lookup but does not apply pending rewards up
// to the requested round rnd.
func (l *Ledger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	var result ledgercore.AccountData

	result, validThrough, err := l.accts.LookupWithoutRewards(rnd, addr)
	if err != nil {
		return ledgercore.AccountData{}, basics.Round(0), err
	}

	return result, validThrough, nil
}

// LatestTotals returns the totals of all accounts for the most recent round, as well as the round number.
func (l *Ledger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.LatestTotals()
}

// Totals returns the totals of all accounts for the given round.
func (l *Ledger) Totals(rnd basics.Round) (ledgercore.AccountTotals, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.Totals(rnd)
}

// OnlineCirculation returns the online totals of all accounts at the end of round rnd.
// It implements agreement's calls for Circulation(rnd)
func (l *Ledger) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.acctsOnline.onlineCirculation(rnd, voteRnd)
}

// CheckDup return whether a transaction is a duplicate one.
func (l *Ledger) CheckDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	return l.txTail.checkDup(currentProto, current, firstValid, lastValid, txid, txl)
}

// Latest returns the latest known block round added to the ledger.
func (l *Ledger) Latest() basics.Round {
	return l.blockQ.latest()
}

// LatestCommitted returns the last block round number written to
// persistent storage.  This block, and all previous blocks, are
// guaranteed to be available after a crash. In addition, it returns
// the latest block round number added to the ledger ( which will be
// flushed to persistent storage later on )
func (l *Ledger) LatestCommitted() (basics.Round, basics.Round) {
	return l.blockQ.latestCommitted()
}

// Block returns the block for round rnd.
func (l *Ledger) Block(rnd basics.Round) (blk bookkeeping.Block, err error) {
	return l.blockQ.getBlock(rnd)
}

// BlockHdr returns the BlockHeader of the block for round rnd.
func (l *Ledger) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {

	// Expected availability range in txTail.blockHeader is [Latest - MaxTxnLife, Latest]
	// allowing (MaxTxnLife + 1) = 1001 rounds back loopback.
	// The depth besides the MaxTxnLife is controlled by DeeperBlockHeaderHistory parameter
	// and currently set to 1.
	// Explanation:
	// Clients are expected to query blocks at rounds (txn.LastValid - (MaxTxnLife + 1)),
	// and because a txn is alive when the current round <= txn.LastValid
	// and valid if txn.LastValid - txn.FirstValid <= MaxTxnLife
	// the deepest lookup happens when txn.LastValid == current => txn.LastValid == Latest + 1
	// that gives Latest + 1 - (MaxTxnLife + 1) = Latest - MaxTxnLife as the first round to be accessible.
	hdr, ok := l.txTail.blockHeader(rnd)
	if !ok {
		hdr, err = l.blockQ.getBlockHdr(rnd)
	}
	return hdr, err
}

// EncodedBlockCert returns the encoded block and the corresponding encoded certificate of the block for round rnd.
func (l *Ledger) EncodedBlockCert(rnd basics.Round) (blk []byte, cert []byte, err error) {
	return l.blockQ.getEncodedBlockCert(rnd)
}

// BlockCert returns the block and the certificate of the block for round rnd.
func (l *Ledger) BlockCert(rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	return l.blockQ.getBlockCert(rnd)
}

// AddBlock adds a new block to the ledger.  The block is stored in an
// in-memory queue and is written to the disk in the background.  An error
// is returned if this is not the expected next block number.
func (l *Ledger) AddBlock(blk bookkeeping.Block, cert agreement.Certificate) error {
	// passing nil as the executionPool is ok since we've asking the evaluator to skip verification.

	updates, err := eval.Eval(context.Background(), l, blk, false, l.verifiedTxnCache, nil, l.tracer)
	if err != nil {
		if errNSBE, ok := err.(ledgercore.ErrNonSequentialBlockEval); ok && errNSBE.EvaluatorRound <= errNSBE.LatestRound {
			return ledgercore.BlockInLedgerError{
				LastRound: errNSBE.EvaluatorRound,
				NextRound: errNSBE.LatestRound + 1}
		}
		return err
	}
	updates.OptimizeAllocatedMemory(l.cfg.MaxAcctLookback)
	vb := ledgercore.MakeValidatedBlock(blk, updates)

	return l.AddValidatedBlock(vb, cert)
}

// AddValidatedBlock adds a new block to the ledger, after the block has
// been validated by calling Ledger.Validate().  This saves the cost of
// having to re-compute the effect of the block on the ledger state, if
// the block has previously been validated.  Otherwise, AddValidatedBlock
// behaves like AddBlock.
func (l *Ledger) AddValidatedBlock(vb ledgercore.ValidatedBlock, cert agreement.Certificate) error {
	// Grab the tracker lock first, to ensure newBlock() is notified before committedUpTo().
	t0 := time.Now()
	l.trackerMu.Lock()
	ledgerTrackerMuLockCount.Inc(nil)
	defer func() {
		l.trackerMu.Unlock()
		ledgerTrackerMuLockMicros.AddMicrosecondsSince(t0, nil)
	}()

	blk := vb.Block()
	err := l.blockQ.putBlock(blk, cert)
	if err != nil {
		return err
	}
	l.trackers.newBlock(blk, vb.Delta())
	l.log.Debugf("ledger.AddValidatedBlock: added blk %d", blk.Round())
	return nil
}

// WaitForCommit waits until block r (and block before r) are durably
// written to disk.
func (l *Ledger) WaitForCommit(r basics.Round) {
	l.blockQ.waitCommit(r)
}

// Wait returns a channel that closes once a given round is stored
// durably in the ledger.
// When <-l.Wait(r) finishes, ledger is guaranteed to have round r,
// and will not lose round r after a crash.
// This makes it easy to use in a select{} statement.
func (l *Ledger) Wait(r basics.Round) chan struct{} {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.bulletinDisk.Wait(r)
}

// WaitWithCancel returns a channel that closes once a given round is
// stored durably in the ledger. The returned function can be used to
// cancel the wait, which cleans up resources if no other Wait call is
// active for the same round.
func (l *Ledger) WaitWithCancel(r basics.Round) (chan struct{}, func()) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.bulletinDisk.Wait(r), func() { l.bulletinDisk.CancelWait(r) }
}

// WaitMem returns a channel that closes once a given round is
// available in memory in the ledger, but might not be stored
// durably on disk yet.
func (l *Ledger) WaitMem(r basics.Round) chan struct{} {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.bulletinMem.Wait(r)
}

// GenesisHash returns the genesis hash for this ledger.
func (l *Ledger) GenesisHash() crypto.Digest {
	return l.genesisHash
}

// GenesisProto returns the initial protocol for this ledger.
func (l *Ledger) GenesisProto() config.ConsensusParams {
	return l.genesisProto
}

// GenesisProtoVersion returns the initial protocol version for this ledger.
func (l *Ledger) GenesisProtoVersion() protocol.ConsensusVersion {
	return l.genesisProtoVersion
}

// GenesisAccounts returns initial accounts for this ledger.
func (l *Ledger) GenesisAccounts() map[basics.Address]basics.AccountData {
	return l.genesisAccounts
}

// GetCatchpointCatchupState returns the current state of the catchpoint catchup.
func (l *Ledger) GetCatchpointCatchupState(ctx context.Context) (state CatchpointCatchupState, err error) {
	return MakeCatchpointCatchupAccessor(l, l.log).GetState(ctx)
}

// GetCatchpointStream returns a ReadCloseSizer file stream from which the catchpoint file
// for the provided round could be retrieved. If no such stream can be generated, a non-nil
// error is returned. The io.ReadCloser and the error are mutually exclusive -
// if error is returned, the file stream is guaranteed to be nil, and vice versa,
// if the file stream is not nil, the error is guaranteed to be nil.
func (l *Ledger) GetCatchpointStream(round basics.Round) (ReadCloseSizer, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.catchpoint.GetCatchpointStream(round)
}

// ledgerForTracker methods
func (l *Ledger) trackerDB() trackerdb.Store {
	return l.trackerDBs
}

// ledgerForTracker methods
func (l *Ledger) blockDB() db.Pair {
	return l.blockDBs
}

func (l *Ledger) trackerLog() logging.Logger {
	return l.log
}

// trackerEvalVerified is used by the accountUpdates to reconstruct the ledgercore.StateDelta from a given block during it's loadFromDisk execution.
// when this function is called, the trackers mutex is expected already to be taken. The provided accUpdatesLedger would allow the
// evaluator to shortcut the "main" ledger ( i.e. this struct ) and avoid taking the trackers lock a second time.
func (l *Ledger) trackerEvalVerified(blk bookkeeping.Block, accUpdatesLedger eval.LedgerForEvaluator) (ledgercore.StateDelta, error) {
	// passing nil as the executionPool is ok since we've asking the evaluator to skip verification.
	return eval.Eval(context.Background(), accUpdatesLedger, blk, false, l.verifiedTxnCache, nil, l.tracer)
}

// IsWritingCatchpointDataFile returns true when a catchpoint file is being generated.
// The function is used by the catchup service to avoid memory pressure until the
// catchpoint data file writing is complete.
func (l *Ledger) IsWritingCatchpointDataFile() bool {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.catchpoint.isWritingCatchpointDataFile()
}

// VerifiedTransactionCache returns the verify.VerifiedTransactionCache
func (l *Ledger) VerifiedTransactionCache() verify.VerifiedTransactionCache {
	return l.verifiedTxnCache
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate. If the length of the
// payset being evaluated is known in advance, a paysetHint >= 0 can be
// passed, avoiding unnecessary payset slice growth. The optional maxTxnBytesPerBlock parameter
// provides a cap on the size of a single generated block size, when a non-zero value is passed.
// If a value of zero or less is passed to maxTxnBytesPerBlock, the consensus MaxTxnBytesPerBlock would
// be used instead.
// The tracer argument is a logic.EvalTracer which will be attached to the evaluator and have its hooked invoked during
// the eval process for each block. A nil tracer will default to the tracer attached to the ledger.
func (l *Ledger) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int, tracer logic.EvalTracer) (*eval.BlockEvaluator, error) {
	tracerForEval := tracer
	if tracerForEval == nil {
		tracerForEval = l.tracer
	}
	return eval.StartEvaluator(l, hdr,
		eval.EvaluatorOptions{
			PaysetHint:          paysetHint,
			Generate:            true,
			Validate:            true,
			MaxTxnBytesPerBlock: maxTxnBytesPerBlock,
			Tracer:              tracerForEval,
		})
}

// FlushCaches flushes any pending data in caches so that it is fully available during future lookups.
func (l *Ledger) FlushCaches() {
	l.accts.flushCaches()
}

// Validate uses the ledger to validate block blk as a candidate next block.
// It returns an error if blk is not the expected next block, or if blk is
// not a valid block (e.g., it has duplicate transactions, overspends some
// account, etc).
func (l *Ledger) Validate(ctx context.Context, blk bookkeeping.Block, executionPool execpool.BacklogPool) (*ledgercore.ValidatedBlock, error) {
	delta, err := eval.Eval(ctx, l, blk, true, l.verifiedTxnCache, executionPool, l.tracer)
	if err != nil {
		return nil, err
	}

	vb := ledgercore.MakeValidatedBlock(blk, delta)
	return &vb, nil
}

// LatestTrackerCommitted returns the trackers' dbRound which "is always exactly accountsRound()"
func (l *Ledger) LatestTrackerCommitted() basics.Round {
	return l.trackers.getDbRound()
}

// IsBehindCommittingDeltas indicates if the ledger is behind expected number of in-memory deltas.
// It intended to slow down the catchup service when deltas overgrow some limit.
func (l *Ledger) IsBehindCommittingDeltas() bool {
	return l.trackers.isBehindCommittingDeltas(l.Latest())
}

// DebuggerLedger defines the minimal set of method required for creating a debug balances.
type DebuggerLedger = eval.LedgerForCowBase

// MakeDebugBalances creates a ledger suitable for dryrun and debugger
func MakeDebugBalances(l DebuggerLedger, round basics.Round, proto protocol.ConsensusVersion, prevTimestamp int64) apply.Balances {
	return eval.MakeDebugBalances(l, round, proto, prevTimestamp)
}

var ledgerInitblocksdbCount = metrics.NewCounter("ledger_initblocksdb_count", "calls")
var ledgerInitblocksdbMicros = metrics.NewCounter("ledger_initblocksdb_micros", "µs spent")
var ledgerVerifygenhashCount = metrics.NewCounter("ledger_verifygenhash_count", "calls")
var ledgerVerifygenhashMicros = metrics.NewCounter("ledger_verifygenhash_micros", "µs spent")
var ledgerTrackerMuLockCount = metrics.NewCounter("ledger_lock_trackermu_count", "calls")
var ledgerTrackerMuLockMicros = metrics.NewCounter("ledger_lock_trackermu_micros", "µs spent")
