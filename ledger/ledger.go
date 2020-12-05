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
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/metrics"
)

// Ledger is a database storing the contents of the ledger.
type Ledger struct {
	// Database connections to the DBs storing blocks and tracker state.
	// We use potentially different databases to avoid SQLite contention
	// during catchup.
	trackerDBs dbPair
	blockDBs   dbPair

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

	genesisProto config.ConsensusParams

	// State-machine trackers
	accts    accountUpdates
	txTail   txTail
	bulletin bulletin
	notifier blockNotifier
	time     timeTracker
	metrics  metricsTracker

	trackers  trackerRegistry
	trackerMu deadlock.RWMutex

	headerCache heapLRUCache
}

// InitState structure defines blockchain init params
type InitState struct {
	Block       bookkeeping.Block
	Accounts    map[basics.Address]basics.AccountData
	GenesisHash crypto.Digest
}

// OpenLedger creates a Ledger object, using SQLite database filenames
// based on dbPathPrefix (in-memory if dbMem is true). genesisInitState.Blocks and
// genesisInitState.Accounts specify the initial blocks and accounts to use if the
// database wasn't initialized before.
func OpenLedger(
	log logging.Logger, dbPathPrefix string, dbMem bool, genesisInitState InitState, cfg config.Local,
) (*Ledger, error) {
	var err error
	l := &Ledger{
		log:                            log,
		archival:                       cfg.Archival,
		genesisHash:                    genesisInitState.GenesisHash,
		genesisAccounts:                genesisInitState.Accounts,
		genesisProto:                   config.Consensus[genesisInitState.Block.CurrentProtocol],
		synchronousMode:                db.SynchronousMode(cfg.LedgerSynchronousMode),
		accountsRebuildSynchronousMode: db.SynchronousMode(cfg.AccountsRebuildSynchronousMode),
	}

	l.headerCache.maxEntries = 10

	defer func() {
		if err != nil {
			l.Close()
		}
	}()

	l.trackerDBs, l.blockDBs, err = openLedgerDB(dbPathPrefix, dbMem)
	if err != nil {
		err = fmt.Errorf("OpenLedger.openLedgerDB %v", err)
		return nil, err
	}
	l.trackerDBs.rdb.SetLogger(log)
	l.trackerDBs.wdb.SetLogger(log)
	l.blockDBs.rdb.SetLogger(log)
	l.blockDBs.wdb.SetLogger(log)

	l.setSynchronousMode(context.Background(), l.synchronousMode)

	start := time.Now()
	ledgerInitblocksdbCount.Inc(nil)
	err = l.blockDBs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
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

	l.accts.initialize(cfg, dbPathPrefix, l.genesisProto, l.genesisAccounts)

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
		l.blockQ.close()
		l.blockQ = nil
	}

	// take the trackers lock. This would ensure that no other goroutine is using the trackers.
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	// close the trackers.
	l.trackers.close()

	// reload -
	var err error
	l.blockQ, err = bqInit(l)
	if err != nil {
		err = fmt.Errorf("reloadLedger.bqInit %v", err)
		return err
	}

	l.trackers.register(&l.accts)    // update the balances
	l.trackers.register(&l.time)     // tracks the block timestamps
	l.trackers.register(&l.txTail)   // update the transaction tail, tracking the recent 1000 txn
	l.trackers.register(&l.bulletin) // provide closed channel signaling support for completed rounds
	l.trackers.register(&l.notifier) // send OnNewBlocks to subscribers
	l.trackers.register(&l.metrics)  // provides metrics reporting support

	err = l.trackers.loadFromDisk(l)
	if err != nil {
		err = fmt.Errorf("reloadLedger.loadFromDisk %v", err)
		return err
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
	err = l.blockDBs.rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		latest, err := blockLatest(tx)
		if err != nil {
			return err
		}

		hdr, err := blockGetHdr(tx, latest)
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

func openLedgerDB(dbPathPrefix string, dbMem bool) (trackerDBs dbPair, blockDBs dbPair, err error) {
	// Backwards compatibility: we used to store both blocks and tracker
	// state in a single SQLite db file.
	var trackerDBFilename string
	var blockDBFilename string

	if !dbMem {
		commonDBFilename := dbPathPrefix + ".sqlite"
		_, err = os.Stat(commonDBFilename)
		if !os.IsNotExist(err) {
			// before launch, we used to have both blocks and tracker
			// state in a single SQLite db file. We don't have that anymore,
			// and we want to fail when that's the case.
			err = fmt.Errorf("A single ledger database file '%s' was detected. This is no longer supported by current binary", commonDBFilename)
			return
		}
	}

	trackerDBFilename = dbPathPrefix + ".tracker.sqlite"
	blockDBFilename = dbPathPrefix + ".block.sqlite"

	trackerDBs, err = dbOpen(trackerDBFilename, dbMem)
	if err != nil {
		return
	}

	blockDBs, err = dbOpen(blockDBFilename, dbMem)
	if err != nil {
		return
	}
	return
}

// setSynchronousMode sets the writing database connections syncronous mode to the specified mode
func (l *Ledger) setSynchronousMode(ctx context.Context, synchronousMode db.SynchronousMode) {
	if synchronousMode < db.SynchronousModeOff || synchronousMode > db.SynchronousModeExtra {
		l.log.Warnf("ledger.setSynchronousMode unable to set syncronous mode : requested value %d is invalid", synchronousMode)
		return
	}

	err := l.blockDBs.wdb.SetSynchronousMode(ctx, synchronousMode, synchronousMode >= db.SynchronousModeFull)
	if err != nil {
		l.log.Warnf("ledger.setSynchronousMode unable to set syncronous mode on blocks db: %v", err)
		return
	}

	err = l.trackerDBs.wdb.SetSynchronousMode(ctx, synchronousMode, synchronousMode >= db.SynchronousModeFull)
	if err != nil {
		l.log.Warnf("ledger.setSynchronousMode unable to set syncronous mode on trackers db: %v", err)
		return
	}
}

// initBlocksDB performs DB initialization:
// - creates and populates it with genesis blocks
// - ensures DB is in good shape for archival mode and resets it if not
func initBlocksDB(tx *sql.Tx, l *Ledger, initBlocks []bookkeeping.Block, isArchival bool) (err error) {
	err = blockInit(tx, initBlocks)
	if err != nil {
		err = fmt.Errorf("initBlocksDB.blockInit %v", err)
		return err
	}

	// in archival mode check if DB contains all blocks up to the latest
	if isArchival {
		earliest, err := blockEarliest(tx)
		if err != nil {
			err = fmt.Errorf("initBlocksDB.blockEarliest %v", err)
			return err
		}

		// Detect possible problem - archival node needs all block but have only subsequence of them
		// So reset the DB and init it again
		if earliest != basics.Round(0) {
			l.log.Warnf("resetting blocks DB (earliest block is %v)", earliest)
			err := blockResetDB(tx)
			if err != nil {
				err = fmt.Errorf("initBlocksDB.blockResetDB %v", err)
				return err
			}
			err = blockInit(tx, initBlocks)
			if err != nil {
				err = fmt.Errorf("initBlocksDB.blockInit 2 %v", err)
				return err
			}
		}

		// Manually replace block 0, even if we already had it
		// (necessary to normalize the payset commitment because of a
		// bug that caused its value to change)
		//
		// Don't bother for non-archival nodes since they will toss
		// block 0 almost immediately
		//
		// TODO remove this once a version containing this code has
		// been deployed to archival nodes
		if len(initBlocks) > 0 && initBlocks[0].Round() == basics.Round(0) {
			updated, err := blockReplaceIfExists(tx, l.log, initBlocks[0], agreement.Certificate{})
			if err != nil {
				err = fmt.Errorf("initBlocksDB.blockReplaceIfExists %v", err)
				return err
			}
			if updated {
				l.log.Infof("initBlocksDB replaced block 0")
			}
		}
	}

	return nil
}

// Close reclaims resources used by the ledger (namely, the database connection
// and goroutines used by trackers).
func (l *Ledger) Close() {
	// we shut the the blockqueue first, since it's sync goroutine dispatches calls
	// back to the trackers.
	if l.blockQ != nil {
		l.blockQ.close()
		l.blockQ = nil
	}

	// take the trackers lock. This would ensure that no other goroutine is using the trackers.
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	// then, we shut down the trackers and their corresponding goroutines.
	l.trackers.close()

	// last, we close the underlying database connections.
	l.blockDBs.close()
	l.trackerDBs.close()
}

// RegisterBlockListeners registers listeners that will be called when a
// new block is added to the ledger.
func (l *Ledger) RegisterBlockListeners(listeners []BlockListener) {
	l.notifier.register(listeners)
}

// notifyCommit informs the trackers that all blocks up to r have been
// written to disk.  Returns the minimum block number that must be kept
// in the database.
func (l *Ledger) notifyCommit(r basics.Round) basics.Round {
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()
	minToSave := l.trackers.committedUpTo(r)

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
	return l.accts.GetLastCatchpointLabel()
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

// CompactCertVoters returns the top online accounts at round rnd.
// The result might be nil, even with err=nil, if there are no voters
// for that round because compact certs were not enabled.
func (l *Ledger) CompactCertVoters(rnd basics.Round) (voters *VotersForRound, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.voters.getVoters(rnd)
}

// ListAssets takes a maximum asset index and maximum result length, and
// returns up to that many CreatableLocators from the database where app idx is
// less than or equal to the maximum.
func (l *Ledger) ListAssets(maxAssetIdx basics.AssetIndex, maxResults uint64) (results []basics.CreatableLocator, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.ListAssets(maxAssetIdx, maxResults)
}

// ListApplications takes a maximum app index and maximum result length, and
// returns up to that many CreatableLocators from the database where app idx is
// less than or equal to the maximum.
func (l *Ledger) ListApplications(maxAppIdx basics.AppIndex, maxResults uint64) (results []basics.CreatableLocator, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.ListApplications(maxAppIdx, maxResults)
}

// Lookup uses the accounts tracker to return the account state for a
// given account in a particular round.  The account values reflect
// the changes of all blocks up to and including rnd.
func (l *Ledger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	// Intentionally apply (pending) rewards up to rnd.
	data, err := l.accts.LookupWithRewards(rnd, addr)
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// LookupWithoutRewards is like Lookup but does not apply pending rewards up
// to the requested round rnd.
func (l *Ledger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, basics.Round, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	data, validThrough, err := l.accts.LookupWithoutRewards(rnd, addr)
	if err != nil {
		return basics.AccountData{}, basics.Round(0), err
	}

	return data, validThrough, nil
}

// Totals returns the totals of all accounts at the end of round rnd.
func (l *Ledger) Totals(rnd basics.Round) (AccountTotals, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.Totals(rnd)
}

func (l *Ledger) checkDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl txlease) error {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txTail.checkDup(currentProto, current, firstValid, lastValid, txid, txl)
}

// GetRoundTxIds returns a map of the transactions ids that we have for the given round
// this function is currently not being used, but remains here as it might be useful in the future.
func (l *Ledger) GetRoundTxIds(rnd basics.Round) (txMap map[transactions.Txid]bool) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txTail.getRoundTxIds(rnd)
}

// Latest returns the latest known block round added to the ledger.
func (l *Ledger) Latest() basics.Round {
	return l.blockQ.latest()
}

// LatestCommitted returns the last block round number written to
// persistent storage.  This block, and all previous blocks, are
// guaranteed to be available after a crash.
func (l *Ledger) LatestCommitted() basics.Round {
	return l.blockQ.latestCommitted()
}

// Block returns the block for round rnd.
func (l *Ledger) Block(rnd basics.Round) (blk bookkeeping.Block, err error) {
	return l.blockQ.getBlock(rnd)
}

// BlockHdr returns the BlockHeader of the block for round rnd.
func (l *Ledger) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	value, exists := l.headerCache.Get(rnd)
	if exists {
		blk = value.(bookkeeping.BlockHeader)
		return
	}

	blk, err = l.blockQ.getBlockHdr(rnd)
	if err == nil {
		l.headerCache.Put(rnd, blk)
	}
	return
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
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.

	updates, err := eval(context.Background(), l, blk, false, nil, nil)
	if err != nil {
		return err
	}

	vb := ValidatedBlock{
		blk:   blk,
		delta: updates,
	}

	return l.AddValidatedBlock(vb, cert)
}

// AddValidatedBlock adds a new block to the ledger, after the block has
// been validated by calling Ledger.Validate().  This saves the cost of
// having to re-compute the effect of the block on the ledger state, if
// the block has previously been validated.  Otherwise, AddValidatedBlock
// behaves like AddBlock.
func (l *Ledger) AddValidatedBlock(vb ValidatedBlock, cert agreement.Certificate) error {
	// Grab the tracker lock first, to ensure newBlock() is notified before committedUpTo().
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	err := l.blockQ.putBlock(vb.blk, cert)
	if err != nil {
		return err
	}
	l.headerCache.Put(vb.blk.Round(), vb.blk.BlockHeader)
	l.trackers.newBlock(vb.blk, vb.delta)
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
	return l.bulletin.Wait(r)
}

// Timestamp uses the timestamp tracker to return the timestamp
// from block r.
func (l *Ledger) Timestamp(r basics.Round) (int64, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.time.timestamp(r)
}

// GenesisHash returns the genesis hash for this ledger.
func (l *Ledger) GenesisHash() crypto.Digest {
	return l.genesisHash
}

// GenesisProto returns the initial protocol for this ledger.
func (l *Ledger) GenesisProto() config.ConsensusParams {
	return l.genesisProto
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
	return l.accts.GetCatchpointStream(round)
}

// ledgerForTracker methods
func (l *Ledger) trackerDB() dbPair {
	return l.trackerDBs
}

// ledgerForTracker methods
func (l *Ledger) blockDB() dbPair {
	return l.blockDBs
}

func (l *Ledger) trackerLog() logging.Logger {
	return l.log
}

// trackerEvalVerified is used by the accountUpdates to reconstruct the StateDelta from a given block during it's loadFromDisk execution.
// when this function is called, the trackers mutex is expected already to be taken. The provided accUpdatesLedger would allow the
// evaluator to shortcut the "main" ledger ( i.e. this struct ) and avoid taking the trackers lock a second time.
func (l *Ledger) trackerEvalVerified(blk bookkeeping.Block, accUpdatesLedger ledgerForEvaluator) (StateDelta, error) {
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.
	return eval(context.Background(), accUpdatesLedger, blk, false, nil, nil)
}

// IsWritingCatchpointFile returns true when a catchpoint file is being generated. The function is used by the catchup service
// to avoid memory pressure until the catchpoint file writing is complete.
func (l *Ledger) IsWritingCatchpointFile() bool {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.IsWritingCatchpointFile()
}

// A txlease is a transaction (sender, lease) pair which uniquely specifies a
// transaction lease.
type txlease struct {
	sender basics.Address
	lease  [32]byte
}

var ledgerInitblocksdbCount = metrics.NewCounter("ledger_initblocksdb_count", "calls")
var ledgerInitblocksdbMicros = metrics.NewCounter("ledger_initblocksdb_micros", "µs spent")
var ledgerVerifygenhashCount = metrics.NewCounter("ledger_verifygenhash_count", "calls")
var ledgerVerifygenhashMicros = metrics.NewCounter("ledger_verifygenhash_micros", "µs spent")
