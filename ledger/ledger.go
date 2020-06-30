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
	"io"
	"os"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
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
		log:             log,
		archival:        cfg.Archival,
		genesisHash:     genesisInitState.GenesisHash,
		genesisAccounts: genesisInitState.Accounts,
		genesisProto:    config.Consensus[genesisInitState.Block.CurrentProtocol],
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

	err = l.blockDBs.wdb.Atomic(func(tx *sql.Tx) error {
		return initBlocksDB(tx, l, []bookkeeping.Block{genesisInitState.Block}, cfg.Archival)
	})
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
	// close first.
	l.trackers.close()
	if l.blockQ != nil {
		l.blockQ.close()
		l.blockQ = nil
	}

	// reload.
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
	err = l.blockDBs.rdb.Atomic(func(tx *sql.Tx) error {
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

// initLedgerDB performs DB initialization:
// - creates and populates it with genesis blocks
// - ensures DB is in good shape for archival mode and resets it if not
// - does nothing if everything looks good
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
	// then, we shut down the trackers and their corresponding goroutines.
	l.trackers.close()

	// last, we close the underlaying database connections.
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
	return l.accts.getLastCatchpointLabel()
}

// GetAssetCreatorForRound looks up the asset creator given the numerical asset
// ID. This is necessary so that we can retrieve the AssetParams from the
// creator's balance record.
func (l *Ledger) GetAssetCreatorForRound(rnd basics.Round, assetIdx basics.AssetIndex) (basics.Address, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.getAssetCreatorForRound(rnd, assetIdx)
}

// GetAssetCreator is like GetAssetCreatorForRound, but for the latest round
// and race free with respect to ledger.Latest()
func (l *Ledger) GetAssetCreator(assetIdx basics.AssetIndex) (basics.Address, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.getAssetCreatorForRound(l.blockQ.latest(), assetIdx)
}

// ListAssets takes a maximum asset index and maximum result length, and
// returns up to that many asset AssetIDs from the database where asset id is
// less than or equal to the maximum.
func (l *Ledger) ListAssets(maxAssetIdx basics.AssetIndex, maxResults uint64) (results []basics.CreatableLocator, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.listAssets(maxAssetIdx, maxResults)
}

// Lookup uses the accounts tracker to return the account state for a
// given account in a particular round.  The account values reflect
// the changes of all blocks up to and including rnd.
func (l *Ledger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	// Intentionally apply (pending) rewards up to rnd.
	data, err := l.accts.lookup(rnd, addr, true)
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// LookupWithoutRewards is like Lookup but does not apply pending rewards up
// to the requested round rnd.
func (l *Ledger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	data, err := l.accts.lookup(rnd, addr, false)
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// Totals returns the totals of all accounts at the end of round rnd.
func (l *Ledger) Totals(rnd basics.Round) (AccountTotals, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.totals(rnd)
}

func (l *Ledger) isDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txTail.isDup(currentProto, current, firstValid, lastValid, txid, txl)
}

// GetRoundTxIds returns a map of the transactions ids that we have for the given round
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

	updates, err := l.eval(context.Background(), blk, false, nil, nil)
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

// GetCatchpointCatchupState returns the current state of the catchpoint catchup.
func (l *Ledger) GetCatchpointCatchupState(ctx context.Context) (state CatchpointCatchupState, err error) {
	return MakeCatchpointCatchupAccessor(l, l.log).GetState(ctx)
}

// GetCatchpointStream returns an io.ReadCloser file stream from which the catchpoint file
// for the provided round could be retrieved. If no such stream can be generated, a non-nil
// error is returned. The io.ReadCloser and the error are mutually exclusive -
// if error is returned, the file stream is gurenteed to be nil, and vice versa,
// if the file stream is not nil, the error is gurenteed to be nil.
func (l *Ledger) GetCatchpointStream(round basics.Round) (io.ReadCloser, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.getCatchpointStream(round)
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

func (l *Ledger) trackerEvalVerified(blk bookkeeping.Block) (StateDelta, error) {
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.
	delta, err := l.eval(context.Background(), blk, false, nil, nil)
	return delta, err
}

// A txlease is a transaction (sender, lease) pair which uniquely specifies a
// transaction lease.
type txlease struct {
	sender basics.Address
	lease  [32]byte
}
