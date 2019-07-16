// Copyright (C) 2019 Algorand, Inc.
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
	// The default is archival mode; it can be changed by SetArchival().
	archival bool

	// genesisHash stores the genesis hash for this ledger.
	genesisHash crypto.Digest

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

// OpenLedger creates a Ledger object, using SQLite database filenames
// based on dbPathPrefix (in-memory if dbMem is true).  initBlocks and
// initAccounts specify the initial blocks and accounts to use if the
// database wasn't initialized before.
func OpenLedger(log logging.Logger, dbPathPrefix string, dbMem bool, initBlocks []bookkeeping.Block, initAccounts map[basics.Address]basics.AccountData, genesisHash crypto.Digest) (*Ledger, error) {
	var err error
	l := &Ledger{
		log:         log,
		archival:    true,
		genesisHash: genesisHash,
	}

	l.headerCache.maxEntries = 10

	defer func() {
		if err != nil {
			l.Close()
			if l.blockQ != nil {
				l.blockQ.close()
			}
		}
	}()

	// Backwards compatibility: we used to store both blocks and tracker
	// state in a single SQLite db file.
	var trackerDBFilename string
	var blockDBFilename string

	commonDBFilename := dbPathPrefix + ".sqlite"
	if !dbMem {
		_, err = os.Stat(commonDBFilename)
	}

	if !dbMem && os.IsNotExist(err) {
		// No common file, so use two separate files for blocks and tracker.
		trackerDBFilename = dbPathPrefix + ".tracker.sqlite"
		blockDBFilename = dbPathPrefix + ".block.sqlite"
	} else if err == nil {
		// Legacy common file exists (or testing in-memory, where performance
		// doesn't matter), use same database for everything.
		trackerDBFilename = commonDBFilename
		blockDBFilename = commonDBFilename
	} else {
		return nil, err
	}

	l.trackerDBs, err = dbOpen(trackerDBFilename, dbMem)
	if err != nil {
		return nil, err
	}

	l.blockDBs, err = dbOpen(blockDBFilename, dbMem)
	if err != nil {
		return nil, err
	}

	err = l.blockDBs.wdb.Atomic(func(tx *sql.Tx) error {
		return blockInit(tx, initBlocks)
	})
	if err != nil {
		return nil, err
	}

	l.blockQ, err = bqInit(l)
	if err != nil {
		return nil, err
	}

	// Accounts are special because they get an initialization argument (initAccounts).
	if initAccounts == nil {
		initAccounts = make(map[basics.Address]basics.AccountData)
	}

	if len(initBlocks) != 0 {
		// only needed if not initialized yet
		l.accts.initProto = config.Consensus[initBlocks[0].CurrentProtocol]
	}
	l.accts.initAccounts = initAccounts

	l.trackers.register(&l.accts)
	l.trackers.register(&l.txTail)
	l.trackers.register(&l.bulletin)
	l.trackers.register(&l.notifier)
	l.trackers.register(&l.time)
	l.trackers.register(&l.metrics)

	err = l.trackers.loadFromDisk(l)
	if err != nil {
		return nil, err
	}

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
		if params.SupportGenesisHash && hdr.GenesisHash != genesisHash {
			return fmt.Errorf("latest block %d genesis hash %v does not match expected genesis hash %v", latest, hdr.GenesisHash, genesisHash)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return l, nil
}

// Close reclaims resources used by the ledger (namely, the database connection
// and goroutines used by trackers).
func (l *Ledger) Close() {
	l.trackerDBs.close()
	l.blockDBs.close()
	l.trackers.close()
}

// SetArchival sets whether the ledger should operate in archival mode or not.
func (l *Ledger) SetArchival(a bool) {
	l.archival = a
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

func (l *Ledger) isDup(firstValid basics.Round, lastValid basics.Round, txid transactions.Txid) (bool, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txTail.isDup(firstValid, lastValid, txid)
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

// Committed uses the transaction tail tracker to check if txn already
// appeared in a block.
func (l *Ledger) Committed(txn transactions.SignedTxn) (bool, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txTail.isDup(txn.Txn.First(), l.Latest(), txn.ID())
}

func (l *Ledger) blockAux(rnd basics.Round) (bookkeeping.Block, evalAux, error) {
	return l.blockQ.getBlockAux(rnd)
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

// EncodedBlockCert returns the encoded block and the corresponding encodded certificate of the block for round rnd.
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
	updates, aux, err := l.eval(context.Background(), blk, nil, false, nil, nil)
	if err != nil {
		return err
	}

	vb := ValidatedBlock{
		blk:   blk,
		delta: updates,
		aux:   aux,
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

	err := l.blockQ.putBlock(vb.blk, cert, vb.aux)
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

// AllBalances returns a map of every account balance as of round rnd.
func (l *Ledger) AllBalances(rnd basics.Round) (map[basics.Address]basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.allBalances(rnd)
}

// GenesisHash returns the genesis hash for this ledger.
func (l *Ledger) GenesisHash() crypto.Digest {
	return l.genesisHash
}

// ledgerForTracker methods
func (l *Ledger) trackerDB() dbPair {
	return l.trackerDBs
}

func (l *Ledger) trackerLog() logging.Logger {
	return l.log
}

func (l *Ledger) trackerEvalVerified(blk bookkeeping.Block, aux evalAux) (stateDelta, error) {
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.
	delta, _, err := l.eval(context.Background(), blk, &aux, false, nil, nil)
	return delta, err
}
