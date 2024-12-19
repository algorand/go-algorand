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

package stateproof

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// This is a soft limit on how many provers should be kept in memory, the rest shall be fetched from DB.
// At most times only 1 should prover should be stored (both in memory and on disk), as this feature
// is mostly used for recoverability purposes - in case the StateProof chain is stalled.
// The provers cache is composed of the X earliest provers as well as the latest prover, for a total of X+1 (in case of stalled chain).
const proversCacheLength = 5 // must be at least 2 to function properly (earliest stateproof + latest stateproof)

// Worker builds state proofs, by broadcasting
// signatures using this node's participation keys, by collecting
// signatures sent by others, and by sending out the resulting
// state proof in a transaction.
type Worker struct {
	// The mutex serializes concurrent message handler invocations
	// from the network stack.
	mu deadlock.Mutex

	spDbFileName string
	db           db.Accessor
	log          logging.Logger
	accts        Accounts
	ledger       Ledger
	net          Network
	txnSender    TransactionSender

	// provers is indexed by the round of the block being signed.
	provers map[basics.Round]spProver

	ctx      context.Context
	shutdown context.CancelFunc
	wg       sync.WaitGroup

	// Mutex for protecting access to the signed field
	signedMu deadlock.RWMutex
	signed   basics.Round
	signedCh chan struct{}

	lastCleanupRound basics.Round

	// inMemory indicates whether the state proof db should in memory. used for testing.
	inMemory bool
}

// NewWorker constructs a new Worker, as used by the node.
func NewWorker(genesisDir string, log logging.Logger, accts Accounts, ledger Ledger, net Network, txnSender TransactionSender) *Worker {
	// Delete the deprecated database file if it exists. This can be removed in future updates since this file should not exist by then.
	oldCompactCertPath := filepath.Join(genesisDir, "compactcert.sqlite")
	os.Remove(oldCompactCertPath)

	stateProofPathname := filepath.Join(genesisDir, config.StateProofFileName)

	return &Worker{
		spDbFileName: stateProofPathname,
		log:          log,
		accts:        accts,
		ledger:       ledger,
		net:          net,
		txnSender:    txnSender,
		inMemory:     false,
	}
}

// Start starts the goroutines for the worker.
func (spw *Worker) Start() {
	spw.ctx, spw.shutdown = context.WithCancel(context.Background())
	spw.signedCh = make(chan struct{}, 1)

	err := spw.initDb(spw.inMemory)
	if err != nil {
		spw.log.Warn(err)
		return
	}

	spw.initProvers()

	spw.ledger.RegisterVotersCommitListener(spw)

	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.StateProofSigTag, MessageHandler: network.HandlerFunc(spw.handleSigMessage)},
	}
	spw.net.RegisterHandlers(handlers)

	latest := spw.ledger.Latest()

	spw.wg.Add(1)
	go spw.signer(latest)

	spw.wg.Add(1)
	go spw.builder(latest)
}

func (spw *Worker) initDb(inMemory bool) error {
	stateProofAccess, err := db.MakeAccessor(spw.spDbFileName, false, inMemory)
	if err != nil {
		return fmt.Errorf("spw.initDb(): cannot load state proof data: %w", err)

	}

	spw.db = stateProofAccess
	err = makeStateProofDB(spw.db)
	if err != nil {
		return fmt.Errorf("spw.initDb(): makeStateProofDB failed: %w", err)
	}
	return nil
}

// Stop stops any goroutines associated with this worker. It is the caller responsibility to remove the register
// network handlers
func (spw *Worker) Stop() {
	spw.log.Debug("stateproof worker is stopping")
	defer spw.log.Debug("stateproof worker has stopped")

	spw.shutdown()
	spw.wg.Wait()

	spw.ledger.UnregisterVotersCommitListener()

	// we take the lock in case the network handler currently running handleSig
	spw.mu.Lock()
	defer spw.mu.Unlock()

	spw.provers = nil
	spw.signedCh = nil

	if spw.db.Handle != nil {
		spw.db.Close()
	}
}

// SortAddress implements sorting by Address keys for
// canonical encoding of maps in msgpack format.
//
//msgp:sort basics.Address SortAddress
type SortAddress = basics.SortAddress

// Address is required for the msgpack sort binding, since it looks for Address and not basics.Address
type Address = basics.Address
