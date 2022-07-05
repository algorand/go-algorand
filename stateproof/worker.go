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

package stateproof

import (
	"context"
	"database/sql"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type builder struct {
	*stateproof.Builder

	voters    *ledgercore.VotersForRound
	votersHdr bookkeeping.BlockHeader
	message   stateproofmsg.Message
}

// Worker builds state proofs, by broadcasting
// signatures using this node's participation keys, by collecting
// signatures sent by others, and by sending out the resulting
// state proof in a transaction.
type Worker struct {
	// The mutex serializes concurrent message handler invocations
	// from the network stack.
	mu deadlock.Mutex

	db        db.Accessor
	log       logging.Logger
	accts     Accounts
	ledger    Ledger
	net       Network
	txnSender TransactionSender

	// builders is indexed by the round of the block being signed.
	builders map[basics.Round]builder

	ctx      context.Context
	shutdown context.CancelFunc
	wg       sync.WaitGroup

	signed   basics.Round
	signedCh chan struct{}
}

// NewWorker constructs a new Worker, as used by the node.
func NewWorker(db db.Accessor, log logging.Logger, accts Accounts, ledger Ledger, net Network, txnSender TransactionSender) *Worker {
	ctx, cancel := context.WithCancel(context.Background())

	return &Worker{
		db:        db,
		log:       log,
		accts:     accts,
		ledger:    ledger,
		net:       net,
		txnSender: txnSender,
		builders:  make(map[basics.Round]builder),
		ctx:       ctx,
		shutdown:  cancel,
		signedCh:  make(chan struct{}, 1),
	}
}

// Start starts the goroutines for the worker.
func (spw *Worker) Start() {
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return initDB(tx)
	})
	if err != nil {
		spw.log.Warnf("spw.Start(): initDB: %v", err)
		return
	}

	spw.initBuilders()

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

// Shutdown stops any goroutines associated with this worker.
func (spw *Worker) Shutdown() {
	spw.shutdown()
	spw.wg.Wait()
	spw.db.Close()
}
