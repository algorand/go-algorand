// Copyright (C) 2019-2021 Algorand, Inc.
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

package indexer

import (
	"context"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
)

// Ledger interface to make testing easier
type Ledger interface {
	Block(rnd basics.Round) (blk bookkeeping.Block, err error)
	Wait(r basics.Round) chan struct{}
}

// Indexer keeps track of transactions and their senders
// to enable quick retrieval.
type Indexer struct {
	IDB *DB

	l Ledger

	ctx       context.Context
	cancelCtx context.CancelFunc
}

// MakeIndexer makes a new indexer.
func MakeIndexer(dataDir string, ledger Ledger, inMemory bool) (*Indexer, error) {
	orm, err := MakeIndexerDB(dataDir, inMemory)
	if err != nil {
		return &Indexer{}, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Indexer{
		IDB:       orm,
		l:         ledger,
		ctx:       ctx,
		cancelCtx: cancel,
	}, nil
}

// GetRoundByTXID takes a transactionID an returns its round number
func (idx *Indexer) GetRoundByTXID(txID string) (uint64, error) {
	txn, err := idx.IDB.GetTransactionByID(txID)
	if err != nil {
		return 0, err
	}
	return uint64(txn.Round), nil
}

// GetRoundsByAddressAndDate takes an address, date range and maximum number of txns to return , and returns all
// blocks that contain the relevant transaction. if top is 0, it defaults to 100.
func (idx *Indexer) GetRoundsByAddressAndDate(addr string, top uint64, from, to int64) ([]uint64, error) {
	rounds, err := idx.IDB.GetTransactionsRoundsByAddrAndDate(addr, top, from, to)
	if err != nil {
		return nil, err
	}
	return rounds, nil
}

// GetRoundsByAddress takes an address and the number of transactions to return
// and returns all blocks that contain transaction where the address was the
// sender or the receiver.
func (idx *Indexer) GetRoundsByAddress(addr string, top uint64) ([]uint64, error) {
	rounds, err := idx.IDB.GetTransactionsRoundsByAddr(addr, top)
	if err != nil {
		return nil, err
	}
	return rounds, nil
}

// NewBlock takes a block and updates the DB
// If the block exists, return nil.the block must be the next block
func (idx *Indexer) NewBlock(b bookkeeping.Block) error {
	// Get last block
	rnd, err := idx.LastBlock()
	if err != nil {
		return err
	}

	if b.Round() <= rnd {
		return nil
	}

	err = idx.IDB.AddBlock(b)
	if err != nil {
		return err
	}
	return nil
}

// Start starts the indexer
func (idx *Indexer) Start() error {
	round, err := idx.LastBlock()
	if err != nil {
		return err
	}

	go idx.update(round)

	return nil
}

func (idx *Indexer) update(round basics.Round) {
	for {
		select {
		// Wait on the block
		case <-idx.l.Wait(round + 1):
			b, err := idx.l.Block(round + 1)
			if err != nil {
				logging.Base().Errorf("failed fetching block %d, trying again in 0.5 seconds", round+1)
				time.Sleep(time.Millisecond * 500)
			} else {
				err = idx.NewBlock(b)
				if err != nil {
					logging.Base().Errorf("failed write block %d, trying again in 0.5 seconds", round+1)
					time.Sleep(time.Millisecond * 500)
				} else {
					round++
				}
			}

		case <-idx.ctx.Done():
			return
		}
	}
}

// LastBlock returns the last block the indexer is aware of
func (idx *Indexer) LastBlock() (basics.Round, error) {
	rnd, err := idx.IDB.MaxRound()
	if err != nil {
		return 0, err
	}
	return basics.Round(rnd), nil
}

// Shutdown closes the indexer
func (idx *Indexer) Shutdown() {
	idx.cancelCtx()
	idx.IDB.Close()
}
