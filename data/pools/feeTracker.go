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

package pools

import (
	"sort"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// feeTracker keeps track of the EWMA of the medians of the past 50 blocks

var (
	// lag value for the EWMA. (\alpha = frac{2}{1+L})
	decayValue float64
)

// FeeTracker keeps track of the fees on the ledger and provides suggested fee
type FeeTracker struct {
	mu   deadlock.Mutex
	ewma *EWMA
}

// MakeFeeTracker creates a new Fee Tracker
func MakeFeeTracker() (*FeeTracker, error) {
	ft := FeeTracker{}

	// init decay value
	decayValue = 2.0 / (1 + float64(config.GetDefaultLocal().SuggestedFeeSlidingWindowSize))

	ewma, err := NewEMA(decayValue)
	if err != nil {
		return nil, err
	}
	ft.ewma = ewma
	return &ft, nil
}

// EstimateFee returns the current suggested fee per byte
func (ft *FeeTracker) EstimateFee() basics.MicroAlgos {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	return basics.MicroAlgos{Raw: ft.ewma.Value()}
}

// ProcessBlock takes a block and update the current suggested fee
func (ft *FeeTracker) ProcessBlock(block bookkeeping.Block) {
	// If the block is less than half full, drive the suggested fee down rapidly. Suggested Fee may fall to zero, but algod API client will be responsible for submitting transactions with at least MinTxnFee
	if len(protocol.Encode(block.Payset)) < config.Consensus[block.CurrentProtocol].MaxTxnBytesPerBlock/2 {
		ft.add(1.0)
		return
	}

	// Get the median of the block
	payset, err := block.DecodePaysetFlat()
	if err != nil {
		return
	}

	fees := make([]float64, len(payset))
	for i, txad := range payset {
		tx := txad.SignedTxn
		fees[i] = ft.processTransaction(tx)
	}

	// Add median to EWMA
	ft.add(median(fees))
}

// add adds the given value to the ewma
func (ft *FeeTracker) add(n float64) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.ewma.Add(n)
}

// processTransaction takes a transaction and process it
func (ft *FeeTracker) processTransaction(txn transactions.SignedTxn) float64 {
	// return the fee per byte
	return float64(txn.Txn.Fee.Raw) / float64(txn.GetEncodedLength())
}

func median(input []float64) float64 {
	sort.Float64s(input)

	l := len(input)
	if l == 0 {
		return 0
	} else if l%2 == 0 {
		return (input[l/2-1] + input[l/2]) / 2
	}
	return input[l/2]
}
