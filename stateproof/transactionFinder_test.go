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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const stateProofIntervalTests = uint64(256)

type mockLedger struct {
	blocks []bookkeeping.Block
}

func newEmptyBlock(round basics.Round) bookkeeping.Block {
	var blk bookkeeping.Block
	blk.BlockHeader = bookkeeping.BlockHeader{
		Round: round,
	}

	return blk
}

func addStateProofInNeeded(blk bookkeeping.Block) bookkeeping.Block {
	round := uint64(blk.Round())
	if round%stateProofIntervalTests == (stateProofIntervalTests/2+18) && round > stateProofIntervalTests*2 {
		stateProofRound := (round - round%stateProofIntervalTests) - stateProofIntervalTests
		tx := transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type:   protocol.StateProofTx,
				Header: transactions.Header{Sender: transactions.StateProofSender},
				StateProofTxnFields: transactions.StateProofTxnFields{
					StateProofIntervalLatestRound: basics.Round(stateProofRound + stateProofIntervalTests),
					StateProofType:                0,
					Message: stateproofmsg.Message{
						BlockHeadersCommitment: []byte{0x0, 0x1, 0x2},
						FirstAttestedRound:     stateProofRound + 1,
						LastAttestedRound:      stateProofRound + stateProofIntervalTests,
					},
				},
			},
		}
		txnib := transactions.SignedTxnInBlock{SignedTxnWithAD: transactions.SignedTxnWithAD{SignedTxn: tx}}
		blk.Payset = append(blk.Payset, txnib)
	}

	return blk
}

func (m *mockLedger) AddressTxns(id basics.Address, r basics.Round) ([]transactions.SignedTxnWithAD, error) {
	blk := m.blocks[r]

	spec := transactions.SpecialAddresses{
		FeeSink:     blk.FeeSink,
		RewardsPool: blk.RewardsPool,
	}

	var res []transactions.SignedTxnWithAD

	for _, tx := range blk.Payset {
		if tx.Txn.MatchAddress(id, spec) {
			signedTxn := transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: tx.Txn}}
			res = append(res, signedTxn)
		}
	}
	return res, nil
}

func TestStateproofTransactionForRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ledger := mockLedger{blocks: make([]bookkeeping.Block, 0, 1000)}
	for i := 0; i < 1000; i++ {
		blk := newEmptyBlock(basics.Round(i))
		blk = addStateProofInNeeded(blk)
		ledger.blocks = append(ledger.blocks, blk)
	}

	txn, err := GetStateProofTransactionForRound(&ledger, basics.Round(stateProofIntervalTests*2+1), 1000)
	a.NoError(err)
	a.Equal(2*stateProofIntervalTests+1, txn.Message.FirstAttestedRound)
	a.Equal(3*stateProofIntervalTests, txn.Message.LastAttestedRound)
	a.Equal([]byte{0x0, 0x1, 0x2}, txn.Message.BlockHeadersCommitment)

	txn, err = GetStateProofTransactionForRound(&ledger, basics.Round(2*stateProofIntervalTests), 1000)
	a.NoError(err)
	a.Equal(stateProofIntervalTests+1, txn.Message.FirstAttestedRound)
	a.Equal(2*stateProofIntervalTests, txn.Message.LastAttestedRound)

	txn, err = GetStateProofTransactionForRound(&ledger, 999, 1000)
	a.ErrorIs(err, ErrNoStateProofForRound)

	txn, err = GetStateProofTransactionForRound(&ledger, basics.Round(2*stateProofIntervalTests), basics.Round(2*stateProofIntervalTests))
	a.ErrorIs(err, ErrNoStateProofForRound)
}
