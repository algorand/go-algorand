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

package ledger

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

func TestTxTailCheckdup(t *testing.T) {
	ledger := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tail := txTail{}
	require.NoError(t, tail.loadFromDisk(ledger))

	lastRound := basics.Round(proto.MaxTxnLife)
	lookback := basics.Round(100)
	txvalidity := basics.Round(10)
	leasevalidity := basics.Round(32)

	// push 1000 rounds into the txtail
	for rnd := basics.Round(1); rnd < lastRound; rnd++ {
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: rnd,
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: protocol.ConsensusCurrentVersion,
				},
			},
		}

		txids := make(map[transactions.Txid]basics.Round, 1)
		txids[transactions.Txid(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(1)}))] = rnd + txvalidity
		txleases := make(map[ledgercore.Txlease]basics.Round, 1)
		txleases[ledgercore.Txlease{Sender: basics.Address(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(2)})), Lease: crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(3)})}] = rnd + leasevalidity

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 1, 0)
		delta.Txids = txids
		delta.Txleases = txleases
		tail.newBlock(blk, delta)
		tail.committedUpTo(rnd.SubSaturate(lookback))
	}

	// test txid duplication testing.
	for rnd := basics.Round(1); rnd < lastRound; rnd++ {
		txid := transactions.Txid(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(1)}))
		err := tail.checkDup(proto, basics.Round(0), basics.Round(0), rnd+txvalidity, txid, ledgercore.Txlease{})
		require.Errorf(t, err, "round %d", rnd)
		if rnd < lastRound-lookback-txvalidity-1 {
			var missingRoundErr *txtailMissingRound
			require.Truef(t, errors.As(err, &missingRoundErr), "error a txtailMissingRound(%d) : %v ", rnd, err)
		} else {
			var txInLedgerErr *ledgercore.TransactionInLedgerError
			require.Truef(t, errors.As(err, &txInLedgerErr), "error a TransactionInLedgerError(%d) : %v ", rnd, err)
		}
	}

	// test lease detection
	for rnd := basics.Round(1); rnd < lastRound; rnd++ {
		lease := ledgercore.Txlease{Sender: basics.Address(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(2)})), Lease: crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(3)})}
		err := tail.checkDup(proto, rnd, basics.Round(0), rnd, transactions.Txid{}, lease)
		require.Errorf(t, err, "round %d", rnd)
		if rnd < lastRound-lookback-1 {
			var missingRoundErr *txtailMissingRound
			require.Truef(t, errors.As(err, &missingRoundErr), "error a txtailMissingRound(%d) : %v ", rnd, err)
		} else {
			var leaseInLedgerErr *ledgercore.LeaseInLedgerError
			require.Truef(t, errors.As(err, &leaseInLedgerErr), "error a LeaseInLedgerError(%d) : %v ", rnd, err)
		}
	}
}

type txTailTestLedger struct {
	Ledger
}

const testTxTailValidityRange = 200
const testTxTailTxnPerRound = 150

func (t *txTailTestLedger) Latest() basics.Round {
	return basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnLife + 10)
}

func (t *txTailTestLedger) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}, nil
}

func (t *txTailTestLedger) Block(r basics.Round) (bookkeeping.Block, error) {
	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
			Round: r,
		},
		Payset: make(transactions.Payset, testTxTailTxnPerRound),
	}
	for i := range blk.Payset {
		blk.Payset[i] = makeTxTailTestTransaction(r, i)
	}

	return blk, nil
}
func makeTxTailTestTransaction(r basics.Round, txnIdx int) (txn transactions.SignedTxnInBlock) {
	txn.Txn.FirstValid = r
	txn.Txn.LastValid = r + testTxTailValidityRange
	if txnIdx%5 == 0 {
		digest := crypto.Hash([]byte{byte(r), byte(r >> 8), byte(r >> 16), byte(r >> 24), byte(r >> 32), byte(r >> 40), byte(r >> 48), byte(r >> 56)})
		copy(txn.Txn.Lease[:], digest[:])
	}
	// use 7 different senders.
	sender := uint64((int(r) + txnIdx) % 7)
	senderDigest := crypto.Hash([]byte{byte(sender), byte(sender >> 8), byte(sender >> 16), byte(sender >> 24), byte(sender >> 32), byte(sender >> 40), byte(sender >> 48), byte(sender >> 56)})
	copy(txn.Txn.Sender[:], senderDigest[:])
	return txn
}

func TestTxTailLoadFromDisk(t *testing.T) {
	var ledger txTailTestLedger
	txtail := txTail{}

	err := txtail.loadFromDisk(&ledger)
	require.NoError(t, err)
	require.Equal(t, int(config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnLife), len(txtail.recent))
	require.Equal(t, testTxTailValidityRange, len(txtail.lastValid))
	require.Equal(t, ledger.Latest(), txtail.lowWaterMark)

	// do some fuzz testing for leases -
	for i := 0; i < 5000; i++ {
		r := basics.Round(crypto.RandUint64() % uint64(ledger.Latest()))
		txIdx := int(crypto.RandUint64() % uint64(len(txtail.recent)))
		txn := makeTxTailTestTransaction(r, txIdx)
		if txn.Txn.Lease != [32]byte{} {
			// transaction has a lease
			txl := ledgercore.Txlease{Sender: txn.Txn.Sender, Lease: txn.Txn.Lease}
			dupResult := txtail.checkDup(
				config.Consensus[protocol.ConsensusCurrentVersion], ledger.Latest(),
				txn.Txn.FirstValid, txn.Txn.LastValid, txn.Txn.ID(),
				txl)
			if r >= ledger.Latest()-testTxTailValidityRange {
				require.Equal(t, ledgercore.MakeLeaseInLedgerError(txn.Txn.ID(), txl), dupResult)
			} else {
				require.Equal(t, &txtailMissingRound{round: txn.Txn.LastValid}, dupResult)
			}
		} else {
			// transaction has no lease
			dupResult := txtail.checkDup(
				config.Consensus[protocol.ConsensusCurrentVersion], ledger.Latest(),
				txn.Txn.FirstValid, txn.Txn.LastValid, txn.Txn.ID(),
				ledgercore.Txlease{})
			if r >= ledger.Latest()-testTxTailValidityRange {
				if txn.Txn.LastValid > ledger.Latest() {
					require.Equal(t, &ledgercore.TransactionInLedgerError{Txid: txn.Txn.ID()}, dupResult)
				} else {
					require.Nil(t, dupResult)
				}
			} else {
				require.Equal(t, &txtailMissingRound{round: txn.Txn.LastValid}, dupResult)
			}
		}
	}
}
