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

package ledger

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTxTailCheckdup(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := ledgertesting.RandomAccounts(10, false)
	ledger := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, []map[basics.Address]basics.AccountData{accts})
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tail := txTail{}
	require.NoError(t, tail.loadFromDisk(ledger, 0))

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
			Payset: make(transactions.Payset, 1),
		}

		txids := make(map[transactions.Txid]ledgercore.IncludedTransactions, 1)
		blk.Payset[0].Txn.Note = []byte{byte(rnd % 256), byte(rnd / 256), byte(1)}
		txids[blk.Payset[0].Txn.ID()] = ledgercore.IncludedTransactions{LastValid: rnd + txvalidity, TransactionIndex: 0}
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
		Txn := transactions.Transaction{
			Header: transactions.Header{
				Note: []byte{byte(rnd % 256), byte(rnd / 256), byte(1)},
			},
		}
		err := tail.checkDup(proto, basics.Round(0), basics.Round(0), rnd+txvalidity, Txn.ID(), ledgercore.Txlease{})
		require.Errorf(t, err, "round %d", rnd)
		if rnd < lastRound-lookback-txvalidity-1 {
			var missingRoundErr *errTxTailMissingRound
			require.Truef(t, errors.As(err, &missingRoundErr), "error a errTxTailMissingRound(%d) : %v ", rnd, err)
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
			var missingRoundErr *errTxTailMissingRound
			require.Truef(t, errors.As(err, &missingRoundErr), "error a errTxTailMissingRound(%d) : %v ", rnd, err)
		} else {
			var leaseInLedgerErr *ledgercore.LeaseInLedgerError
			require.Truef(t, errors.As(err, &leaseInLedgerErr), "error a LeaseInLedgerError(%d) : %v ", rnd, err)
		}
	}
}

type txTailTestLedger struct {
	Ledger
	protoVersion protocol.ConsensusVersion
}

const testTxTailValidityRange = 200
const testTxTailTxnPerRound = 150

func (t *txTailTestLedger) Latest() basics.Round {
	return basics.Round(config.Consensus[t.protoVersion].MaxTxnLife + 10)
}

func (t *txTailTestLedger) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: t.protoVersion,
		},
	}, nil
}

func (t *txTailTestLedger) Block(r basics.Round) (bookkeeping.Block, error) {
	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: t.protoVersion,
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

func (t *txTailTestLedger) initialize(ts *testing.T, protoVersion protocol.ConsensusVersion) error {
	// create a corresponding blockdb.
	inMemory := true
	t.blockDBs, _ = dbOpenTest(ts, inMemory)
	t.trackerDBs, _ = dbOpenTest(ts, inMemory)
	t.protoVersion = protoVersion

	tx, err := t.trackerDBs.Wdb.Handle.Begin()
	require.NoError(ts, err)

	accts := ledgertesting.RandomAccounts(20, true)
	proto := config.Consensus[protoVersion]
	newDB := accountsInitTest(ts, tx, accts, protoVersion)
	require.True(ts, newDB)
	_, err = accountsInit(tx, accts, proto)
	require.NoError(ts, err)

	roundData := make([][]byte, 0, proto.MaxTxnLife)
	startRound := t.Latest() - basics.Round(proto.MaxTxnLife) + 1
	for i := startRound; i <= t.Latest(); i++ {
		blk, err := t.Block(i)
		require.NoError(ts, err)
		tail, err := txTailRoundFromBlock(blk)
		require.NoError(ts, err)
		encoded, _ := tail.encode()
		roundData = append(roundData, encoded)
	}
	fmt.Printf("%d\n", len(roundData))
	err = txtailNewRound(context.Background(), tx, startRound, roundData, 0)
	require.NoError(ts, err)
	tx.Commit()
	return nil
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
	partitiontest.PartitionTest(t)
	var ledger txTailTestLedger
	txtail := txTail{}
	require.NoError(t, ledger.initialize(t, protocol.ConsensusCurrentVersion))

	err := txtail.loadFromDisk(&ledger, ledger.Latest())
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
				require.Equal(t, &errTxTailMissingRound{round: txn.Txn.LastValid}, dupResult)
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
				require.Equal(t, &errTxTailMissingRound{round: txn.Txn.LastValid}, dupResult)
			}
		}
	}
}

func TestTxTailDeltaTracking(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, protoVersion := range []protocol.ConsensusVersion{protocol.ConsensusV32, protocol.ConsensusFuture} {
		t.Run(string(protoVersion), func(t *testing.T) {

			var ledger txTailTestLedger
			txtail := txTail{}
			require.NoError(t, ledger.initialize(t, protoVersion))

			err := txtail.loadFromDisk(&ledger, ledger.Latest())
			require.NoError(t, err)
			fmt.Printf("%d, %s\n", len(txtail.recent), protoVersion)
			require.Equal(t, int(config.Consensus[protoVersion].MaxTxnLife), len(txtail.recent))
			require.Equal(t, testTxTailValidityRange, len(txtail.lastValid))
			require.Equal(t, ledger.Latest(), txtail.lowWaterMark)

			var lease [32]byte
			for i := int(ledger.Latest()) + 1; i < int(config.Consensus[protoVersion].MaxTxnLife)*3; i++ {
				blk := bookkeeping.Block{
					BlockHeader: bookkeeping.BlockHeader{
						Round:     basics.Round(i),
						TimeStamp: int64(i << 10),
						UpgradeState: bookkeeping.UpgradeState{
							CurrentProtocol: protoVersion,
						},
					},
					Payset: make(transactions.Payset, 1),
				}
				sender := &basics.Address{}
				sender[0] = byte(i)
				sender[1] = byte(i >> 8)
				sender[2] = byte(i >> 16)
				blk.Payset[0].Txn.Sender = *sender
				blk.Payset[0].Txn.Lease = lease
				deltas := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 0, 0)
				deltas.Txids[blk.Payset[0].Txn.ID()] = ledgercore.IncludedTransactions{
					LastValid:        basics.Round(i + 50),
					TransactionIndex: 0,
				}
				deltas.Txleases[ledgercore.Txlease{Sender: blk.Payset[0].Txn.Sender, Lease: blk.Payset[0].Txn.Lease}] = basics.Round(i + 50)

				txtail.newBlock(blk, deltas)
				txtail.committedUpTo(basics.Round(i))
				dcc := &deferredCommitContext{
					deferredCommitRange: deferredCommitRange{
						oldBase:              basics.Round(i - 1),
						offset:               1,
						catchpointFirstStage: true,
					},
					newBase: basics.Round(i),
				}
				err = txtail.prepareCommit(dcc)
				require.NoError(t, err)

				tx, err := ledger.trackerDBs.Wdb.Handle.Begin()
				require.NoError(t, err)

				err = txtail.commitRound(context.Background(), tx, dcc)
				require.NoError(t, err)
				tx.Commit()
				proto := config.Consensus[protoVersion]
				retainSize := proto.MaxTxnLife + proto.DeeperBlockHeaderHistory
				if uint64(i) > proto.MaxTxnLife*2 {
					// validate internal storage length.
					require.Equal(t, 1, len(txtail.roundTailSerializedDeltas))
					require.Equal(t, int(retainSize+1), len(txtail.blockHeaderData)) // retainSize + 1 in-memory delta
					if enableTxTailHashes {
						require.Equal(t, int(retainSize+1), len(txtail.roundTailHashes))
					}
				}
				txtail.postCommit(context.Background(), dcc)
				if uint64(i) > proto.MaxTxnLife*2 {
					// validate internal storage length.
					require.Zero(t, len(txtail.roundTailSerializedDeltas))
					require.Equal(t, int(retainSize), len(txtail.blockHeaderData))
					if enableTxTailHashes {
						require.Equal(t, int(retainSize), len(txtail.roundTailHashes))
					}
				}
			}
		})
	}
}

// BenchmarkTxTailBlockHeaderCache adds 2M random blocks by calling
// newBlock and postCommit on txTail tracker, and reports memory allocations
func BenchmarkTxTailBlockHeaderCache(b *testing.B) {
	const numBlocks = 2_000_000
	b.ReportAllocs()

	accts := ledgertesting.RandomAccounts(10, false)
	ledger := makeMockLedgerForTracker(b, true, 1, protocol.ConsensusCurrentVersion, []map[basics.Address]basics.AccountData{accts})
	tail := txTail{}
	require.NoError(b, tail.loadFromDisk(ledger, 0))

	dbRound := basics.Round(0)
	const lookback = 8
	for i := 1; i < numBlocks+1; i++ {
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round:     basics.Round(i),
				TimeStamp: int64(i << 10),
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: protocol.ConsensusCurrentVersion,
				},
			},
		}
		tail.newBlock(blk, ledgercore.StateDelta{})

		if i%10 == 0 || i == numBlocks {
			offset := uint64(i - int(dbRound) - lookback)
			dcc := &deferredCommitContext{
				deferredCommitRange: deferredCommitRange{
					offset:   offset,
					oldBase:  dbRound,
					lookback: lookback,
				},
				newBase: dbRound + basics.Round(offset),
			}
			err := tail.prepareCommit(dcc)
			require.NoError(b, err)
			tail.postCommit(context.Background(), dcc)
			dbRound = dcc.newBase
			require.Less(b, len(tail.blockHeaderData), 1001+10)
		}
	}
}
