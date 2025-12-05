// Copyright (C) 2019-2025 Algorand, Inc.
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
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestLoad checks that hdr.Load is populated properly
func TestLoad(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	loadBegin := 42
	ledgertesting.TestConsensusRange(t, loadBegin, 0,
		func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
			genBalances, addrs, _ := ledgertesting.NewTestGenesis()
			dl := NewDoubleLedger(t, genBalances, cv, cfg)
			defer dl.Close()

			r := require.New(t)

			// Empty block should have 0 load
			vb := dl.fullBlock()
			r.Zero(vb.Block().BlockHeader.Load)

			// A pay should cause some load, construct with a note so we can
			// make two more in the next block that are exactly the same size
			// but different.
			vb = dl.fullBlock(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1_000_000,
				Note:     []byte("1")},
			)
			if ver < loadBegin {
				r.Zero(vb.Block().BlockHeader.Load)
				// before Load, no more tests
				return
			}
			onePayLoad := vb.Block().BlockHeader.Load
			r.Positive(onePayLoad)

			vb = dl.fullBlock(
				&txntest.Txn{
					Type:     "pay",
					Sender:   addrs[1],
					Receiver: addrs[0],
					Amount:   1_000_000,
					Note:     "2"},
				&txntest.Txn{
					Type:     "pay",
					Sender:   addrs[1],
					Receiver: addrs[0],
					Amount:   1_000_000,
					Note:     "3"},
			)
			twoPayLoad := vb.Block().BlockHeader.Load
			// Because of rounding, load might not be _exactly_ double
			r.InDelta(uint64(2*onePayLoad), uint64(twoPayLoad), 1)

			// And just for a little paranoia...
			vb = dl.fullBlock()
			r.Zero(vb.Block().BlockHeader.Load)
		})
}

// TestCongestion checks transactions must pay extra when load raises the base fee.
func TestCongestion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	loadBegin := 42
	ledgertesting.TestConsensusRange(t, loadBegin, 0,
		func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
			genBalances, addrs, _ := ledgertesting.NewTestGenesis()
			dl := NewDoubleLedger(t, genBalances, cv, cfg)
			defer dl.Close()

			r := require.New(t)

			vb := dl.fullBlock()
			r.Zero(vb.Block().BlockHeader.CongestionTax)

			// A pay should cause some load, construct with a note so we can
			// make two more in the next block that are exactly the same size
			// but different.
			vb = dl.fullBlock(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1_000_000,
				Lease:    ledgertesting.RandomAddress(),
				Note:     strings.Repeat("X", 1024),
			})
			if ver < loadBegin {
				r.Zero(vb.Block().BlockHeader.Load)
				// before Load, no more tests
				return
			}
			onePayLoad := vb.Block().BlockHeader.Load
			r.Positive(onePayLoad)
			txnsUnderCongestion := 490_000 / int(onePayLoad) // rounding prevents precision
			txnsOverCongestion := 510_000 / int(onePayLoad)

			manyPays := func(num int) *ledgercore.ValidatedBlock {
				dl.beginBlock()
				for range num {
					dl.txn(&txntest.Txn{
						Type:     "pay",
						Sender:   addrs[1],
						Receiver: addrs[0],
						Amount:   1_000_000,
						Lease:    ledgertesting.RandomAddress(),
						Note:     strings.Repeat("X", 1024),
					})
				}
				return dl.endBlock()
			}

			vb = manyPays(txnsUnderCongestion)
			// The error should be no more that 0.5 * #txns
			r.InDelta(490_000, uint64(vb.Block().BlockHeader.Load), 0.5*float64(txnsUnderCongestion))

			// Having a load under 500_000 does not raise the congestion fee
			vb = dl.fullBlock()
			r.Zero(vb.Block().BlockHeader.CongestionTax)

			vb = manyPays(txnsOverCongestion)
			// The error should be no more that 0.5 * #txns
			r.InDelta(510_000, uint64(vb.Block().BlockHeader.Load), 0.5*float64(txnsOverCongestion))

			// Having a load over 500_000 does raise it
			vb = dl.fullBlock()
			r.Positive(vb.Block().BlockHeader.CongestionTax)

			// But after another block with nothing, it's back to zero
			vb = dl.fullBlock()
			r.Zero(vb.Block().BlockHeader.CongestionTax)

			// Now, raise congestion again, and show effect of transaction
			// acceptance.
			vb = manyPays(txnsOverCongestion)
			// as we saw above, the next block is going to have a congestion tax after `manyPays`

			// There is no effect!  For now, evaluation doesn't care what the
			// congestion level is. Only the transactionPool ingress functions
			// checks that transactions have enough tip to pay for the
			// congestion tax.
			dl.txn(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1_000_000,
				Fee:      1_000,
			})

			// To be admitted, txns need a high enough tip to pay the tax.  This
			// shows that even if the tax is 0, a txn with a Tip needs to pay
			// it.
			vb = dl.fullBlock()
			r.Zero(vb.Block().BlockHeader.CongestionTax)

			dl.txn(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1_000_000,
				Fee:      1000,
				Tip:      100_000, //txn says it will tip, so the fee needs to be bigger
			}, "txgroup with 1mA fees is less")

			dl.txn(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1_000_000,
				Fee:      1000,
				Tip:      999, // tipping at less than 1/1000, so it rounds down
			})

			dl.txn(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1_000_000,
				Fee:      1000,
				Tip:      1000, // tipping at 1/1000, so it requires 1 extra uAlgo
			}, "txgroup with 1mA fees is less than 1.001mA")

			dl.txn(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1_000_000,
				Fee:      1100, // sufficient for the 10% tax
				Tip:      100_000,
			})
		})
}
