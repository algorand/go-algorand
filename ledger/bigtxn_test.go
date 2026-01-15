// Copyright (C) 2019-2026 Algorand, Inc.
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
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

const (
	bigVersion = 42
)

// TestBigAppCreate tests that big apps can be made if appropriate fees are paid
func TestBigAppCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, bigVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		proto := config.Consensus[cv]

		// This make bytecode about ~3900 bytes long, and goings into Approval
		// and ClearState, so we're just under 8k, and requires no extra fee.
		dl.txn(&txntest.Txn{
			Fee:             proto.MinFee(),
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("pushint 1; return;\n", 1300),
		})

		// But now an extra fee is required, because 1400*3*2 > 8196
		dl.txn(&txntest.Txn{
			Fee:             proto.MinFee(),
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("pushint 1; return;\n", 1400),
		}, "txgroup with 1mA fees is less than")

		dl.txn(&txntest.Txn{
			Fee:             1_500, // ~200 bytes over limit, so about 1.2mA needed
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("pushint 1; return;\n", 1400),
		})

		// In fact, dl.txn() knows how to compute the fee, so if we leave it
		// empty, we can see what it sets it too.
		vb := dl.fullBlock(&txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: strings.Repeat("pushint 1; return;\n", 1400),
		})
		require.EqualValues(t, 1210, vb.Block().Payset[0].Txn.Fee.Raw)
	})
}

// TestBigAppCall tests that big apps can be called, but only if BoxRef used to
// increase read quota.
func TestBigAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, bigVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// proto := config.Consensus[cv]

		// createApp takes care of figuring out and setting the fee
		appID := dl.createApp(addrs[0], strings.Repeat("pushint 1; return;\n", 1400))

		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
		}
		dl.txn(&call)
	})
}
