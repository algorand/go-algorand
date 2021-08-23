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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// main wraps up some TEAL source in a header and footer so that it is
// an app that does nothing at create time, but otherwise run source,
// then approves, assuming that the source did not panic and left the
// stack empty.
func main(source string) string {
	return fmt.Sprintf(`txn ApplicationID
            bz end
            %s
       end: int 1`, source)
}

// Test that a pay in teal affects balances
func TestPayAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	create := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         tx_begin
         int pay
         tx_field TypeEnum
         int 5000
         tx_field Amount
         txn Accounts 1
         tx_field Receiver
         tx_submit
`),
	}

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: basics.AppIndex(1).Address(),
		Amount:   200000, // account min balance, plus fees
	}

	payout1 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: basics.AppIndex(1),
		Accounts:      []basics.Address{addrs[1]}, // pay self
	}

	eval := l.nextBlock(t)
	eval.txns(t, &create, &fund, &payout1)
	l.endBlock(t, eval)

	ad0 := l.lookup(t, addrs[0])
	ad1 := l.lookup(t, addrs[1])
	app := l.lookup(t, basics.AppIndex(1).Address())

	// create(1000) and fund(1000 + 200000)
	require.Equal(t, uint64(202000), genBalances.Balances[addrs[0]].MicroAlgos.Raw-ad0.MicroAlgos.Raw)
	// paid 5000, but 1000 fee
	require.Equal(t, uint64(4000), ad1.MicroAlgos.Raw-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
	// app still has 194000 (paid out 5000, and paid fee to do it)
	require.Equal(t, uint64(194000), app.MicroAlgos.Raw)

	// Build up Residue in RewardsState so it's ready to pay
	for i := 1; i < 10; i++ {
		eval = l.nextBlock(t)
		l.endBlock(t, eval)
	}

	eval = l.nextBlock(t)
	payout2 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: basics.AppIndex(1),
		Accounts:      []basics.Address{addrs[2]}, // pay other
	}
	eval.txn(t, &payout2)
	l.endBlock(t, eval)

	payInBlock := eval.block.Payset[0]
	rewards := payInBlock.ApplyData.SenderRewards.Raw
	t.Logf("%+v", payInBlock.ApplyData)
	require.Greater(t, rewards, uint64(2000)) // some biggish number

	// refresh balances
	ad1 = l.lookup(t, addrs[1])
	app = l.lookup(t, basics.AppIndex(1).Address())

	// paid 10000, but 2000 fee
	require.Equal(t, rewards+8000, ad1.MicroAlgos.Raw-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
	// app still has 188000 (paid out 10000, and paid 2k fees to do it)
	// why no rewards?
	require.Equal(t, uint64(200000)-10000-2000, app.MicroAlgos.Raw)
}
