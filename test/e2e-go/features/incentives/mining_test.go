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

package suspension

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestBasicPayouts shows proposers getting paid
func TestBasicPayouts(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	// Make the seed lookback shorter, otherwise we need to wait 320 rounds to become IncentiveEligible.
	fixture.FasterConsensus(protocol.ConsensusFuture)
	fixture.Setup(t, filepath.Join("nettemplates", "Mining.json"))
	defer fixture.Shutdown()

	// Overview of this test:
	// rereg to become eligible (must pay extra fee)
	// show payouts are paid (from fees and bonuses)
	// deplete feesink to ensure it's graceful

	clientAndAccount := func(name string) (libgoal.Client, model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 1)
		return c, accounts[0]
	}

	c15, account15 := clientAndAccount("Node15")
	c01, account01 := clientAndAccount("Node01")

	data01 := rekeyreg(&fixture, a, c01, account01.Address)
	data15 := rekeyreg(&fixture, a, c15, account15.Address)

	// have account01 burn some money to get below to eligibility cap
	// Starts with 100M, so burn 60M and get under 50M cap.
	txn, err := c01.SendPaymentFromUnencryptedWallet(account01.Address, basics.Address{}.String(),
		1000, 60_000_000_000_000, nil)
	a.NoError(err)
	burn, err := fixture.WaitForConfirmedTxn(uint64(txn.LastValid), txn.ID().String())
	a.NoError(err)
	data01, err = c01.AccountData(account01.Address)
	a.NoError(err)

	// Go 31 rounds after the burn happened. During this time, incentive
	// eligibility is not in effect yet, so regardless of who proposes, they
	// won't earn anything.

	client := fixture.LibGoalClient
	status, err := client.Status()
	a.NoError(err)
	for status.LastRound < *burn.ConfirmedRound+31 {
		block, err := client.BookkeepingBlock(status.LastRound)
		a.NoError(err)

		fmt.Printf(" 1 block %d proposed by %v\n", status.LastRound, block.Proposer())
		a.Zero(block.ProposerPayout()) // nobody is eligible yet (hasn't worked back to balance round)
		a.EqualValues(5_000_000, block.Bonus.Raw)
		fixture.WaitForRoundWithTimeout(status.LastRound + 1)

		// incentives would pay out in the next round (they won't here, but makes the test realistic)
		next, err := client.AccountData(block.Proposer().String())
		a.EqualValues(next.LastProposed, status.LastRound)
		// regardless of proposer, nobody gets paid
		switch block.Proposer().String() {
		case account01.Address:
			a.Equal(data01.MicroAlgos, next.MicroAlgos)
			data01 = next
		case account15.Address:
			a.Equal(data15.MicroAlgos, next.MicroAlgos)
			data15 = next
		default:
			a.Fail("bad proposer", "%v proposed", block.Proposer)
		}
		status, err = client.Status()
		a.NoError(err)
	}

	// Wait until each have proposed, so we can see that 01 gets paid and 15 does not (too much balance)
	proposed01 := false
	proposed15 := false
	for i := 0; !proposed01 || !proposed15; i++ {
		status, err := client.Status()
		a.NoError(err)
		block, err := client.BookkeepingBlock(status.LastRound)
		a.NoError(err)

		fmt.Printf(" 3 block %d proposed by %v\n", status.LastRound, block.Proposer())
		a.EqualValues(5_000_000, block.Bonus.Raw)

		// incentives would pay out in the next round so wait to see them
		fixture.WaitForRoundWithTimeout(status.LastRound + 1)
		next, err := client.AccountData(block.Proposer().String())
		fmt.Printf(" proposer %v has %d at round %d\n", block.Proposer(), next.MicroAlgos.Raw, status.LastRound)

		// 01 would get paid (because under balance cap) 15 would not
		switch block.Proposer().String() {
		case account01.Address:
			a.NotZero(block.ProposerPayout())
			a.NotEqual(data01.MicroAlgos, next.MicroAlgos)
			proposed01 = true
			data01 = next
		case account15.Address:
			a.Zero(block.ProposerPayout())
			a.Equal(data15.MicroAlgos, next.MicroAlgos)
			data15 = next
			proposed15 = true
		default:
			a.Fail("bad proposer", "%v proposed", block.Proposer)
		}
	}
	a.True(proposed15)
	a.True(proposed01) // There's some chance of this triggering flakily

	// Now that we've proven incentives get paid, let's drain the FeeSink and
	// ensure it happens gracefully.  Have account15 go offline so that (after
	// 32 rounds) only account01 is proposing. It is eligible and will drain the
	// fee sink.

	offline, err := c15.MakeUnsignedGoOfflineTx(account15.Address, 0, 0, 1000, [32]byte{})
	a.NoError(err)
	wh, err := c15.GetUnencryptedWalletHandle()
	a.NoError(err)
	_, err = c15.SignAndBroadcastTransaction(wh, nil, offline)
	a.NoError(err)

	for i := 0; i < 100; i++ {
		status, err := client.Status()
		a.NoError(err)
		block, err := client.BookkeepingBlock(status.LastRound)
		a.NoError(err)

		feesink := block.BlockHeader.FeeSink
		err = fixture.WaitForRoundWithTimeout(status.LastRound + 1)
		a.NoError(err)
		data, err := client.AccountData(feesink.String())
		a.NoError(err)
		fmt.Printf(" feesink has %d at round %d\n", data.MicroAlgos.Raw, status.LastRound)
		a.LessOrEqual(100000, int(data.MicroAlgos.Raw)) // won't go below minfee
		if data.MicroAlgos.Raw == 100000 {
			break
		}
		a.Less(i, 32+20)
	}
}

func rekeyreg(f *fixtures.RestClientFixture, a *require.Assertions, client libgoal.Client, address string) basics.AccountData {
	// we start by making an _offline_ tx here, because we want to populate the
	// key material ourself with a copy of the account's existing material. That
	// makes it an _online_ keyreg. That allows the running node to chug along
	// without new part keys. We overpay the fee, which makes us
	// IncentiveEligible, and to get some funds into FeeSink because we will
	// watch it drain toward bottom of test.
	reReg, err := client.MakeUnsignedGoOfflineTx(address, 0, 0, 12_000_000, [32]byte{})
	a.NoError(err)

	data, err := client.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status) // must already be online for this to work
	a.True(data.LastHeartbeat == 0)
	a.False(data.IncentiveEligible)
	reReg.KeyregTxnFields = transactions.KeyregTxnFields{
		VotePK:          data.VoteID,
		SelectionPK:     data.SelectionID,
		StateProofPK:    data.StateProofID,
		VoteFirst:       data.VoteFirstValid,
		VoteLast:        data.VoteLastValid,
		VoteKeyDilution: data.VoteKeyDilution,
	}

	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, reReg)
	a.NoError(err)
	txn, err := f.WaitForConfirmedTxn(uint64(reReg.LastValid), onlineTxID)
	a.NoError(err)
	data, err = client.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)
	a.True(data.LastHeartbeat > 0)
	a.True(data.IncentiveEligible)
	fmt.Printf(" %v has %v in round %d\n", address, data.MicroAlgos.Raw, *txn.ConfirmedRound)
	return data
}
