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

// first bonus payout, set in config/consensus.go
const bonus1 = 10_000_000

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
		fmt.Printf("Client %s is %v\n", name, accounts[0].Address)
		return c, accounts[0]
	}

	c15, account15 := clientAndAccount("Node15")
	c01, account01 := clientAndAccount("Node01")
	relay, _ := clientAndAccount("Relay")

	data01 := rekeyreg(&fixture, a, c01, account01.Address)
	data15 := rekeyreg(&fixture, a, c15, account15.Address)

	// have account01 burn some money to get below the eligibility cap
	// Starts with 100M, so burn 60M and get under 70M cap.
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

		fmt.Printf("block %d proposed by %v\n", status.LastRound, block.Proposer())
		a.Zero(block.ProposerPayout()) // nobody is eligible yet (hasn't worked back to balance round)
		a.EqualValues(bonus1, block.Bonus.Raw)

		// all nodes agree the proposer proposed. The paranoia here is
		// justified. Block incentives are the first time we're making changes
		// to the Delta in the "second" evaluation of the block.  That is, the
		// payment and LastProposed change happen only if evaluating a block
		// that `agreement` has already added to.  An easy bug to have is an
		// optimization that avoids this re-evaluation in the algod that
		// proposed the block.  We had such an optimization, and it would cause
		// failures here.  The fix is throwing away the ValidatedBlock in
		// proposalForBlock() after makeProposal.
		for i, c := range []libgoal.Client{c15, c01, relay} {
			fmt.Printf("checking block %v\n", block.Round())
			data, err := c.AccountData(block.Proposer().String())
			a.NoError(err)
			bb, err := c.BookkeepingBlock(status.LastRound)
			a.NoError(err)
			a.Equal(block.Proposer(), bb.Proposer())
			a.Equal(block.Round(), data.LastProposed, "client %d thinks %v", i, block.Proposer())
		}

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
		fixture.WaitForRoundWithTimeout(status.LastRound + 1)
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
		a.EqualValues(bonus1, block.Bonus.Raw)

		next, err := client.AccountData(block.Proposer().String())
		fmt.Printf(" proposer %v has %d after proposing round %d\n", block.Proposer(), next.MicroAlgos.Raw, status.LastRound)

		// all nodes agree the proposer proposed
		for i, c := range []libgoal.Client{c15, c01, relay} {
			data, err := c.AccountData(block.Proposer().String())
			a.NoError(err)
			a.Equal(block.Round(), data.LastProposed, i)
		}

		// 01 would get paid (because under balance cap) 15 would not
		switch block.Proposer().String() {
		case account01.Address:
			a.EqualValues(bonus1, block.ProposerPayout().Raw)
			a.EqualValues(data01.MicroAlgos.Raw+bonus1, next.MicroAlgos.Raw) // 01 earns
			proposed01 = true
			data01 = next
		case account15.Address:
			a.Zero(block.ProposerPayout())
			a.Equal(data15.MicroAlgos, next.MicroAlgos) // didn't earn
			data15 = next
			proposed15 = true
		default:
			a.Fail("bad proposer", "%v proposed", block.Proposer)
		}
		fixture.WaitForRoundWithTimeout(status.LastRound + 1)
	}

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

		a.EqualValues(bonus1, block.Bonus.Raw)

		data, err := client.AccountData(block.Proposer().String())
		a.NoError(err)
		fmt.Printf(" proposer %v has %d after proposing round %d\n", block.Proposer(), data.MicroAlgos.Raw, status.LastRound)

		pdata, err := c15.AccountData(block.Proposer().String())
		a.NoError(err)
		feesink := block.BlockHeader.FeeSink
		fdata, err := c15.AccountData(feesink.String())
		a.NoError(err)

		for _, c := range []libgoal.Client{c15, c01, relay} {
			data, err = c.AccountData(block.Proposer().String())
			a.NoError(err)
			a.Equal(block.Round(), data.LastProposed)
			a.Equal(pdata, data)

			data, err = c.AccountData(feesink.String())
			a.NoError(err)
			a.Equal(fdata, data)
		}
		a.LessOrEqual(100000, int(data.MicroAlgos.Raw)) // won't go below minfee
		if data.MicroAlgos.Raw == 100000 {
			break
		}
		a.Less(i, 32+20)
		err = fixture.WaitForRoundWithTimeout(status.LastRound + 1)
		a.NoError(err)
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
