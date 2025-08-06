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

package suspension

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
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
	const lookback = 32
	fixture.FasterConsensus(protocol.ConsensusFuture, time.Second, lookback)
	t.Logf("lookback is %d\n", lookback)
	fixture.Setup(t, filepath.Join("nettemplates", "Payouts.json"))
	defer fixture.Shutdown()

	// Overview of this test:
	// rereg to become eligible (must pay extra fee)
	// show payouts are paid (from fees and bonuses)
	// deplete feesink to ensure it's graceful
	addressToNode := make(map[string]string)
	clientAndAccount := func(name string) (libgoal.Client, model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 1)
		t.Logf("Client %s is %v\n", name, accounts[0].Address)
		addressToNode[accounts[0].Address] = name
		return c, accounts[0]
	}

	c15, account15 := clientAndAccount("Node15")
	c01, account01 := clientAndAccount("Node01")
	relay, _ := clientAndAccount("Relay")

	data01 := rekeyreg(a, c01, account01.Address, true)
	data15 := rekeyreg(a, c15, account15.Address, true)

	// Wait a few rounds after rekeyreg, this means that `lookback` rounds after
	// those rekeyregs, the nodes will be IncentiveEligible, but both will have
	// too much stake to earn rewards.  Then we'll burn from account01, so
	// lookback rounds after _that_ account01 will start earning.
	client := fixture.LibGoalClient
	status, err := client.Status()
	a.NoError(err)
	fixture.WaitForRoundWithTimeout(status.LastRound + 10)

	// have account01 burn some money to get below the eligibility cap
	// Starts with 100M, so burn 60M and get under 70M cap.
	txn, err := c01.SendPaymentFromUnencryptedWallet(account01.Address, basics.Address{}.String(),
		1000, 60_000_000_000_000, nil)
	a.NoError(err)
	burn, err := fixture.WaitForConfirmedTxn(txn.LastValid, txn.ID().String())
	a.NoError(err)
	burnRound := *burn.ConfirmedRound
	t.Logf("burn round is %d", burnRound)
	// sync up with the network
	_, err = c01.WaitForRound(burnRound)
	a.NoError(err)
	data01, err = c01.AccountData(account01.Address)
	a.NoError(err)

	// Start advancing. IncentiveEligibile will come into effect 32 rounds after
	// the rekeregs but earning will only happen 32 rounds after burnRound, and
	// only for account01 (the one that burned to get under the cap).
	status, err = client.Status()
	a.NoError(err)
	account1earned := false
	for !account1earned {
		block, err := client.BookkeepingBlock(status.LastRound)
		a.NoError(err)

		t.Logf("block %d proposed by %s %v\n",
			status.LastRound, addressToNode[block.Proposer().String()], block.Proposer())
		a.EqualValues(bonus1, block.Bonus.Raw)

		// all nodes agree the proposer proposed. The paranoia here is
		// justified. Block incentives are computed in two stages. A little bit
		// of extra work is done when agreement "Finishes" the block.  An easy
		// bug to have is using the block the Deltas() computed on the block
		// without the changes that come after agreement runs.  We had such an
		// optimization, and it would cause failures here.  Interface changes
		// made since they should make such a problem impossible, but...
		for i, c := range []libgoal.Client{c15, c01, relay} {
			t.Logf("checking block %v\n", block.Round())
			bb, err := getblock(c, status.LastRound)
			a.NoError(err)
			a.Equal(block.Proposer(), bb.Proposer())

			// check that the LastProposed for the proposer has been incremented
			data, err := c.AccountData(block.Proposer().String())
			a.NoError(err)
			// We use LOE instead of Equal because it's possible that by now
			// the proposer has proposed again!
			a.LessOrEqual(block.Round(), data.LastProposed, "client %d thinks %v", i, block.Proposer())
		}

		next, err := client.AccountData(block.Proposer().String())
		a.NoError(err)
		a.LessOrEqual(int(status.LastRound), int(next.LastProposed))
		switch block.Proposer().String() {
		case account01.Address:
			if block.Round() < burnRound+lookback {
				// until the burn is lookback rounds old, account01 can't earn
				a.Zero(block.ProposerPayout())
				a.Equal(data01.MicroAlgos, next.MicroAlgos)
			} else {
				a.EqualValues(bonus1, block.ProposerPayout().Raw)
				// We'd like to do test if account one got paid the bonus:
				// a.EqualValues(data01.MicroAlgos.Raw+bonus1, next.MicroAlgos.Raw)

				// But we can't because it might have already proposed again. So
				// let's check if it has received one OR two bonuses.
				earned := int(next.MicroAlgos.Raw - data01.MicroAlgos.Raw)
				a.True(earned == bonus1 || earned == 2*bonus1, "earned %d", earned)
				account1earned = true
			}
			data01 = next
		case account15.Address:
			a.Zero(block.ProposerPayout())
			a.Equal(data15.MicroAlgos, next.MicroAlgos)
			data15 = next
		default:
			a.Fail("bad proposer", "%v proposed", block.Proposer)
		}
		fixture.WaitForRoundWithTimeout(status.LastRound + 1)
		status, err = client.Status()
		a.NoError(err)
	}

	// Now that we've proven incentives get paid, let's drain the FeeSink and
	// ensure it happens gracefully.  Have account15 go offline so that (after
	// 32 rounds) only account01 (who is eligible) is proposing, so drainage
	// will happen soon after.

	offline, err := c15.MakeUnsignedGoOfflineTx(account15.Address, 0, 0, 1000, [32]byte{})
	a.NoError(err)
	wh, err := c15.GetUnencryptedWalletHandle()
	a.NoError(err)
	offlineTxID, err := c15.SignAndBroadcastTransaction(wh, nil, offline)
	a.NoError(err)
	offTxn, err := fixture.WaitForConfirmedTxn(offline.LastValid, offlineTxID)
	a.NoError(err)

	t.Logf(" c15 (%s) will be truly offline (not proposing) after round %d\n",
		account15.Address, *offTxn.ConfirmedRound+lookback)

	var feesink basics.Address
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
		feesink = block.BlockHeader.FeeSink
		fdata, err := c15.AccountData(feesink.String())
		a.NoError(err)

		for _, c := range []libgoal.Client{c15, c01, relay} {
			_, err := c.WaitForRound(status.LastRound)
			a.NoError(err)
			data, err = c.AccountData(block.Proposer().String())
			a.NoError(err)
			// <= in case one node is behind, and the others have already advanced
			a.LessOrEqual(block.Round(), data.LastProposed)
			// <= in case one node is behind, and the others have already advanced
			a.LessOrEqual(pdata.MicroAlgos.Raw, data.MicroAlgos.Raw)
			a.Equal(pdata.Status, data.Status)
			a.True(data.IncentiveEligible)

			data, err = c.AccountData(feesink.String())
			a.NoError(err)
			// >= in case one node is behind, and the others have already advanced
			a.GreaterOrEqual(fdata.MicroAlgos.Raw, data.MicroAlgos.Raw)
		}
		a.LessOrEqual(100000, int(data.MicroAlgos.Raw)) // won't go below minfee
		if data.MicroAlgos.Raw == 100000 {
			break
		}
		a.Less(i, int(lookback+20))
		err = fixture.WaitForRoundWithTimeout(status.LastRound + 1)
		a.NoError(err)
	}
	// maybe it got drained before c15 stops proposing. wait.
	err = fixture.WaitForRoundWithTimeout(*offTxn.ConfirmedRound + lookback)
	a.NoError(err)

	// put 50 algos back into the feesink, show it pays out again
	txn, err = c01.SendPaymentFromUnencryptedWallet(account01.Address, feesink.String(), 1000, 50_000_000, nil)
	a.NoError(err)
	refill, err := fixture.WaitForConfirmedTxn(txn.LastValid, txn.ID().String())
	fmt.Printf("refilled fee sink in %d\n", *refill.ConfirmedRound)
	a.NoError(err)
	block, err := client.BookkeepingBlock(*refill.ConfirmedRound)
	a.NoError(err)
	// 01 is the only one online, so it proposed the block
	require.Equal(t, account01.Address, block.Proposer().String())
	// and therefore feesink is already down to ~40
	data, err := relay.AccountData(feesink.String())
	a.NoError(err)
	a.Less(int(data.MicroAlgos.Raw), 41_000_000)
	a.Greater(int(data.MicroAlgos.Raw), 39_000_000)

	// Closeout c01.  This is pretty weird, it means nobody will be online.  But
	// that will take `lookback` rounds.  We will stop the test before then, we just
	// want to show that c01 does not get paid if it has closed.
	wh, err = c01.GetUnencryptedWalletHandle()
	a.NoError(err)
	junk := basics.Address{0x01, 0x01}.String()
	txn, err = c01.SendPaymentFromWallet(wh, nil, account01.Address, junk, 1000, 0, nil, junk /* close to */, 0, 0)
	a.NoError(err)
	close, err := fixture.WaitForConfirmedTxn(txn.LastValid, txn.ID().String())
	a.NoError(err)
	fmt.Printf("closed c01 in %d\n", *close.ConfirmedRound)
	block, err = client.BookkeepingBlock(*close.ConfirmedRound)
	a.NoError(err)
	// 01 is the only one online, so it proposed the block
	require.Equal(t, account01.Address, block.Proposer().String())

	// The feesink got was 0.1A, and got 50A in refill.ConfirmedRound. c01
	// closed out in close.ConfirmedRound. So the feesink should have about:
	expected := 100_000 + 1_000_000*(50-10*(*close.ConfirmedRound-*refill.ConfirmedRound))

	// account is gone anyway (it didn't get paid)
	data, err = relay.AccountData(account01.Address)
	a.NoError(err)
	a.Zero(data, "%+v", data)

	data, err = relay.AccountData(feesink.String())
	a.NoError(err)
	// Don't want to bother dealing with the exact fees paid in/out.
	a.Less(data.MicroAlgos.Raw, expected+5000)
	a.Greater(data.MicroAlgos.Raw, expected-5000)

	// Lest one be concerned about that cavalier attitude, wait for a few more
	// rounds, and show feesink is unchanged.
	a.NoError(fixture.WaitForRoundWithTimeout(*close.ConfirmedRound + 5))
	after, err := relay.AccountData(feesink.String())
	a.NoError(err)
	a.Equal(data.MicroAlgos, after.MicroAlgos)
}

// getblock waits for the given block because we use when we might be talking to
// a client that is behind the network (since it has low stake)
func getblock(client libgoal.Client, round basics.Round) (bookkeeping.Block, error) {
	if _, err := client.WaitForRound(round); err != nil {
		return bookkeeping.Block{}, err
	}
	return client.BookkeepingBlock(round)
}

func rekeyreg(a *require.Assertions, client libgoal.Client, address string, becomeEligible bool) basics.AccountData {
	// we start by making an _offline_ tx here, because we want to populate the
	// key material ourself with a copy of the account's existing material. That
	// makes it an _online_ keyreg. That allows the running node to chug along
	// without new part keys. We overpay the fee, which makes us
	// IncentiveEligible, and to get some funds into FeeSink because we will
	// watch it drain toward bottom of test.

	fee := uint64(1000)
	if becomeEligible {
		fee = 12_000_000
	}
	reReg, err := client.MakeUnsignedGoOfflineTx(address, 0, 0, fee, [32]byte{})
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
	txn, err := client.WaitForConfirmedTxn(reReg.LastValid, onlineTxID)
	a.NoError(err)
	// sync up with the network
	_, err = client.WaitForRound(*txn.ConfirmedRound)
	a.NoError(err)
	data, err = client.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)
	a.True(data.LastHeartbeat > 0)
	a.Equal(becomeEligible, data.IncentiveEligible)
	fmt.Printf(" %v has %v in round %d\n", address, data.MicroAlgos.Raw, *txn.ConfirmedRound)
	return data
}
