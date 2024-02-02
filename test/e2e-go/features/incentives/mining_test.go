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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const roundTime = 4 * time.Second

// TestBasicMining shows proposers getting paid
func TestBasicMining(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a single network
	// Show that a genesis account does not get incentives
	// rereg to become eligible
	// show incentives are paid (mining and bonuses)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	richAccount, err := fixture.GetRichestAccount()
	a.NoError(err)

	// wait for richAccount to have LastProposed != 0
	account, err := client.AccountData(richAccount.Address)
	fmt.Printf(" rich balance %v %d\n", richAccount.Address, account.MicroAlgos)
	for account.LastProposed == 0 {
		a.NoError(err)
		a.Equal(basics.Online, account.Status)
		account, err = client.AccountData(richAccount.Address)
		time.Sleep(roundTime)
	}
	a.NoError(err)

	// we make an _offline_ tx here, because we want to populate the key
	// material ourself, by copying the account's existing state. That makes it
	// an _online_ keyreg. That allows the running node to chug along without
	// new part keys. We overpay the fee, just to get some funds into FeeSink
	// because we will watch it drain toward bottom of test.
	reReg, err := client.MakeUnsignedGoOfflineTx(richAccount.Address, 0, 0, 12_000_000, [32]byte{})
	require.NoError(t, err, "should be able to make tx")

	reReg.KeyregTxnFields = transactions.KeyregTxnFields{
		VotePK:          account.VoteID,
		SelectionPK:     account.SelectionID,
		StateProofPK:    account.StateProofID,
		VoteFirst:       account.VoteFirstValid,
		VoteLast:        account.VoteLastValid,
		VoteKeyDilution: account.VoteKeyDilution,
	}

	wh, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err, "should be able to get unencrypted wallet handle")
	onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, reReg)
	require.NoError(t, err, "should be no errors when going online")
	fixture.WaitForConfirmedTxn(uint64(reReg.LastValid), onlineTxID)

	account, err = client.AccountData(richAccount.Address)
	a.NoError(err)
	a.True(account.IncentiveEligible)
	// wait for richAccount to propose again, earns nothing (too much balance)
	proposed := account.LastProposed
	priorBalance := account.MicroAlgos
	for account.LastProposed == proposed {
		a.NoError(err)
		account, err = client.AccountData(richAccount.Address)
		a.NoError(err)
		time.Sleep(roundTime)
	}

	// incentives would pay out in the next round (they won't here, but makes the test realistic)
	fixture.WaitForRound(uint64(account.LastProposed+1), roundTime)
	account, err = client.AccountData(richAccount.Address)
	a.NoError(err)
	a.Equal(priorBalance, account.MicroAlgos)

	// Unload some algos, so we become incentive eligible
	burn := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	target := basics.Algos(1_000_000) // Assumes 1M algos is eligible
	diff, _ := basics.OSubA(account.MicroAlgos, target)
	fmt.Printf(" rich pays out %d + fee\n", diff.Raw)
	tx, err := client.SendPaymentFromUnencryptedWallet(richAccount.Address, burn, 0, diff.Raw, nil)
	a.NoError(err)
	status, err := client.Status()
	a.NoError(err)
	info, err := fixture.WaitForConfirmedTxn(status.LastRound+10, tx.ID().String())
	a.NoError(err)

	// Figure out whether rich account was proposer of its own payment
	blockProposer := func(r uint64) string {
		block, err := client.Block(r)
		a.NoError(err)
		return block.Block["prp"].(string)
	}

	// allow the incentive payment to happen
	err = fixture.WaitForRound(*info.ConfirmedRound+1, roundTime)
	a.NoError(err)
	// check that rich account got paid (or didn't) based on whether it proposed
	if blockProposer(*info.ConfirmedRound) == richAccount.Address {
		// should earn the block bonus
		target, _ = basics.OAddA(target, basics.Algos(5))
		// and only spent 25% of fee, since we earned 75% back
		target, _ = basics.OAddA(target, basics.MicroAlgos{Raw: 750})
	}
	// undershot 1M because of fee
	target, _ = basics.OSubA(target, basics.MicroAlgos{Raw: 1000})
	account, err = client.AccountData(richAccount.Address)
	a.NoError(err)
	a.Equal(target, account.MicroAlgos)

	proposed = account.LastProposed
	priorBalance = account.MicroAlgos
	// wait for richAccount to propose following its payment to become eligible
	r := *info.ConfirmedRound + 1
	for blockProposer(r) != richAccount.Address {
		r++
		err = fixture.WaitForRound(r, roundTime)
		a.NoError(err)
		a.Less(r, *info.ConfirmedRound+20) // avoid infinite loop if bug
	}
	account, err = client.AccountData(richAccount.Address)
	a.NoError(err)
	fmt.Printf(" rich balance after eligible proposal %d\n", account.MicroAlgos)
	// incentives pay out in the next round
	err = fixture.WaitForRound(r+1, roundTime)
	a.NoError(err)
	account, err = client.AccountData(richAccount.Address)
	a.NoError(err)
	fmt.Printf(" rich balance after eligible payout %d\n", account.MicroAlgos)
	// Should have earned 5A
	target, _ = basics.OAddA(target, basics.Algos(5))
	a.Equal(target, account.MicroAlgos)

	// Now that we've proven incentives get paid, let's drain the FeeSink and
	// ensure it happens gracefully.
	block, err := client.Block(r + 1)
	a.NoError(err)
	feesink := block.Block["fees"].(string)
	status, err = client.Status()
	a.NoError(err)
	for i := uint64(0); i < 10; i++ {
		err = fixture.WaitForRound(status.LastRound+i, roundTime)
		a.NoError(err)
		account, err = client.AccountData(feesink)
		a.NoError(err)
	}
	a.EqualValues(100000, account.MicroAlgos.Raw) // won't go below minfee
}
