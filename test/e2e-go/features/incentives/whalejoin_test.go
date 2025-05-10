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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestWhaleJoin shows a "whale" with more stake than is currently online can go
// online without immediate suspension.  This tests for a bug we had where we
// calcululated expected proposal interval using the _old_ totals, rather than
// the totals following the keyreg. So big joiner was being expected to propose
// in the same block it joined.
func TestWhaleJoin(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	// Make rounds shorter and seed lookback smaller, otherwise we need to wait
	// 320 slow rounds for particpation effects to matter.
	const lookback = 32
	fixture.FasterConsensus(protocol.ConsensusFuture, time.Second, lookback)
	fixture.Setup(t, filepath.Join("nettemplates", "Payouts.json"))
	defer fixture.Shutdown()

	// Overview of this test:
	// 1. Take wallet15 offline (but retain keys so can back online later)
	// 2. Have wallet01 spend almost all their algos
	// 3. Wait for balances to flow through "lookback"
	// 4. Rejoin wallet15 which will have way more stake that what is online.

	clientAndAccount := func(name string) (libgoal.Client, model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 1)
		t.Logf("Client %s is %v\n", name, accounts[0].Address)
		return c, accounts[0]
	}

	c15, account15 := clientAndAccount("Node15")
	c01, account01 := clientAndAccount("Node01")

	// 1. take wallet15 offline
	keys := offline(a, c15, account15.Address)

	// 2. c01 starts with 100M, so burn 99.9M to get total online stake down
	burn, err := c01.SendPaymentFromUnencryptedWallet(account01.Address, basics.Address{}.String(),
		1000, 99_900_000_000_000, nil)
	a.NoError(err)
	receipt, err := fixture.WaitForConfirmedTxn(burn.LastValid, burn.ID().String())
	a.NoError(err)

	// 3. Wait lookback rounds
	_, err = c01.WaitForRound(*receipt.ConfirmedRound + lookback)
	a.NoError(err)

	// 4. rejoin, with 1.5B against the paltry 100k that's currently online
	online(a, c15, account15.Address, keys)

	// 5. wait for agreement balances to kick in (another lookback's worth, plus some slack)
	_, err = c01.WaitForRound(*receipt.ConfirmedRound + 2*lookback + 5)
	a.NoError(err)

	data, err := c15.AccountData(account15.Address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)

	// even after being in the block to "get noticed"
	txn, err := c15.SendPaymentFromUnencryptedWallet(account15.Address, basics.Address{}.String(),
		1000, 1, nil)
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(txn.LastValid, txn.ID().String())
	a.NoError(err)
	data, err = c15.AccountData(account15.Address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)
}

// TestBigJoin shows that even though an account can't vote during the first 320
// rounds after joining, it is not marked absent because of that gap. This would
// be a problem for "biggish" accounts, that might already be absent after 320
// rounds of not voting.
func TestBigJoin(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	// We need lookback to be fairly long, so that we can have a node join with
	// 1/16 stake, and have lookback be long enough to risk absenteeism.
	const lookback = 164 // > 160, which is 10x the 1/16th's interval
	fixture.FasterConsensus(protocol.ConsensusFuture, time.Second/2, lookback)
	fixture.Setup(t, filepath.Join("nettemplates", "Payouts.json"))
	defer fixture.Shutdown()

	// Overview of this test:
	// 1. Take wallet01 offline (but retain keys so can back online later)
	// 2. Wait `lookback` rounds so it can't propose.
	// 3. Rejoin wallet01 which will now have 1/16 of the stake
	// 4. Wait 160 rounds and ensure node01 does not get knocked offline for being absent
	// 5. Wait the rest of lookback to ensure it _still_ does not get knock off.

	clientAndAccount := func(name string) (libgoal.Client, model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 1)
		t.Logf("Client %s is %v\n", name, accounts[0].Address)
		return c, accounts[0]
	}

	c01, account01 := clientAndAccount("Node01")

	// 1. take wallet01 offline
	keys := offline(a, c01, account01.Address)

	// 2. Wait lookback rounds
	wait(&fixture, a, lookback)

	// 4. rejoin, with 1/16 of total stake
	onRound := online(a, c01, account01.Address, keys)

	// 5. wait for enough rounds to pass, during which c01 can't vote, that is
	// could get knocked off.
	wait(&fixture, a, 161)
	data, err := c01.AccountData(account01.Address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)

	// 5a. just to be sure, do a zero pay to get it "noticed"
	zeroPay(a, c01, account01.Address)
	data, err = c01.AccountData(account01.Address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)

	// 6. Now wait until lookback after onRound (which should just be a couple
	// more rounds). Check again, to ensure that once c01 is _really_
	// online/voting, it is still safe for long enough to propose.
	a.NoError(fixture.WaitForRoundWithTimeout(onRound + lookback))
	data, err = c01.AccountData(account01.Address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)

	zeroPay(a, c01, account01.Address)
	data, err = c01.AccountData(account01.Address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)

	// The node _could_ have gotten lucky and propose in first couple rounds it
	// is allowed to propose, so this test is expected to be "flaky" in a
	// sense. It would pass about 1/8 of the time, even if we had the problem it
	// is looking for.
}

// TestBigIncrease shows when an incentive eligible account receives a lot of
// algos, they are not immediately suspended. We also check the details of the
// mechanism - that LastHeartbeat is incremented when such an account doubles
// its balance in a single pay.
func TestBigIncrease(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	const lookback = 32
	fixture.FasterConsensus(protocol.ConsensusFuture, time.Second/2, lookback)
	fixture.Setup(t, filepath.Join("nettemplates", "Payouts.json"))
	defer fixture.Shutdown()

	// Overview of this test:
	// 0. spend wallet01 down so it has a very small percent of stake
	// 1. rereg wallet01 so it is suspendable
	// 2. move almost all of wallet15's money to wallet01
	// 3. check that c1.LastHeart is set to 32 rounds later
	// 4. wait 40 rounds ensure c1 stays online

	clientAndAccount := func(name string) (libgoal.Client, model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 1)
		t.Logf("Client %s is %v\n", name, accounts[0].Address)
		return c, accounts[0]
	}

	c1, account01 := clientAndAccount("Node01")
	c15, account15 := clientAndAccount("Node15")

	// We need to spend 01 down so that it has nearly no stake. That way, it
	// certainly will not have proposed by pure luck just before the critical
	// round. If we don't do that, 1/16 of stake is enough that it will probably
	// have a fairly recent proposal, and not get knocked off.
	pay(a, c1, account01.Address, account15.Address, 99*account01.Amount/100)

	rekeyreg(a, c1, account01.Address, true)

	// 2. Wait lookback rounds
	wait(&fixture, a, lookback)

	tx := pay(a, c15, account15.Address, account01.Address, 50*account15.Amount/100)
	data, err := c15.AccountData(account01.Address)
	a.NoError(err)
	a.EqualValues(*tx.ConfirmedRound+lookback, data.LastHeartbeat)

	wait(&fixture, a, lookback+5)
	data, err = c15.AccountData(account01.Address)
	a.NoError(err)
	a.Equal(basics.Online, data.Status)
	a.True(data.IncentiveEligible)
}

func wait(f *fixtures.RestClientFixture, a *require.Assertions, count basics.Round) {
	res, err := f.AlgodClient.Status()
	a.NoError(err)
	round := res.LastRound + count
	a.NoError(f.WaitForRoundWithTimeout(round))
}

func pay(a *require.Assertions, c libgoal.Client,
	from string, to string, amount uint64) v2.PreEncodedTxInfo {
	pay, err := c.SendPaymentFromUnencryptedWallet(from, to, 1000, amount, nil)
	a.NoError(err)
	tx, err := c.WaitForConfirmedTxn(pay.LastValid, pay.ID().String())
	a.NoError(err)
	return tx
}

func zeroPay(a *require.Assertions, c libgoal.Client, address string) {
	pay(a, c, address, address, 0)
}

// Go offline, but return the key material so it's easy to go back online
func offline(a *require.Assertions, client libgoal.Client, address string) transactions.KeyregTxnFields {
	offTx, err := client.MakeUnsignedGoOfflineTx(address, 0, 0, 100_000, [32]byte{})
	a.NoError(err)

	data, err := client.AccountData(address)
	a.NoError(err)
	keys := transactions.KeyregTxnFields{
		VotePK:          data.VoteID,
		SelectionPK:     data.SelectionID,
		StateProofPK:    data.StateProofID,
		VoteFirst:       data.VoteFirstValid,
		VoteLast:        data.VoteLastValid,
		VoteKeyDilution: data.VoteKeyDilution,
	}

	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, offTx)
	a.NoError(err)
	txn, err := client.WaitForConfirmedTxn(offTx.LastValid, onlineTxID)
	a.NoError(err)
	// sync up with the network
	_, err = client.WaitForRound(*txn.ConfirmedRound)
	a.NoError(err)
	data, err = client.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Offline, data.Status)
	return keys
}

// Go online with the supplied key material
func online(a *require.Assertions, client libgoal.Client, address string, keys transactions.KeyregTxnFields) basics.Round {
	// sanity check that we start offline
	data, err := client.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Offline, data.Status)

	// make an empty keyreg, we'll copy in the keys
	onTx, err := client.MakeUnsignedGoOfflineTx(address, 0, 0, 100_000, [32]byte{})
	a.NoError(err)

	onTx.KeyregTxnFields = keys
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, onTx)
	a.NoError(err)
	receipt, err := client.WaitForConfirmedTxn(onTx.LastValid, onlineTxID)
	a.NoError(err)
	data, err = client.AccountData(address)
	a.NoError(err)
	// Before bug fix, the account would be suspended in the same round of the
	// keyreg, so it would not be online.
	a.Equal(basics.Online, data.Status)
	return *receipt.ConfirmedRound
}
