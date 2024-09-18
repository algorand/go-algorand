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
// the totals following the keyreg. So big joiner could be expected to propose
// in the same block they joined.
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
		fmt.Printf("Client %s is %v\n", name, accounts[0].Address)
		return c, accounts[0]
	}

	c15, account15 := clientAndAccount("Node15")
	c01, account01 := clientAndAccount("Node01")

	// 1. take wallet15 offline
	keys := offline(&fixture, a, c15, account15.Address)

	// 2. c01 starts with 100M, so burn 99.9M to get total online stake down
	burn, err := c01.SendPaymentFromUnencryptedWallet(account01.Address, basics.Address{}.String(),
		1000, 99_900_000_000_000, nil)
	a.NoError(err)
	receipt, err := fixture.WaitForConfirmedTxn(uint64(burn.LastValid), burn.ID().String())
	a.NoError(err)

	// 3. Wait lookback rounds
	_, err = c01.WaitForRound(*receipt.ConfirmedRound + lookback)
	a.NoError(err)

	// 4. rejoin, with 1.5B against the paltry 100k that's currently online
	online(&fixture, a, c15, account15.Address, keys)
}

// Go offline, but return the key material so it's easy to go back online
func offline(f *fixtures.RestClientFixture, a *require.Assertions, client libgoal.Client, address string) transactions.KeyregTxnFields {
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
	txn, err := f.WaitForConfirmedTxn(uint64(offTx.LastValid), onlineTxID)
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
func online(f *fixtures.RestClientFixture, a *require.Assertions, client libgoal.Client, address string, keys transactions.KeyregTxnFields) {
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
	_, err = f.WaitForConfirmedTxn(uint64(onTx.LastValid), onlineTxID)
	a.NoError(err)
	data, err = client.AccountData(address)
	a.NoError(err)
	// Before bug fix, the account would be suspended in the same round of the
	// keyreg, so it would not be online.
	a.Equal(basics.Online, data.Status)
}
