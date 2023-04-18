// Copyright (C) 2019-2023 Algorand, Inc.
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

package testsuite

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func init() {
	// register tests that will run on each KV implementation
	registerTest("online-accounts-write-read", CustomTestOnlineAccountsWriteRead)
	registerTest("online-accounts-all", CustomTestOnlineAccountsAll)
	registerTest("online-accounts-top", CustomTestAccountsOnlineTop)
	registerTest("online-accounts-get-by-addr", CustomTestLookupOnlineAccountDataByAddress)
	registerTest("online-accounts-history", CustomTestOnlineAccountHistory)
	registerTest("online-accounts-totals", CustomTestOnlineAccountTotals)
	registerTest("online-accounts-delete", CustomTestOnlineAccountsDelete)
}

func CustomTestOnlineAccountsWriteRead(t *customT) {
	oaw, err := t.db.MakeOnlineAccountsOptimizedWriter(true)
	require.NoError(t, err)

	oar, err := t.db.MakeOnlineAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	// generate some test data
	addrA := RandomAddress()
	updRoundA := uint64(400)
	lastValidA := uint64(500)
	dataA := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(100)},
		RewardsBase:    uint64(200),
	}
	normalizedBalA := dataA.NormalizedOnlineBalance(t.proto)

	// write
	refA, err := oaw.InsertOnlineAccount(addrA, normalizedBalA, dataA, updRoundA, lastValidA)
	require.NoError(t, err)

	// read
	poA, err := oar.LookupOnline(addrA, basics.Round(updRoundA))
	require.NoError(t, err)
	require.Equal(t, addrA, poA.Addr)
	require.Equal(t, refA, poA.Ref)
	require.Equal(t, dataA, poA.AccountData)
	require.Equal(t, basics.Round(updRoundA), poA.UpdRound) // check the "update round" was read
	require.Equal(t, expectedRound, poA.Round)

	// write a new version
	dataA.MicroAlgos = basics.MicroAlgos{Raw: uint64(321)}
	normalizedBalA = dataA.NormalizedOnlineBalance(t.proto)
	updRoundA = uint64(450)
	_, err = oaw.InsertOnlineAccount(addrA, normalizedBalA, dataA, updRoundA, lastValidA)
	require.NoError(t, err)

	// read (latest)
	poA, err = oar.LookupOnline(addrA, basics.Round(500))
	require.NoError(t, err)
	require.Equal(t, dataA, poA.AccountData)                // check the data is from the new version
	require.Equal(t, basics.Round(updRoundA), poA.UpdRound) // check the "update round"

	// read (original)
	poA, err = oar.LookupOnline(addrA, basics.Round(405))
	require.NoError(t, err)
	require.Equal(t, basics.MicroAlgos{Raw: uint64(100)}, poA.AccountData.MicroAlgos) // check the data is from the new version
	require.Equal(t, basics.Round(400), poA.UpdRound)                                 // check the "update round"
}

func CustomTestOnlineAccountHistory(t *customT) {
	oaw, err := t.db.MakeOnlineAccountsOptimizedWriter(true)
	require.NoError(t, err)

	oar, err := t.db.MakeOnlineAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	// generate some test data
	addrA := RandomAddress()
	dataA1 := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(20)},
		RewardsBase:    uint64(200),
	}
	normalizedBalA1 := dataA1.NormalizedOnlineBalance(t.proto)

	refA1, err := oaw.InsertOnlineAccount(addrA, normalizedBalA1, dataA1, uint64(2), uint64(2))
	require.NoError(t, err)

	// generate some test data
	dataA2 := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(100)},
		RewardsBase:    uint64(200),
	}
	normalizedBalA2 := dataA2.NormalizedOnlineBalance(t.proto)

	refA2, err := oaw.InsertOnlineAccount(addrA, normalizedBalA2, dataA2, uint64(3), uint64(3))
	require.NoError(t, err)

	// generate some test data
	addrB := RandomAddress()
	dataB1 := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(75)},
		RewardsBase:    uint64(200),
	}
	normalizedBalB1 := dataB1.NormalizedOnlineBalance(t.proto)

	refB1, err := oaw.InsertOnlineAccount(addrB, normalizedBalB1, dataB1, uint64(3), uint64(3))
	require.NoError(t, err)

	//
	// the test
	//

	resultsA, rnd, err := oar.LookupOnlineHistory(addrA)
	require.NoError(t, err)
	require.Equal(t, expectedRound, rnd) // check the db round
	require.Len(t, resultsA, 2)
	require.Equal(t, basics.Round(2), resultsA[0].UpdRound) // check ordering
	require.Equal(t, basics.Round(3), resultsA[1].UpdRound) // check ordering
	// check item fields
	require.Empty(t, resultsA[0].Round)               // check the db round is not set
	require.Equal(t, addrA, resultsA[0].Addr)         // check addr
	require.Equal(t, refA1, resultsA[0].Ref)          // check ref
	require.Equal(t, dataA1, resultsA[0].AccountData) // check data
	// check ref is valid on all
	require.Equal(t, refA2, resultsA[1].Ref) // check ref

	// check for B
	resultsB, _, err := oar.LookupOnlineHistory(addrB)
	require.NoError(t, err)
	require.Len(t, resultsB, 1)
	require.Equal(t, addrB, resultsB[0].Addr) // check addr
	require.Equal(t, refB1, resultsB[0].Ref)  // check ref
}

func CustomTestOnlineAccountsAll(t *customT) {
	oaw, err := t.db.MakeOnlineAccountsOptimizedWriter(true)
	require.NoError(t, err)

	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	voteLastValid := uint64(0)

	// generate some test data
	addrA := basics.Address(crypto.Hash([]byte("a")))
	dataA0 := trackerdb.BaseOnlineAccountData{
		MicroAlgos: basics.MicroAlgos{Raw: uint64(200)},
	}
	_, err = oaw.InsertOnlineAccount(addrA, dataA0.NormalizedOnlineBalance(t.proto), dataA0, 0, voteLastValid)
	require.NoError(t, err)

	dataA1 := trackerdb.BaseOnlineAccountData{
		MicroAlgos: basics.MicroAlgos{Raw: uint64(250)},
	}
	_, err = oaw.InsertOnlineAccount(addrA, dataA1.NormalizedOnlineBalance(t.proto), dataA1, 1, voteLastValid)
	require.NoError(t, err)

	addrB := basics.Address(crypto.Hash([]byte("b")))
	dataB := trackerdb.BaseOnlineAccountData{
		MicroAlgos: basics.MicroAlgos{Raw: uint64(100)},
	}
	_, err = oaw.InsertOnlineAccount(addrB, dataB.NormalizedOnlineBalance(t.proto), dataB, 0, voteLastValid)
	require.NoError(t, err)

	addrC := basics.Address(crypto.Hash([]byte("c")))
	dataC := trackerdb.BaseOnlineAccountData{
		MicroAlgos: basics.MicroAlgos{Raw: uint64(30)},
	}
	_, err = oaw.InsertOnlineAccount(addrC, dataC.NormalizedOnlineBalance(t.proto), dataC, 0, voteLastValid)
	require.NoError(t, err)

	//
	// test
	//

	// read all accounts (with max accounts)
	poA, err := ar.OnlineAccountsAll(2)
	require.NoError(t, err)
	require.Len(t, poA, 3) // account A has 2 records + 1 record from account B

	require.Equal(t, addrA, poA[0].Addr)
	require.Equal(t, basics.MicroAlgos{Raw: uint64(200)}, poA[0].AccountData.MicroAlgos)
	require.Equal(t, basics.Round(0), poA[0].UpdRound)

	require.Equal(t, addrA, poA[1].Addr)
	require.Equal(t, basics.MicroAlgos{Raw: uint64(250)}, poA[1].AccountData.MicroAlgos)
	require.Equal(t, basics.Round(1), poA[1].UpdRound)

	require.Equal(t, addrB, poA[2].Addr)
	require.Equal(t, basics.MicroAlgos{Raw: uint64(100)}, poA[2].AccountData.MicroAlgos)
	require.Equal(t, basics.Round(0), poA[2].UpdRound)
}

func CustomTestAccountsOnlineTop(t *customT) {
	oaw, err := t.db.MakeOnlineAccountsOptimizedWriter(true)
	require.NoError(t, err)

	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	// generate some test data
	var testData []basics.Address
	updRound := uint64(0)
	for i := 0; i < 10; i++ {
		addr := RandomAddress()
		microAlgos := basics.MicroAlgos{Raw: uint64(10 + i*100)}
		rewardBase := uint64(200 + i)
		lastValid := uint64(500 + i)
		data := trackerdb.BaseOnlineAccountData{
			BaseVotingData: trackerdb.BaseVotingData{},
			MicroAlgos:     microAlgos,
			RewardsBase:    rewardBase,
		}
		normalizedBal := data.NormalizedOnlineBalance(t.proto)

		// write
		_, err := oaw.InsertOnlineAccount(addr, normalizedBal, data, updRound, lastValid)
		require.NoError(t, err)

		testData = append(testData, addr)
	}

	// read (all)
	poA, err := ar.AccountsOnlineTop(basics.Round(0), 0, 10, t.proto)
	require.NoError(t, err)
	require.Contains(t, poA, testData[9]) // most money
	require.Contains(t, poA, testData[0]) // least money

	// read (just a few)
	poA, err = ar.AccountsOnlineTop(basics.Round(0), 1, 2, t.proto)
	require.NoError(t, err)
	require.Len(t, poA, 2)
	require.Contains(t, poA, testData[8]) // (second most money, we skipped 1)
	require.Contains(t, poA, testData[7]) // (third, we only have 2 items)
}

func CustomTestLookupOnlineAccountDataByAddress(t *customT) {
	oaw, err := t.db.MakeOnlineAccountsOptimizedWriter(true)
	require.NoError(t, err)

	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	// generate some test data
	addrA := RandomAddress()
	updRoundA := uint64(400)
	lastValidA := uint64(500)
	dataA := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(100)},
		RewardsBase:    uint64(200),
	}
	normalizedBalA := dataA.NormalizedOnlineBalance(t.proto)

	refA, err := oaw.InsertOnlineAccount(addrA, normalizedBalA, dataA, updRoundA, lastValidA)
	require.NoError(t, err)

	//
	// test
	//

	// check non-existing account
	nonExistingAddr := RandomAddress()
	_, _, err = ar.LookupOnlineAccountDataByAddress(nonExistingAddr)
	require.Error(t, err)
	require.Equal(t, trackerdb.ErrNotFound, err) // check the error type

	// read existing addr
	readRef, readData, err := ar.LookupOnlineAccountDataByAddress(addrA)
	require.NoError(t, err)
	require.Equal(t, refA, readRef) // check ref is the same
	// the method returns raw bytes, parse them
	var badA trackerdb.BaseOnlineAccountData
	err = protocol.Decode(readData, &badA)
	require.NoError(t, err)
	require.Equal(t, dataA, badA)
}

func CustomTestOnlineAccountTotals(t *customT) {
	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	oaor, err := t.db.MakeOnlineAccountsOptimizedReader()
	require.NoError(t, err)

	// generate some test data
	roundParams := []ledgercore.OnlineRoundParamsData{
		{OnlineSupply: 100},
		{OnlineSupply: 42},
		{OnlineSupply: 9000},
	}
	err = aw.AccountsPutOnlineRoundParams(roundParams, basics.Round(3))
	require.NoError(t, err)

	//
	// test
	//

	// lookup totals
	totals, err := oaor.LookupOnlineTotalsHistory(basics.Round(4))
	require.NoError(t, err)
	require.Equal(t, basics.MicroAlgos{Raw: uint64(42)}, totals)

	// lookup not found
	_, err = oaor.LookupOnlineTotalsHistory(basics.Round(121))
	require.Error(t, err)
	require.Equal(t, trackerdb.ErrNotFound, err)
}

func CustomTestOnlineAccountsDelete(t *customT) {
	oaw, err := t.db.MakeOnlineAccountsOptimizedWriter(true)
	require.NoError(t, err)

	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	// generate some test data
	addrA := RandomAddress()
	dataA1 := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(20)},
		RewardsBase:    uint64(200),
	}
	normalizedBalA1 := dataA1.NormalizedOnlineBalance(t.proto)

	_, err = oaw.InsertOnlineAccount(addrA, normalizedBalA1, dataA1, uint64(0), uint64(2))
	require.NoError(t, err)

	// generate some test data
	dataA2 := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(100)},
		RewardsBase:    uint64(200),
	}
	normalizedBalA2 := dataA2.NormalizedOnlineBalance(t.proto)

	_, err = oaw.InsertOnlineAccount(addrA, normalizedBalA2, dataA2, uint64(1), uint64(3))
	require.NoError(t, err)

	// generate some test data
	addrB := RandomAddress()
	dataB1 := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     basics.MicroAlgos{Raw: uint64(75)},
		RewardsBase:    uint64(200),
	}
	normalizedBalB1 := dataB1.NormalizedOnlineBalance(t.proto)

	_, err = oaw.InsertOnlineAccount(addrB, normalizedBalB1, dataB1, uint64(2), uint64(3))
	require.NoError(t, err)

	//
	// the test
	//

	// delete before 0 (no changes)
	err = aw.OnlineAccountsDelete(basics.Round(0))
	require.NoError(t, err)

	// check they are all there
	oas, err := ar.AccountsOnlineTop(basics.Round(0), 0, 10, t.proto)
	require.NoError(t, err)
	require.Len(t, oas, 1)
	require.Equal(t, oas[addrA].MicroAlgos, basics.MicroAlgos{Raw: uint64(20)}) // check item

	// delete before round 1
	err = aw.OnlineAccountsDelete(basics.Round(1))
	require.NoError(t, err)

	// check they are all there
	oas, err = ar.AccountsOnlineTop(basics.Round(1), 0, 10, t.proto)
	require.NoError(t, err)
	require.Len(t, oas, 1)
	require.Equal(t, oas[addrA].MicroAlgos, basics.MicroAlgos{Raw: uint64(100)}) // check item

	// delete before round 2
	err = aw.OnlineAccountsDelete(basics.Round(2))
	require.NoError(t, err)

	// check they are all there
	oas, err = ar.AccountsOnlineTop(basics.Round(2), 0, 10, t.proto)
	require.NoError(t, err)
	require.Len(t, oas, 1)
	require.Equal(t, oas[addrB].MicroAlgos, basics.MicroAlgos{Raw: uint64(75)}) // check item
}
