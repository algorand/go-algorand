package testsuite

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/stretchr/testify/require"
)

func init() {
	// register tests that will run on each KV implementation
	// registerTest("online-accounts-crud", CustomTestOnlineReadWrite)
	registerTest("online-accounts-all", CustomTestOnlineAccountsAll)
	registerTest("online-accounts-top", CustomTestAccountsOnlineTop)
	registerTest("online-accounts-get-by-addr", CustomTestLookupOnlineAccountDataByAddress)

}

func CustomTestOnlineReadWrite(t *customT) {
	oaw, err := t.db.MakeOnlineAccountsOptimizedWriter(false)
	require.NoError(t, err)

	oar, err := t.db.MakeOnlineAccountsOptimizedReader()
	require.NoError(t, err)

	// generate some test data
	addrA := RandomAddress()
	microAlgosA := basics.MicroAlgos{Raw: uint64(100)}
	rewardBaseA := uint64(200)
	updRoundA := uint64(400)
	lastValidA := uint64(500)
	dataA := trackerdb.BaseOnlineAccountData{
		BaseVotingData: trackerdb.BaseVotingData{},
		MicroAlgos:     microAlgosA,
		RewardsBase:    rewardBaseA,
	}
	normalizedBalA := dataA.NormalizedOnlineBalance(t.proto)

	// write
	refA, err := oaw.InsertOnlineAccount(addrA, normalizedBalA, dataA, updRoundA, lastValidA)
	require.NoError(t, err)

	// read
	poA, err := oar.LookupOnline(addrA, basics.Round(updRoundA))
	require.NoError(t, err)

	// check that the returned ref is the same as the original
	require.Equal(t, addrA, poA.Addr)
	require.Equal(t, refA, poA.Ref)
	require.Equal(t, 1, 2)
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
	var test_data []basics.Address
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

		test_data = append(test_data, addr)
	}

	// read (all)
	poA, err := ar.AccountsOnlineTop(basics.Round(0), 0, 10, t.proto)
	require.NoError(t, err)
	require.Contains(t, poA, test_data[9]) // most money
	require.Contains(t, poA, test_data[0]) // least money

	// read (just a few)
	poA, err = ar.AccountsOnlineTop(basics.Round(0), 1, 2, t.proto)
	require.NoError(t, err)
	require.Len(t, poA, 2)
	require.Contains(t, poA, test_data[8]) // (second most money, we skipped 1)
	require.Contains(t, poA, test_data[7]) // (third, we only have 2 items)
}

func CustomTestLookupOnlineAccountDataByAddress(t *customT) {
	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	// check non-existing account
	addr := RandomAddress()

	_, _, err = ar.LookupOnlineAccountDataByAddress(addr)
	require.Error(t, err)
}
