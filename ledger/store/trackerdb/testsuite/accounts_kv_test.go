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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/stretchr/testify/require"
)

func init() {
	// register tests that will run on each KV implementation
	registerTest("accounts-crud", CustomTestAccountsCrud)
	registerTest("resources-crud", CustomTestResourcesCrud)
	registerTest("resources-query-all", CustomTestResourcesQueryAll)
	registerTest("kv-crud", CustomTestAppKVCrud)
	registerTest("creatables-crud", CustomTestCreatablesCrud)
	registerTest("creatables-query-all", CustomTestCreatablesQueryAll)
}

func CustomTestAccountsCrud(t *customT) {
	aow, err := t.db.MakeAccountsOptimizedWriter(true, false, false, false)
	require.NoError(t, err)

	aor, err := t.db.MakeAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	ar, err := t.db.MakeAccountsReader()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	// generate some test data
	addrA := RandomAddress()
	dataA := trackerdb.BaseAccountData{
		RewardsBase: 1000,
	}

	// insert the account
	normBalanceA := dataA.NormalizedOnlineBalance(t.proto)
	refA, err := aow.InsertAccount(addrA, normBalanceA, dataA)
	require.NoError(t, err)

	// read the account
	padA, err := aor.LookupAccount(addrA)
	require.NoError(t, err)
	require.Equal(t, addrA, padA.Addr)          // addr is present and correct
	require.Equal(t, refA, padA.Ref)            // same ref as when we inserted it
	require.Equal(t, dataA, padA.AccountData)   // same data
	require.Equal(t, expectedRound, padA.Round) // db round

	// read the accounts "ref"
	readRefA, err := ar.LookupAccountRowID(addrA)
	require.NoError(t, err)
	require.Equal(t, refA, readRefA) // same ref as when we inserted it

	// update the account
	dataA.RewardsBase = 98287
	normBalanceA = dataA.NormalizedOnlineBalance(t.proto)
	_, err = aow.UpdateAccount(refA, normBalanceA, dataA)
	require.NoError(t, err)

	// read updated account
	padA, err = aor.LookupAccount(addrA)
	require.NoError(t, err)
	require.Equal(t, dataA, padA.AccountData) // same updated data

	// delete account
	_, err = aow.DeleteAccount(refA)
	require.NoError(t, err)

	// read deleted account
	// Note: this is a bit counter-intuitive but lookup returns a value
	//	     even when the account doesnt exist.
	padA, err = aor.LookupAccount(addrA)
	require.NoError(t, err)
	require.Equal(t, addrA, padA.Addr)          // the addr is there
	require.Empty(t, padA.AccountData)          // no data
	require.Equal(t, expectedRound, padA.Round) // db round (this is present even if record does not exist)
}

func CustomTestResourcesCrud(t *customT) {
	aow, err := t.db.MakeAccountsOptimizedWriter(true, true, false, false)
	require.NoError(t, err)

	aor, err := t.db.MakeAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	//
	// pre-fill the db with an account for testing
	//

	// account
	addrA := RandomAddress()
	accDataA := trackerdb.BaseAccountData{RewardsBase: 1000}
	refAccA, err := aow.InsertAccount(addrA, accDataA.NormalizedOnlineBalance(t.proto), accDataA)
	require.NoError(t, err)

	//
	// test
	//

	// generate some test data
	resDataA0 := trackerdb.MakeResourcesData(0)
	resDataA0.SetAssetParams(basics.AssetParams{
		Total:     100,
		UnitName:  "t",
		AssetName: "test-asset",
		Manager:   addrA,
		Reserve:   addrA,
		Freeze:    addrA,
		Clawback:  addrA,
		URL:       "http://127.0.0.1/8000",
	}, true)
	resDataA0.SetAssetHolding(basics.AssetHolding{Amount: 10})
	aidxResA0 := basics.CreatableIndex(0)

	// insert the resource
	refResA0, err := aow.InsertResource(refAccA, aidxResA0, resDataA0)
	require.NoError(t, err)
	require.NotNil(t, refResA0)

	// read the resource
	prdA0, err := aor.LookupResources(addrA, aidxResA0, basics.AssetCreatable)
	require.NoError(t, err)
	require.Equal(t, aidxResA0, prdA0.Aidx)      // aidx is present and correct
	require.Equal(t, refAccA, prdA0.AcctRef)     // acctRef is present and correct
	require.Equal(t, resDataA0, prdA0.Data)      // same data
	require.Equal(t, expectedRound, prdA0.Round) // db round

	// update the resource
	resDataA0.Amount = 900
	_, err = aow.UpdateResource(refAccA, aidxResA0, resDataA0)
	require.NoError(t, err)

	// read updated resource
	prdA0, err = aor.LookupResources(addrA, aidxResA0, basics.AssetCreatable)
	require.NoError(t, err)
	require.Equal(t, resDataA0, prdA0.Data) // same updated data

	// delete resource
	_, err = aow.DeleteResource(refAccA, aidxResA0)
	require.NoError(t, err)

	// read deleted resource
	// Note: this is a bit counter-intuitive but lookup returns a value
	//	     even when the account doesnt exist.
	prdA0, err = aor.LookupResources(addrA, aidxResA0, basics.AssetCreatable)
	require.NoError(t, err)
	require.Equal(t, aidxResA0, prdA0.Aidx)                      // the aidx is there
	require.Nil(t, prdA0.AcctRef)                                // the account ref is not present
	require.Equal(t, trackerdb.MakeResourcesData(0), prdA0.Data) // rnd 0, clean data
	require.Equal(t, expectedRound, prdA0.Round)                 // db round (this is present even if record does not exist)
}

func CustomTestResourcesQueryAll(t *customT) {
	aow, err := t.db.MakeAccountsOptimizedWriter(true, true, false, false)
	require.NoError(t, err)

	aor, err := t.db.MakeAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	//
	// pre-fill the db with an account for testing
	//

	// account A
	addrA := RandomAddress()
	accDataA := trackerdb.BaseAccountData{RewardsBase: 1000}
	refAccA, err := aow.InsertAccount(addrA, accDataA.NormalizedOnlineBalance(t.proto), accDataA)
	require.NoError(t, err)

	// resource A-0
	resDataA0 := trackerdb.ResourcesData{}
	aidxResA0 := basics.CreatableIndex(0)
	_, err = aow.InsertResource(refAccA, aidxResA0, resDataA0)
	require.NoError(t, err)

	// resource A-1
	resDataA1 := trackerdb.ResourcesData{}
	aidxResA1 := basics.CreatableIndex(1)
	_, err = aow.InsertResource(refAccA, aidxResA1, resDataA1)
	require.NoError(t, err)

	//
	// test
	//

	prs, rnd, err := aor.LookupAllResources(addrA)
	require.NoError(t, err)
	require.Equal(t, aidxResA0, prs[0].Aidx)
	require.Equal(t, aidxResA1, prs[1].Aidx)
	require.Equal(t, expectedRound, prs[0].Round) // db round (inside resources)
	require.Equal(t, expectedRound, rnd)          // db round (from the return)
}

func CustomTestAppKVCrud(t *customT) {
	aow, err := t.db.MakeAccountsOptimizedWriter(true, true, true, false)
	require.NoError(t, err)

	aor, err := t.db.MakeAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	//
	// pre-fill the db with an account for testing
	//

	// account
	addrA := RandomAddress()
	accDataA := trackerdb.BaseAccountData{RewardsBase: 1000}
	refAccA, err := aow.InsertAccount(addrA, accDataA.NormalizedOnlineBalance(t.proto), accDataA)
	require.NoError(t, err)
	// resource
	resDataA0 := trackerdb.ResourcesData{}
	aidxResA0 := basics.CreatableIndex(0)
	refResA0, err := aow.InsertResource(refAccA, aidxResA0, resDataA0)
	require.NoError(t, err)
	require.NotNil(t, refResA0)

	//
	// test
	//

	// insert the kv
	kvKey := "foobar-mykey"
	kvValue := []byte("1234")
	err = aow.UpsertKvPair(kvKey, kvValue)
	require.NoError(t, err)

	// read the kv
	pv1, err := aor.LookupKeyValue(kvKey)
	require.NoError(t, err)
	require.Equal(t, kvValue, pv1.Value)       // same data
	require.Equal(t, expectedRound, pv1.Round) // db round

	// update the kv
	kvValue = []byte("777")
	err = aow.UpsertKvPair(kvKey, kvValue)
	require.NoError(t, err)

	// read updated kv
	pv1, err = aor.LookupKeyValue(kvKey)
	require.NoError(t, err)
	require.Equal(t, kvValue, pv1.Value) // same data

	// delete the kv
	err = aow.DeleteKvPair(kvKey)
	require.NoError(t, err)

	// read deleted kv
	require.NoError(t, err)

	// read deleted kv
	// Note: this is a bit counter-intuitive but lookup returns a value
	//	     even when the record doesn't exist.
	pv1, err = aor.LookupKeyValue(kvKey)
	require.NoError(t, err)
	require.Equal(t, expectedRound, pv1.Round) // db round (this is present even if record does not exist)
}

func CustomTestCreatablesCrud(t *customT) {
	aow, err := t.db.MakeAccountsOptimizedWriter(true, true, false, true)
	require.NoError(t, err)

	aor, err := t.db.MakeAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	//
	// pre-fill the db with an account for testing
	//

	// account A
	addrA := RandomAddress()
	accDataA := trackerdb.BaseAccountData{RewardsBase: 1000}
	refAccA, err := aow.InsertAccount(addrA, accDataA.NormalizedOnlineBalance(t.proto), accDataA)
	require.NoError(t, err)

	// resource A-0
	resDataA0 := trackerdb.ResourcesData{}
	aidxResA0 := basics.CreatableIndex(0)
	_, err = aow.InsertResource(refAccA, aidxResA0, resDataA0)
	require.NoError(t, err)

	// resource A-1
	resDataA1 := trackerdb.ResourcesData{}
	aidxResA1 := basics.CreatableIndex(1)
	_, err = aow.InsertResource(refAccA, aidxResA1, resDataA1)
	require.NoError(t, err)

	//
	// test
	//

	// insert creator for A0
	resA0ctype := basics.AssetCreatable
	cRefA0, err := aow.InsertCreatable(aidxResA0, resA0ctype, addrA[:])
	require.NoError(t, err)
	require.NotNil(t, cRefA0)

	// insert creator for A1
	resA1ctype := basics.AppCreatable
	cRefA1, err := aow.InsertCreatable(aidxResA1, resA1ctype, addrA[:])
	require.NoError(t, err)
	require.NotNil(t, cRefA1)

	// lookup creator (correct ctype)
	addr, ok, rnd, err := aor.LookupCreator(aidxResA0, basics.AssetCreatable)
	require.NoError(t, err)
	require.True(t, ok)                  // ok=true when it works
	require.Equal(t, addrA, addr)        // correct owner
	require.Equal(t, expectedRound, rnd) // db round

	// lookup creator (invalid ctype)
	_, ok, rnd, err = aor.LookupCreator(aidxResA0, basics.AppCreatable)
	require.NoError(t, err)
	require.False(t, ok)                 // ok=false when its doesnt match
	require.Equal(t, expectedRound, rnd) // db round (this is present even if record does not exist)

	// lookup creator (unknown index)
	_, ok, rnd, err = aor.LookupCreator(basics.CreatableIndex(999), basics.AppCreatable)
	require.NoError(t, err)
	require.False(t, ok)                 // ok=false when it doesn't exist
	require.Equal(t, expectedRound, rnd) // db round (this is present even if record does not exist)

}

func CustomTestCreatablesQueryAll(t *customT) {
	aow, err := t.db.MakeAccountsOptimizedWriter(true, true, false, true)
	require.NoError(t, err)

	aor, err := t.db.MakeAccountsOptimizedReader()
	require.NoError(t, err)

	aw, err := t.db.MakeAccountsWriter()
	require.NoError(t, err)

	// set round to 3
	// Note: this will be used to check that we read the round
	expectedRound := basics.Round(3)
	err = aw.UpdateAccountsRound(expectedRound)
	require.NoError(t, err)

	//
	// pre-fill the db with an account for testing
	//

	// account A
	addrA := RandomAddress()
	accDataA := trackerdb.BaseAccountData{RewardsBase: 1000}
	refAccA, err := aow.InsertAccount(addrA, accDataA.NormalizedOnlineBalance(t.proto), accDataA)
	require.NoError(t, err)

	// resource A-0
	resDataA0 := trackerdb.ResourcesData{}
	aidxResA0 := basics.CreatableIndex(0)
	_, err = aow.InsertResource(refAccA, aidxResA0, resDataA0)
	require.NoError(t, err)

	// resource A-1
	resDataA1 := trackerdb.ResourcesData{}
	aidxResA1 := basics.CreatableIndex(1)
	_, err = aow.InsertResource(refAccA, aidxResA1, resDataA1)
	require.NoError(t, err)

	// resource A-2
	resDataA2 := trackerdb.ResourcesData{}
	aidxResA2 := basics.CreatableIndex(2)
	_, err = aow.InsertResource(refAccA, aidxResA2, resDataA2)
	require.NoError(t, err)

	// creator for A0
	resA0ctype := basics.AssetCreatable
	cRefA0, err := aow.InsertCreatable(aidxResA0, resA0ctype, addrA[:])
	require.NoError(t, err)
	require.NotNil(t, cRefA0)

	// creator for A1
	resA1ctype := basics.AppCreatable
	cRefA1, err := aow.InsertCreatable(aidxResA1, resA1ctype, addrA[:])
	require.NoError(t, err)
	require.NotNil(t, cRefA1)

	// creator for A2
	resA2ctype := basics.AppCreatable
	cRefA2, err := aow.InsertCreatable(aidxResA2, resA2ctype, addrA[:])
	require.NoError(t, err)
	require.NotNil(t, cRefA2)

	//
	// test
	//

	// filter by type
	cls, rnd, err := aor.ListCreatables(basics.CreatableIndex(99), 5, basics.AssetCreatable)
	require.NoError(t, err)
	require.Len(t, cls, 1)                    // only one asset
	require.Equal(t, aidxResA0, cls[0].Index) // resource A-0
	require.Equal(t, expectedRound, rnd)      // db round

	// with multiple results
	cls, rnd, err = aor.ListCreatables(basics.CreatableIndex(99), 5, basics.AppCreatable)
	require.NoError(t, err)
	require.Len(t, cls, 2)                    // two apps
	require.Equal(t, aidxResA2, cls[0].Index) // resource A-2
	require.Equal(t, aidxResA1, cls[1].Index) // resource A-1
	require.Equal(t, expectedRound, rnd)      // db round

	// limit results
	cls, rnd, err = aor.ListCreatables(basics.CreatableIndex(99), 1, basics.AppCreatable)
	require.NoError(t, err)
	require.Len(t, cls, 1)                    // two apps
	require.Equal(t, aidxResA2, cls[0].Index) // resource A-2
	require.Equal(t, expectedRound, rnd)      // db round

	// filter maxId
	cls, rnd, err = aor.ListCreatables(aidxResA2, 10, basics.AppCreatable)
	require.NoError(t, err)
	require.Len(t, cls, 2)                    // only one app since to that cidx
	require.Equal(t, aidxResA2, cls[0].Index) // resource A-2 (checks for order too)
	require.Equal(t, aidxResA1, cls[1].Index) // resource A-1
	require.Equal(t, expectedRound, rnd)      // db round

}
