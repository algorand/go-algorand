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

package libgoal

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidRounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	var firstValid, lastValid, validRounds, lastRound basics.Round

	lastRound = 1
	const maxTxnLife = 1000

	firstValid = 0
	lastValid = 0
	validRounds = 0
	fv, lv, err := computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(fv+maxTxnLife, lv)

	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife + 1
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(fv+maxTxnLife, lv)

	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife + 2
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: txn validity period 1001 is greater than protocol max txn lifetime 1000", err.Error())

	firstValid = 0
	lastValid = 1
	validRounds = 2
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: ambiguous input: lastValid = 1, validRounds = 2", err.Error())

	firstValid = 2
	lastValid = 1
	validRounds = 0
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: txn would first be valid on round 2 which is after last valid round 1", err.Error())

	firstValid = 1
	lastValid = maxTxnLife + 2
	validRounds = 0
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: txn validity period ( 1 to 1002 ) is greater than protocol max txn lifetime 1000", err.Error())

	firstValid = 1
	lastValid = maxTxnLife + 1
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(1, fv)
	a.EqualValues(maxTxnLife+1, lv)

	firstValid = 0
	lastValid = lastRound + 1
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(lastRound+1, lv)

	firstValid = 0
	lastValid = 0
	validRounds = 1
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(lastRound, lv)

	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(lastRound+maxTxnLife-1, lv)

	firstValid = 1
	lastValid = 0
	validRounds = 1
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(1, fv)
	a.EqualValues(1, lv)

	firstValid = 1
	lastValid = 1
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(1, fv)
	a.EqualValues(1, lv)

	firstValid = 100
	lastValid = 0
	validRounds = maxTxnLife
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(100, fv)
	a.EqualValues(100+maxTxnLife-1, lv)

	firstValid = 100
	lastValid = maxTxnLife
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(100, fv)
	a.EqualValues(maxTxnLife, lv)
}

// bbrs just saves typing
func bbrs(args ...any) []basics.BoxRef {
	if len(args)%2 != 0 {
		panic(fmt.Sprintf("odd number of args %v", args))
	}
	var refs []basics.BoxRef
	for i := 0; i < len(args); i += 2 {
		app := basics.AppIndex(args[i].(int))
		name := args[i+1].(string)
		refs = append(refs, basics.BoxRef{
			App:  app,
			Name: name,
		})
	}
	return refs
}

func TestForeignResolution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := assert.New(t)

	tx := txntest.Txn{
		ApplicationID: 111,
	}.Txn()

	accounts := []basics.Address{{0x22}, {0x33}}
	foreignApps := []basics.AppIndex{222, 333}
	foreignAssets := []basics.AssetIndex{2222, 3333}

	attachForeignRefs(&tx, RefBundle{Accounts: accounts})
	a.Equal(accounts, tx.Accounts)

	attachForeignRefs(&tx, RefBundle{Assets: foreignAssets})
	a.Equal(foreignAssets, tx.ForeignAssets)

	attachForeignRefs(&tx, RefBundle{Apps: foreignApps})
	a.Equal(foreignApps, tx.ForeignApps)

	attachForeignRefs(&tx, RefBundle{Apps: foreignApps})
	a.Equal(append(foreignApps, foreignApps...), tx.ForeignApps)

	boxes := bbrs(3, "aaa")
	attachForeignRefs(&tx, RefBundle{Boxes: boxes})
	a.Equal([]basics.AppIndex{222, 333, 222, 333, 3}, tx.ForeignApps)
	a.Equal([]transactions.BoxRef{{Index: 5, Name: []byte("aaa")}}, tx.Boxes)

	boxes = bbrs(3, "aaa", 0, "bbb")
	tx.Boxes = nil
	attachForeignRefs(&tx, RefBundle{Boxes: boxes})
	a.Equal([]basics.AppIndex{222, 333, 222, 333, 3}, tx.ForeignApps)
	a.Equal([]transactions.BoxRef{
		{Index: 5, Name: []byte("aaa")},
		{Index: 0, Name: []byte("bbb")},
	}, tx.Boxes)

	boxes = bbrs(3, "aaa", 3, "xxx")
	attachForeignRefs(&tx, RefBundle{Boxes: boxes})
	a.Equal([]basics.AppIndex{222, 333, 222, 333, 3}, tx.ForeignApps)
	a.Equal([]transactions.BoxRef{
		{Index: 5, Name: []byte("aaa")},
		{Index: 0, Name: []byte("bbb")},
		{Index: 5, Name: []byte("aaa")},
		{Index: 5, Name: []byte("xxx")},
	}, tx.Boxes)

	boxes = bbrs(111, "aaa", 333, "xxx")
	attachForeignRefs(&tx, RefBundle{Boxes: boxes})
	a.Equal([]basics.AppIndex{222, 333, 222, 333, 3}, tx.ForeignApps)
	a.Equal([]transactions.BoxRef{
		{Index: 5, Name: []byte("aaa")},
		{Index: 0, Name: []byte("bbb")},
		{Index: 5, Name: []byte("aaa")},
		{Index: 5, Name: []byte("xxx")},
		{Index: 0, Name: []byte("aaa")},
		{Index: 2, Name: []byte("xxx")},
	}, tx.Boxes)

	zero := basics.Address{0x00}
	one := basics.Address{0x01}
	two := basics.Address{0x02}
	holdings := []basics.HoldingRef{{Asset: 111, Address: one}, {Asset: 3333, Address: zero}}
	attachForeignRefs(&tx, RefBundle{Holdings: holdings})
	a.Equal([]basics.AssetIndex{2222, 3333, 111}, tx.ForeignAssets) // it's added, 111 is the APP id
	a.Equal(append(accounts, one), tx.Accounts)

	locals := []basics.LocalRef{{App: 111, Address: two}, {App: 333, Address: zero}, {App: 444, Address: one}}
	attachForeignRefs(&tx, RefBundle{Locals: locals})
	a.Equal([]basics.AppIndex{222, 333, 222, 333, 3, 444}, tx.ForeignApps) // 111 not added, it's being called
	a.Equal(append(accounts, one, two), tx.Accounts)
}

func TestAccessResolution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := assert.New(t)

	tx := txntest.Txn{
		ApplicationID: 111,
	}.Txn()

	accounts := []basics.Address{{0x22}, {0x33}}
	foreignApps := []basics.AppIndex{222, 333}
	foreignAssets := []basics.AssetIndex{2222, 3333}

	attachAccessList(&tx, RefBundle{Accounts: accounts})
	a.Nil(tx.Accounts)
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
	}, tx.Access)

	attachAccessList(&tx, RefBundle{Assets: foreignAssets})
	a.Nil(tx.ForeignAssets)
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
	}, tx.Access)

	attachAccessList(&tx, RefBundle{Apps: foreignApps})
	a.Nil(tx.ForeignApps)
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
	}, tx.Access)

	attachAccessList(&tx, RefBundle{Apps: foreignApps})
	// no change
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
	}, tx.Access)

	boxes := bbrs(3, "aaa")
	attachAccessList(&tx, RefBundle{Boxes: boxes})
	a.Nil(tx.Boxes)
	a.Nil(tx.ForeignApps)
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
		{App: 3}, {Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
	}, tx.Access)

	boxes = bbrs(3, "aaa", 0, "bbb")
	attachAccessList(&tx, RefBundle{Boxes: boxes})
	a.Nil(tx.Boxes)
	a.Nil(tx.ForeignApps)
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
		{App: 3}, {Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("bbb")}},
	}, tx.Access)

	boxes = bbrs(3, "aaa", 3, "xxx")
	attachAccessList(&tx, RefBundle{Boxes: boxes})
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
		{App: 3}, {Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("bbb")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("xxx")}},
	}, tx.Access)

	boxes = bbrs(111, "aaa", 333, "xxx")
	attachAccessList(&tx, RefBundle{Boxes: boxes})
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
		{App: 3}, {Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("bbb")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("xxx")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 6, Name: []byte("xxx")}},
	}, tx.Access)

	zero := basics.Address{0x00}
	one := basics.Address{0x01}
	two := basics.Address{0x02}
	holdings := []basics.HoldingRef{{Asset: 111, Address: one}, {Asset: 3333, Address: zero}}
	attachAccessList(&tx, RefBundle{Holdings: holdings})
	a.Nil(tx.ForeignAssets)
	a.Nil(tx.Accounts)
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
		{App: 3}, {Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("bbb")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("xxx")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 6, Name: []byte("xxx")}},
		{Address: one}, {Asset: 111}, {Holding: transactions.HoldingRef{Asset: 16, Address: 15}},
		{Holding: transactions.HoldingRef{Asset: 4, Address: 0}},
	}, tx.Access)

	locals := []basics.LocalRef{{App: 111, Address: two}, {App: 333, Address: zero}, {App: 444, Address: one}}
	attachAccessList(&tx, RefBundle{Locals: locals})
	a.Nil(tx.ForeignApps)
	a.Nil(tx.Accounts)
	a.Equal([]transactions.ResourceRef{
		{Address: accounts[0]}, {Address: accounts[1]},
		{Asset: foreignAssets[0]}, {Asset: foreignAssets[1]},
		{App: foreignApps[0]}, {App: foreignApps[1]},
		{App: 3}, {Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("bbb")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 7, Name: []byte("xxx")}},
		{Box: transactions.BoxRef{Index: 0, Name: []byte("aaa")}},
		{Box: transactions.BoxRef{Index: 6, Name: []byte("xxx")}},
		{Address: one}, {Asset: 111}, {Holding: transactions.HoldingRef{Asset: 16, Address: 15}},
		{Holding: transactions.HoldingRef{Asset: 4, Address: 0}},

		{Address: two},
		{Locals: transactions.LocalsRef{App: 0, Address: 19}},
		{Locals: transactions.LocalsRef{App: 6, Address: 0}},
		{App: 444},
		{Locals: transactions.LocalsRef{App: 22, Address: 15}},
	}, tx.Access)
}
