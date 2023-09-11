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

package data

import (
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestAppRateLimiter_NoApps(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rate := uint64(10)
	window := 1 * time.Second
	rm := MakeAppRateLimiter(10, rate, window)

	txns := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.AssetConfigTx,
			},
		},
		{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
			},
		},
	}
	drop := rm.shouldDrop(txns)
	require.False(t, drop)
}

func getAppTxnGroup(appIdx basics.AppIndex) []transactions.SignedTxn {
	apptxn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appIdx,
		},
	}

	return []transactions.SignedTxn{{Txn: apptxn}}
}

func TestAppRateLimiter_Basics(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rate := uint64(10)
	window := 1 * time.Second
	rm := MakeAppRateLimiter(10, rate, window)

	txns := getAppTxnGroup(1)
	now := time.Now()
	drop := rm.shouldDropInner(txns, now)
	require.False(t, drop)

	for i := len(txns); i < int(rate); i++ {
		drop = rm.shouldDropInner(txns, now)
		require.False(t, drop)
	}

	drop = rm.shouldDropInner(txns, now)
	require.True(t, drop)

	// check a single group with exceed rate is dropped
	apptxn2 := txns[0].Txn
	apptxn2.ApplicationID = 2
	txns = make([]transactions.SignedTxn, 0, rate+1)
	for i := 0; i < int(rate+1); i++ {
		txns = append(txns, transactions.SignedTxn{
			Txn: apptxn2,
		})
	}
	drop = rm.shouldDropInner(txns, now)
	require.True(t, drop)

	drop = rm.shouldDropInner(txns, now.Add(2*window))
	require.True(t, drop)
}

func TestAppRateLimiter_Interval(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rate := uint64(10)
	window := 10 * time.Second
	rm := MakeAppRateLimiter(10, rate, window)

	txns := getAppTxnGroup(1)
	now := time.Date(2023, 9, 11, 10, 10, 11, 0, time.UTC) // 11 sec => 1 sec into the interval

	// fill 80% of the current interval
	// switch to the next interval
	// ensure only 30% of the rate is available (8 * 0.9 = 7.2 => 7)
	// 0.9 is calculated as 1 - 0.1 (fraction of the interval elapsed)
	// since the next interval at second 21 would by 1 sec (== 10% == 0.1) after the interval beginning
	for i := 0; i < int(0.8*float64(rate)); i++ {
		drop := rm.shouldDropInner(txns, now)
		require.False(t, drop)
	}

	next := now.Add(window)
	for i := 0; i < int(0.3*float64(rate)); i++ {
		drop := rm.shouldDropInner(txns, next)
		require.False(t, drop)
	}

	drop := rm.shouldDropInner(txns, next)
	require.True(t, drop)
}

func TestAppRateLimiter_IntervalSkip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rate := uint64(10)
	window := 10 * time.Second
	rm := MakeAppRateLimiter(10, rate, window)

	txns := getAppTxnGroup(1)
	now := time.Date(2023, 9, 11, 10, 10, 11, 0, time.UTC) // 11 sec => 1 sec into the interval

	// fill 80% of the current interval
	// switch to the next next interval
	// ensure all capacity is available

	for i := 0; i < int(0.8*float64(rate)); i++ {
		drop := rm.shouldDropInner(txns, now)
		require.False(t, drop)
	}

	nextnext := now.Add(2 * window)
	for i := 0; i < int(rate); i++ {
		drop := rm.shouldDropInner(txns, nextnext)
		require.False(t, drop)
	}

	drop := rm.shouldDropInner(txns, nextnext)
	require.True(t, drop)
}

func TestAppRateLimiter_MaxSize(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Skip("TODO: implement apps expiration")

	size := uint64(2)
	rate := uint64(10)
	window := 10 * time.Second
	rm := MakeAppRateLimiter(size, rate, window)

	for i := 1; i <= int(size)+1; i++ {
		drop := rm.shouldDrop(getAppTxnGroup(basics.AppIndex(i)))
		require.False(t, drop)
	}

	require.Equal(t, int(size), len(rm.apps))
}
