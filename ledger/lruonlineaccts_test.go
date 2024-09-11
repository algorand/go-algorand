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

package ledger

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLRUOnlineAccountsBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseOnlineAcct lruOnlineAccounts
	baseOnlineAcct.init(logging.TestingLog(t), 10, 5)

	accountsNum := 50
	// write 50 accounts
	for i := 0; i < accountsNum; i++ {
		acct := trackerdb.PersistedOnlineAccountData{
			Addr:  basics.Address(crypto.Hash([]byte{byte(i)})),
			Round: basics.Round(i),
			Ref:   mockEntryRef{int64(i)},
			AccountData: trackerdb.BaseOnlineAccountData{
				MicroAlgos:        basics.MicroAlgos{Raw: uint64(i)},
				IncentiveEligible: i%2 == 0,
			},
		}
		baseOnlineAcct.write(acct)
	}

	// verify that all these accounts are truly there.
	for i := 0; i < accountsNum; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseOnlineAcct.read(addr)
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.Round)
		require.Equal(t, addr, acct.Addr)
		require.Equal(t, uint64(i), acct.AccountData.MicroAlgos.Raw)
		require.Equal(t, i%2 == 0, acct.AccountData.IncentiveEligible)
		require.Equal(t, mockEntryRef{int64(i)}, acct.Ref)
	}

	// verify expected missing entries
	for i := accountsNum; i < accountsNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseOnlineAcct.read(addr)
		require.False(t, has)
		require.Equal(t, trackerdb.PersistedOnlineAccountData{}, acct)
	}

	baseOnlineAcct.prune(accountsNum / 2)

	// verify expected (missing/existing) entries
	for i := 0; i < accountsNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseOnlineAcct.read(addr)

		if i >= accountsNum/2 && i < accountsNum {
			// expected to have it.
			require.True(t, has)
			require.Equal(t, basics.Round(i), acct.Round)
			require.Equal(t, addr, acct.Addr)
			require.Equal(t, uint64(i), acct.AccountData.MicroAlgos.Raw)
			require.Equal(t, i%2 == 0, acct.AccountData.IncentiveEligible)
			require.Equal(t, mockEntryRef{int64(i)}, acct.Ref)
		} else {
			require.False(t, has)
			require.Equal(t, trackerdb.PersistedOnlineAccountData{}, acct)
		}
	}
}

func TestLRUOnlineAccountsDisable(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseOnlineAcct lruOnlineAccounts
	baseOnlineAcct.init(logging.TestingLog(t), 0, 1)

	accountsNum := 5

	for i := 0; i < accountsNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			acct := trackerdb.PersistedOnlineAccountData{
				Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				Round:       basics.Round(i),
				Ref:         mockEntryRef{int64(i)},
				AccountData: trackerdb.BaseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
			}
			baseOnlineAcct.writePending(acct)
		}(i)
	}
	require.Empty(t, baseOnlineAcct.pendingAccounts)
	baseOnlineAcct.flushPendingWrites()
	require.Empty(t, baseOnlineAcct.accounts)

	for i := 0; i < accountsNum; i++ {
		acct := trackerdb.PersistedOnlineAccountData{
			Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
			Round:       basics.Round(i),
			Ref:         mockEntryRef{int64(i)},
			AccountData: trackerdb.BaseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		baseOnlineAcct.write(acct)
	}
	require.Empty(t, baseOnlineAcct.accounts)
}

func TestLRUOnlineAccountsPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseOnlineAcct lruOnlineAccounts
	accountsNum := 250
	baseOnlineAcct.init(logging.TestingLog(t), accountsNum*2, accountsNum)

	for i := 0; i < accountsNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			acct := trackerdb.PersistedOnlineAccountData{
				Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				Round:       basics.Round(i),
				Ref:         mockEntryRef{int64(i)},
				AccountData: trackerdb.BaseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
			}
			baseOnlineAcct.writePending(acct)
		}(i)
	}
	testStarted := time.Now()
	for {
		baseOnlineAcct.flushPendingWrites()
		// check if all accounts were loaded into "main" cache.
		allAccountsLoaded := true
		for i := 0; i < accountsNum; i++ {
			addr := basics.Address(crypto.Hash([]byte{byte(i)}))
			_, has := baseOnlineAcct.read(addr)
			if !has {
				allAccountsLoaded = false
				break
			}
		}
		if allAccountsLoaded {
			break
		}
		if time.Since(testStarted).Seconds() > 20 {
			require.Fail(t, "failed after waiting for 20 second")
		}
		// not yet, keep looping.
	}
}

func TestLRUOnlineAccountsPendingWritesWarning(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseOnlineAcct lruOnlineAccounts
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruAccountsTestLogger{Logger: logging.TestingLog(t)}
	baseOnlineAcct.init(log, pendingWritesBuffer, pendingWritesThreshold)
	for j := 0; j < 50; j++ {
		for i := 0; i < j; i++ {
			acct := trackerdb.PersistedOnlineAccountData{
				Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				Round:       basics.Round(i),
				Ref:         mockEntryRef{int64(i)},
				AccountData: trackerdb.BaseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
			}
			baseOnlineAcct.writePending(acct)
		}
		baseOnlineAcct.flushPendingWrites()
		if j >= pendingWritesThreshold {
			// expect a warning in the log
			require.Equal(t, 1+j-pendingWritesThreshold, log.warnMsgCount)
		}
	}
}

func TestLRUOnlineAccountsOmittedPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseOnlineAcct lruOnlineAccounts
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruAccountsTestLogger{Logger: logging.TestingLog(t)}
	baseOnlineAcct.init(log, pendingWritesBuffer, pendingWritesThreshold)

	for i := 0; i < pendingWritesBuffer*2; i++ {
		acct := trackerdb.PersistedOnlineAccountData{
			Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
			Round:       basics.Round(i),
			Ref:         mockEntryRef{int64(i)},
			AccountData: trackerdb.BaseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		baseOnlineAcct.writePending(acct)
	}

	baseOnlineAcct.flushPendingWrites()

	// verify that all these accounts are truly there.
	for i := 0; i < pendingWritesBuffer; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseOnlineAcct.read(addr)
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.Round)
		require.Equal(t, addr, acct.Addr)
		require.Equal(t, uint64(i), acct.AccountData.MicroAlgos.Raw)
		require.Equal(t, mockEntryRef{int64(i)}, acct.Ref)
	}

	// verify expected missing entries
	for i := pendingWritesBuffer; i < pendingWritesBuffer*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseOnlineAcct.read(addr)
		require.False(t, has)
		require.Equal(t, trackerdb.PersistedOnlineAccountData{}, acct)
	}
}
