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
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLRUBasicAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseAcct lruAccounts
	baseAcct.init(logging.TestingLog(t), 10, 5)

	accountsNum := 50
	// write 50 accounts
	for i := 0; i < accountsNum; i++ {
		acct := trackerdb.PersistedAccountData{
			Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
			Round:       basics.Round(i),
			Ref:         mockEntryRef{int64(i)},
			AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		baseAcct.write(acct)
	}

	// verify that all these accounts are truly there.
	for i := 0; i < accountsNum; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.Round)
		require.Equal(t, addr, acct.Addr)
		require.Equal(t, uint64(i), acct.AccountData.MicroAlgos.Raw)
		require.Equal(t, mockEntryRef{int64(i)}, acct.Ref)
	}

	// verify expected missing entries
	for i := accountsNum; i < accountsNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.False(t, has)
		require.Equal(t, trackerdb.PersistedAccountData{}, acct)
	}

	baseAcct.prune(accountsNum / 2)

	// verify expected (missing/existing) entries
	for i := 0; i < accountsNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)

		if i >= accountsNum/2 && i < accountsNum {
			// expected to have it.
			require.True(t, has)
			require.Equal(t, basics.Round(i), acct.Round)
			require.Equal(t, addr, acct.Addr)
			require.Equal(t, uint64(i), acct.AccountData.MicroAlgos.Raw)
			require.Equal(t, mockEntryRef{int64(i)}, acct.Ref)
		} else {
			require.False(t, has)
			require.Equal(t, trackerdb.PersistedAccountData{}, acct)
		}
	}
}

func TestLRUAccountsDisable(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseAcct lruAccounts
	baseAcct.init(logging.TestingLog(t), 0, 1)

	accountsNum := 5

	for i := 0; i < accountsNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			acct := trackerdb.PersistedAccountData{
				Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				Round:       basics.Round(i),
				Ref:         mockEntryRef{int64(i)},
				AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
			}
			baseAcct.writePending(acct)
		}(i)
	}
	require.Empty(t, baseAcct.pendingAccounts)
	baseAcct.flushPendingWrites()
	require.Empty(t, baseAcct.accounts)

	for i := 0; i < accountsNum; i++ {
		acct := trackerdb.PersistedAccountData{
			Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
			Round:       basics.Round(i),
			Ref:         mockEntryRef{int64(i)},
			AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		baseAcct.write(acct)
	}
	require.Empty(t, baseAcct.accounts)
}

func TestLRUAccountsPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseAcct lruAccounts
	accountsNum := 250
	baseAcct.init(logging.TestingLog(t), accountsNum*2, accountsNum)

	for i := 0; i < accountsNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			acct := trackerdb.PersistedAccountData{
				Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				Round:       basics.Round(i),
				Ref:         mockEntryRef{int64(i)},
				AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
			}
			baseAcct.writePending(acct)
		}(i)
	}
	testStarted := time.Now()
	for {
		baseAcct.flushPendingWrites()
		// check if all accounts were loaded into "main" cache.
		allAccountsLoaded := true
		for i := 0; i < accountsNum; i++ {
			addr := basics.Address(crypto.Hash([]byte{byte(i)}))
			_, has := baseAcct.read(addr)
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

type lruAccountsTestLogger struct {
	logging.Logger
	WarnfCallback func(string, ...interface{})
	warnMsgCount  int
}

func (cl *lruAccountsTestLogger) Warnf(s string, args ...interface{}) {
	cl.warnMsgCount++
}

func TestLRUAccountsPendingWritesWarning(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseAcct lruAccounts
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruAccountsTestLogger{Logger: logging.TestingLog(t)}
	baseAcct.init(log, pendingWritesBuffer, pendingWritesThreshold)
	for j := 0; j < 50; j++ {
		for i := 0; i < j; i++ {
			acct := trackerdb.PersistedAccountData{
				Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				Round:       basics.Round(i),
				Ref:         mockEntryRef{int64(i)},
				AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
			}
			baseAcct.writePending(acct)
		}
		baseAcct.flushPendingWrites()
		if j >= pendingWritesThreshold {
			// expect a warning in the log
			require.Equal(t, 1+j-pendingWritesThreshold, log.warnMsgCount)
		}
	}
}

func TestLRUAccountsOmittedPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseAcct lruAccounts
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruAccountsTestLogger{Logger: logging.TestingLog(t)}
	baseAcct.init(log, pendingWritesBuffer, pendingWritesThreshold)

	for i := 0; i < pendingWritesBuffer*2; i++ {
		acct := trackerdb.PersistedAccountData{
			Addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
			Round:       basics.Round(i),
			Ref:         mockEntryRef{int64(i)},
			AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		baseAcct.writePending(acct)
	}

	baseAcct.flushPendingWrites()

	// verify that all these accounts are truly there.
	for i := 0; i < pendingWritesBuffer; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.Round)
		require.Equal(t, addr, acct.Addr)
		require.Equal(t, uint64(i), acct.AccountData.MicroAlgos.Raw)
		require.Equal(t, mockEntryRef{int64(i)}, acct.Ref)
	}

	// verify expected missing entries
	for i := pendingWritesBuffer; i < pendingWritesBuffer*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.False(t, has)
		require.Equal(t, trackerdb.PersistedAccountData{}, acct)
	}
}

func BenchmarkLRUAccountsWrite(b *testing.B) {
	numTestAccounts := 5000
	// there are 2500 accounts that overlap
	fillerAccounts := generatePersistedAccountData(0, 97500)
	accounts := generatePersistedAccountData(97500-numTestAccounts/2, 97500+numTestAccounts/2)

	benchLruWrite(b, fillerAccounts, accounts)
}

func benchLruWrite(b *testing.B, fillerAccounts []trackerdb.PersistedAccountData, accounts []trackerdb.PersistedAccountData) {
	b.ResetTimer()
	b.StopTimer()
	var baseAcct lruAccounts
	// setting up the baseAccts with a predefined cache size
	baseAcct.init(logging.TestingLog(b), baseAccountsPendingAccountsBufferSize, baseAccountsPendingAccountsWarnThreshold)
	for i := 0; i < b.N; i++ {
		baseAcct = fillLRUAccounts(baseAcct, fillerAccounts)

		b.StartTimer()
		fillLRUAccounts(baseAcct, accounts)
		b.StopTimer()
		baseAcct.prune(0)
	}
}

func fillLRUAccounts(baseAcct lruAccounts, fillerAccounts []trackerdb.PersistedAccountData) lruAccounts {
	for _, account := range fillerAccounts {
		baseAcct.write(account)
	}
	return baseAcct
}

func generatePersistedAccountData(startRound, endRound int) []trackerdb.PersistedAccountData {
	accounts := make([]trackerdb.PersistedAccountData, endRound-startRound)
	buffer := make([]byte, 4)

	for i := startRound; i < endRound; i++ {
		binary.BigEndian.PutUint32(buffer, uint32(i))
		digest := crypto.Hash(buffer)

		accounts[i-startRound] = trackerdb.PersistedAccountData{
			Addr:        basics.Address(digest),
			Round:       basics.Round(i + startRound),
			Ref:         mockEntryRef{int64(i)},
			AccountData: trackerdb.BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
	}
	return accounts
}
