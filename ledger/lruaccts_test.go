// Copyright (C) 2019-2021 Algorand, Inc.
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
	"github.com/algorand/go-algorand/logging"
)

func TestBasicLRUAccounts(t *testing.T) {
	var baseAcct lruAccounts
	baseAcct.init(logging.TestingLog(t), 10, 5)

	accountsNum := 50
	// write 50 accounts
	for i := 0; i < accountsNum; i++ {
		acct := persistedAccountData{
			addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
			round:       basics.Round(i),
			rowid:       int64(i),
			accountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		baseAcct.write(acct)
	}

	// verify that all these accounts are truely there.
	for i := 0; i < accountsNum; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.round)
		require.Equal(t, addr, acct.addr)
		require.Equal(t, uint64(i), acct.accountData.MicroAlgos.Raw)
		require.Equal(t, int64(i), acct.rowid)
	}

	// verify expected missing entries
	for i := accountsNum; i < accountsNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.False(t, has)
		require.Equal(t, persistedAccountData{}, acct)
	}

	baseAcct.prune(accountsNum / 2)

	// verify expected (missing/existing) entries
	for i := 0; i < accountsNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)

		if i >= accountsNum/2 && i < accountsNum {
			// expected to have it.
			require.True(t, has)
			require.Equal(t, basics.Round(i), acct.round)
			require.Equal(t, addr, acct.addr)
			require.Equal(t, uint64(i), acct.accountData.MicroAlgos.Raw)
			require.Equal(t, int64(i), acct.rowid)
		} else {
			require.False(t, has)
			require.Equal(t, persistedAccountData{}, acct)
		}
	}
}

func TestLRUAccountsPendingWrites(t *testing.T) {
	var baseAcct lruAccounts
	accountsNum := 250
	baseAcct.init(logging.TestingLog(t), accountsNum*2, accountsNum)

	for i := 0; i < accountsNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			acct := persistedAccountData{
				addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				round:       basics.Round(i),
				rowid:       int64(i),
				accountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
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
	var baseAcct lruAccounts
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruAccountsTestLogger{Logger: logging.TestingLog(t)}
	baseAcct.init(log, pendingWritesBuffer, pendingWritesThreshold)
	for j := 0; j < 50; j++ {
		for i := 0; i < j; i++ {
			acct := persistedAccountData{
				addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
				round:       basics.Round(i),
				rowid:       int64(i),
				accountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
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
	var baseAcct lruAccounts
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruAccountsTestLogger{Logger: logging.TestingLog(t)}
	baseAcct.init(log, pendingWritesBuffer, pendingWritesThreshold)

	for i := 0; i < pendingWritesBuffer*2; i++ {
		acct := persistedAccountData{
			addr:        basics.Address(crypto.Hash([]byte{byte(i)})),
			round:       basics.Round(i),
			rowid:       int64(i),
			accountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
		baseAcct.writePending(acct)
	}

	baseAcct.flushPendingWrites()

	// verify that all these accounts are truely there.
	for i := 0; i < pendingWritesBuffer; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.round)
		require.Equal(t, addr, acct.addr)
		require.Equal(t, uint64(i), acct.accountData.MicroAlgos.Raw)
		require.Equal(t, int64(i), acct.rowid)
	}

	// verify expected missing entries
	for i := pendingWritesBuffer; i < pendingWritesBuffer*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		acct, has := baseAcct.read(addr)
		require.False(t, has)
		require.Equal(t, persistedAccountData{}, acct)
	}
}

func BenchmarkLRUAccountsWrite(b *testing.B) {
	numTestAccounts := 5000
	// there are 2500 accounts that overlap
	fillerAccounts := generatePersistedAccountData(0, 97500)
	accounts := generatePersistedAccountData(97500-numTestAccounts/2, 97500+numTestAccounts/2)

	b.ResetTimer()
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		var baseAcct lruAccounts
		baseAcct.init(logging.TestingLog(b), 10, 5)
		baseAcct = fillLRUAccounts(baseAcct, fillerAccounts)

		b.StartTimer()
		fillLRUAccounts(baseAcct, accounts)
		b.StopTimer()
	}
}

func fillLRUAccounts(baseAcct lruAccounts, fillerAccounts []persistedAccountData) lruAccounts {
	for _, account := range fillerAccounts {
		baseAcct.write(account)
	}
	return baseAcct
}

func generatePersistedAccountData(startRound, endRound int) []persistedAccountData {
	accounts := make([]persistedAccountData, endRound-startRound)
	buffer := make([]byte, 4)

	for i := startRound; i < endRound; i++ {
		binary.BigEndian.PutUint32(buffer, uint32(i))
		digest := crypto.Hash(buffer)

		accounts[i-startRound] = persistedAccountData{
			addr:        basics.Address(digest),
			round:       basics.Round(i + startRound),
			rowid:       int64(i),
			accountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}},
		}
	}
	return accounts
}
