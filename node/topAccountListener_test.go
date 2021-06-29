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

package node

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testpartitioning"
)

// errorString is a trivial implementation of error.
type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

func TestUpdateTopAccounts(t *testing.T) {
	testpartitioning.PartitionTest(t)

	var topN []basics.AccountDetail
	var input []basics.AccountDetail

	// Empty target array.
	topN = []basics.AccountDetail{}
	input = []basics.AccountDetail{onlineDetail(byte(0), 1), onlineDetail(byte(1), 10)}
	topN = updateTopAccounts(topN, input)

	if len(topN) != 0 {
		t.Errorf("Target slice not 0: len(topN) == %d", len(topN))
	}

	// Extra space available
	topN = make([]basics.AccountDetail, 0, 20)
	input = []basics.AccountDetail{onlineDetail(byte(0), 1), onlineDetail(byte(1), 10)}
	topN = updateTopAccounts(topN, input)

	if err := verifyAccountBalances([]uint64{10, 1}, topN); err != nil {
		t.Error(err)
	}

	// Overflow, unmodified
	topN = make([]basics.AccountDetail, 0, 4)
	input = []basics.AccountDetail{
		onlineDetail(byte(0), 11),
		onlineDetail(byte(1), 12),
		onlineDetail(byte(2), 13),
		onlineDetail(byte(3), 14),
		onlineDetail(byte(4), 1),
	}
	topN = updateTopAccounts(topN, input)

	if err := verifyAccountBalances([]uint64{14, 13, 12, 11}, topN); err != nil {
		t.Error(err)
	}

	// Overflow, insert front
	topN = make([]basics.AccountDetail, 0, 4)
	input = []basics.AccountDetail{
		onlineDetail(byte(1), 11),
		onlineDetail(byte(2), 12),
		onlineDetail(byte(3), 13),
		onlineDetail(byte(4), 14),
		onlineDetail(byte(5), 15),
	}
	topN = updateTopAccounts(topN, input)

	if err := verifyAccountBalances([]uint64{15, 14, 13, 12}, topN); err != nil {
		t.Error(err)
	}

	// Overflow, insert middle
	topN = make([]basics.AccountDetail, 0, 4)
	input = []basics.AccountDetail{
		onlineDetail(byte(1), 11),
		onlineDetail(byte(2), 12),
		onlineDetail(byte(3), 13),
		onlineDetail(byte(4), 15),
		onlineDetail(byte(5), 14),
	}
	topN = updateTopAccounts(topN, input)

	if err := verifyAccountBalances([]uint64{15, 14, 13, 12}, topN); err != nil {
		t.Error(err)
	}

	// Overflow, insert end
	topN = make([]basics.AccountDetail, 0, 4)
	input = []basics.AccountDetail{
		onlineDetail(byte(1), 11),
		onlineDetail(byte(2), 13),
		onlineDetail(byte(3), 14),
		onlineDetail(byte(4), 15),
		onlineDetail(byte(5), 12),
	}
	topN = updateTopAccounts(topN, input)

	if err := verifyAccountBalances([]uint64{15, 14, 13, 12}, topN); err != nil {
		t.Error(err)
	}

	// Ignore offline account, shouldn't change topN
	topN = updateTopAccounts(topN, []basics.AccountDetail{detail(byte(6), 200, false)})
	topN = make([]basics.AccountDetail, 0, 4)
	input = []basics.AccountDetail{
		onlineDetail(byte(1), 12),
		onlineDetail(byte(2), 13),
		onlineDetail(byte(3), 14),
		onlineDetail(byte(4), 15),
		detail(byte(5), 200, false),
	}
	topN = updateTopAccounts(topN, input)

	if err := verifyAccountBalances([]uint64{15, 14, 13, 12}, topN); err != nil {
		t.Error(err)
	}
}

func TestRemoveSome(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Initialize slice with 100 accounts
	var accountsSlice []basics.AccountDetail
	for i := 0; i <= 100; i++ {
		accountsSlice = append(accountsSlice, onlineDetail(byte(i), 10))
	}

	// Remove accounts where the first byte is divisible by 10 (which includes the first and last index
	remove10s := func(details basics.AccountDetail) bool {
		return getInt(details)%10 == 0
	}

	accountsSlice = removeSome(accountsSlice, remove10s)

	if len(accountsSlice) != 90 {
		t.Errorf("Unexpected size found after removeSome/remove10s: 90 != %d", len(accountsSlice))
	}
	for _, d := range accountsSlice {
		if getInt(d)%10 == 0 {
			t.Errorf("Unexpected value found after removeSome/remove10s: %d", getInt(d))
		}
	}

	// Remove remaining accounts where the first byte is even
	removeEven := func(details basics.AccountDetail) bool {
		return getInt(details)%2 == 0
	}

	accountsSlice = removeSome(accountsSlice, removeEven)

	if len(accountsSlice) != 50 {
		t.Errorf("Unexpected size found after removeSome/removeEven: 50 != %d", len(accountsSlice))
	}
	for _, d := range accountsSlice {
		if getInt(d)%2 == 0 {
			t.Errorf("Unexpected value found after removeSome/removeEven: %d", getInt(d))
		}
	}
}

func TestUpdate(t *testing.T) {
	testpartitioning.PartitionTest(t)

	listener := topAccountListener{
		accounts:          []basics.AccountDetail{},
		round:             1,
		totalCirculation:  basics.MicroAlgos{Raw: 100},
		onlineCirculation: basics.MicroAlgos{Raw: 100},
	}

	balanceUpdate := basics.BalanceDetail{
		Accounts:    []basics.AccountDetail{},
		Round:       2,
		OnlineMoney: basics.MicroAlgos{Raw: 100000},
		TotalMoney:  basics.MicroAlgos{Raw: 1000000},
	}

	// Update when accounts is empty.
	listener.update(bookkeeping.Block{}, balanceUpdate)
	if err := verifyListener(listener, []uint64{}, 100000, 1000000, 2); err != nil {
		t.Error(err)
	}

	// Transactions causing acct 1 to increase reorders the TopN.
	listener.accounts = []basics.AccountDetail{
		onlineDetail(byte(0), 15),
		onlineDetail(byte(1), 10),
		onlineDetail(byte(2), 5),
	}
	balanceUpdate.Accounts = []basics.AccountDetail{onlineDetail(byte(1), 100)}
	balanceUpdate.Round++
	block := makeBlockWithTxnFor([]byte{3}, []byte{1})

	listener.update(block, balanceUpdate)

	// 10 -> 100.
	if err := verifyListener(listener, []uint64{100, 15, 5}, 100000, 1000000, 3); err != nil {
		t.Error(err)
	}

	// Transactions causing acct 1 to decrease and falls off topN truncates result.
	listener.accounts = []basics.AccountDetail{
		onlineDetail(byte(0), 15),
		onlineDetail(byte(1), 10),
		onlineDetail(byte(2), 5),
	}
	balanceUpdate.Round++
	balanceUpdate.TotalMoney = basics.MicroAlgos{Raw: 99999999}
	balanceUpdate.Accounts = []basics.AccountDetail{onlineDetail(byte(1), 1)}
	block = makeBlockWithTxnFor([]byte{3}, []byte{1})
	listener.update(block, balanceUpdate)

	if err := verifyListener(listener, []uint64{15, 5}, 100000, 99999999, 4); err != nil {
		t.Error(err)
	}

	// Transactions causing adding a balance to a new account are not reflected in TopN, because they are smaller than
	// the smallest value in TopN (even though there is capacity for it).
	listener.accounts = make([]basics.AccountDetail, 3, 10)
	listener.accounts[0] = onlineDetail(byte(0), 15)
	listener.accounts[1] = onlineDetail(byte(1), 10)
	listener.accounts[2] = onlineDetail(byte(2), 5)

	balanceUpdate.Round++
	balanceUpdate.Accounts = []basics.AccountDetail{onlineDetail(byte(3), 1)}
	block = makeBlockWithTxnFor([]byte{5}, []byte{3})
	listener.update(block, balanceUpdate)

	if err := verifyListener(listener, []uint64{15, 10, 5}, 100000, 99999999, 5); err != nil {
		t.Error(err)
	}

	// Invalid round truncates accounts slice
	listener.update(block, balanceUpdate)
	if len(listener.accounts) != 0 {
		t.Errorf("Accounts should be truncated to zero after unexpected round: len(topN) = %d", len(listener.accounts))
	}
}

func TestInit(t *testing.T) {
	testpartitioning.PartitionTest(t)

	listener := makeTopAccountListener(logging.Base())

	// "init" should remove existing values before adding new ones.
	balanceUpdate := basics.BalanceDetail{
		Accounts:    make([]basics.AccountDetail, 0, 10),
		Round:       2,
		OnlineMoney: basics.MicroAlgos{Raw: 100},
		TotalMoney:  basics.MicroAlgos{Raw: 100},
	}

	listener.accounts = append(listener.accounts, onlineDetail(byte(10), 100))
	balanceUpdate.Accounts = []basics.AccountDetail{onlineDetail(byte(1), 1)}

	listener.init(balanceUpdate)

	if err := verifyListener(listener, []uint64{1}, 100, 100, 2); err != nil {
		t.Error(err)
	}
}

func makeBlockWithTxnFor(senders []byte, receivers []byte) bookkeeping.Block {
	var blk bookkeeping.Block

	paysets := make([]transactions.SignedTxnInBlock, 0, len(receivers))
	for i, b := range receivers {
		txib, err := blk.EncodeSignedTxn(transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender: basics.Address{senders[i]},
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: basics.Address{b},
					// If this ends up being used by topAccountListener, add it here.
					// Amount: basics.MicroAlgos{123},
				},
			}}, transactions.ApplyData{})
		if err != nil {
			panic(err)
		}

		paysets = append(paysets, txib)
	}

	blk.Payset = paysets
	return blk
}

// Helpers for working with data objects.
func onlineDetail(b byte, bal uint64) basics.AccountDetail {
	return detail(b, bal, true)
}

func detail(b byte, bal uint64, isOnline bool) basics.AccountDetail {
	state := basics.Offline
	if isOnline {
		state = basics.Online
	}
	return basics.AccountDetail{
		Address: basics.Address{b},
		Algos:   basics.MicroAlgos{Raw: bal},
		Status:  state,
	}
}

func getInt(detail basics.AccountDetail) uint64 {
	return uint64([32]byte(detail.Address)[0])
}

func verifyAccountBalances(expected []uint64, actual []basics.AccountDetail) error {
	if len(expected) != len(actual) {
		return &errorString{fmt.Sprintf("Lengths do not equal: expected(%d) != actual(%d)", len(expected), len(actual))}
	}

	for i, a := range actual {
		if expected[i] != a.Algos.Raw {
			return &errorString{fmt.Sprintf("Unexpected result at actual[%d]: expected(%d) != actual(%d)", i, expected[i], a.Algos.Raw)}
		}
	}

	return nil
}

func verifyListener(listener topAccountListener, expected []uint64, online uint64, total uint64, round uint64) error {
	if listener.round != basics.Round(round) {
		return &errorString{fmt.Sprintf("Unexpected round: actual(%d) != expected(%d)", uint64(listener.round), round)}
	}

	if listener.onlineCirculation.Raw != online {
		return &errorString{fmt.Sprintf("Unexpected online circulation: actual(%d) != expected(%d)", listener.onlineCirculation.Raw, online)}
	}

	if listener.totalCirculation.Raw != total {
		return &errorString{fmt.Sprintf("Unexpected total circulation: actual(%d) != expected(%d)", listener.totalCirculation.Raw, total)}
	}

	return verifyAccountBalances(expected, listener.accounts)
}
