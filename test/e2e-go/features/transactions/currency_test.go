// Copyright (C) 2019 Algorand, Inc.
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

package transactions

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

type currencyIDParams struct {
	idx uint64
	params v1.CurrencyParams
}

func helperFillSignBroadcast(client libgoal.Client, wh []byte, sender string, tx transactions.Transaction, err error) (string, error) {
	if err != nil {
		return "", err
	}

	tx, err = client.FillUnsignedTxTemplate(sender, 0, 0, 0, tx)
	if err != nil {
		return "", err
	}

	return client.SignAndBroadcastTransaction(wh, nil, tx)
}

func TestCurrencyConfig(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	manager, err := client.GenerateAddress(wh)
	a.NoError(err)

	reserve, err := client.GenerateAddress(wh)
	a.NoError(err)

	freeze, err := client.GenerateAddress(wh)
	a.NoError(err)

	clawback, err := client.GenerateAddress(wh)
	a.NoError(err)

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 100000000, nil)
	a.NoError(err)

	// There should be no currencies to start with
	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.CurrencyParams), 0)

	// Create max number of currencies
	txids := make(map[string]string)
	for i := 0; i < config.Consensus[protocol.ConsensusFuture].MaxCurrenciesPerAccount; i++ {
		tx, err := client.MakeUnsignedCurrencyCreateTx(1+uint64(i), false, manager, reserve, freeze, clawback, fmt.Sprintf("test%d", i))
		txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
		a.NoError(err)
		txids[txid] = account0
	}

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "creating max number of currencies")

	// Creating more currencies should return an error
	tx, err := client.MakeUnsignedCurrencyCreateTx(1, false, manager, reserve, freeze, clawback, fmt.Sprintf("toomany"))
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

	// Check that currencies are visible
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.CurrencyParams), config.Consensus[protocol.ConsensusFuture].MaxCurrenciesPerAccount)
	var currencies []currencyIDParams
	for idx, cp := range info.CurrencyParams {
		currencies = append(currencies, currencyIDParams{idx, cp})
		a.Equal(cp.UnitName, fmt.Sprintf("test%d", cp.Total-1))
		a.Equal(cp.ManagerAddr, manager)
		a.Equal(cp.ReserveAddr, reserve)
		a.Equal(cp.FreezeAddr, freeze)
		a.Equal(cp.ClawbackAddr, clawback)
	}

	// Test changing various keys
	var empty string
	txids = make(map[string]string)

	tx, err = client.MakeUnsignedCurrencyConfigTx(account0, currencies[0].idx, &account0, nil, nil, nil)
	txid, err := helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedCurrencyConfigTx(account0, currencies[1].idx, nil, &account0, nil, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedCurrencyConfigTx(account0, currencies[2].idx, nil, nil, &account0, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedCurrencyConfigTx(account0, currencies[3].idx, nil, nil, nil, &account0)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedCurrencyConfigTx(account0, currencies[4].idx, nil, &empty, nil, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedCurrencyConfigTx(account0, currencies[5].idx, nil, nil, &empty, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedCurrencyConfigTx(account0, currencies[6].idx, nil, nil, nil, &empty)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "changing keys")

	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.CurrencyParams), config.Consensus[protocol.ConsensusFuture].MaxCurrenciesPerAccount)
	for idx, cp := range info.CurrencyParams {
		a.Equal(cp.UnitName, fmt.Sprintf("test%d", cp.Total-1))

		if idx == currencies[0].idx {
			a.Equal(cp.ManagerAddr, account0)
		} else {
			a.Equal(cp.ManagerAddr, manager)
		}

		if idx == currencies[1].idx {
			a.Equal(cp.ReserveAddr, account0)
		} else if idx == currencies[4].idx {
			a.Equal(cp.ReserveAddr, "")
		} else {
			a.Equal(cp.ReserveAddr, reserve)
		}

		if idx == currencies[2].idx {
			a.Equal(cp.FreezeAddr, account0)
		} else if idx == currencies[5].idx {
			a.Equal(cp.FreezeAddr, "")
		} else {
			a.Equal(cp.FreezeAddr, freeze)
		}

		if idx == currencies[3].idx {
			a.Equal(cp.ClawbackAddr, account0)
		} else if idx == currencies[6].idx {
			a.Equal(cp.ClawbackAddr, "")
		} else {
			a.Equal(cp.ClawbackAddr, clawback)
		}
	}

	// Should not be able to close account before destroying currencies
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.Error(err)

	// Destroy currencies
	txids = make(map[string]string)
	for idx := range info.CurrencyParams {
		tx, err := client.MakeUnsignedCurrencyDestroyTx(account0, idx)
		sender := manager
		if idx == currencies[0].idx {
			sender = account0
		}
		txid, err := helperFillSignBroadcast(client, wh, sender, tx, err)
		a.NoError(err)
		txids[txid] = sender
	}

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "destroying currencies")

	// Should be able to close now
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}

func TestCurrencySend(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	manager, err := client.GenerateAddress(wh)
	a.NoError(err)

	reserve, err := client.GenerateAddress(wh)
	a.NoError(err)

	freeze, err := client.GenerateAddress(wh)
	a.NoError(err)

	clawback, err := client.GenerateAddress(wh)
	a.NoError(err)

	extra, err := client.GenerateAddress(wh)
	a.NoError(err)

	// Fund the manager, freeze, clawback, and extra, so they can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 100000000, nil)
	a.NoError(err)
	_, err = client.SendPaymentFromUnencryptedWallet(account0, freeze, 0, 100000000, nil)
	a.NoError(err)
	_, err = client.SendPaymentFromUnencryptedWallet(account0, clawback, 0, 100000000, nil)
	a.NoError(err)
	_, err = client.SendPaymentFromUnencryptedWallet(account0, extra, 0, 100000000, nil)
	a.NoError(err)

	// Create two currencies: one with default-freeze, and one without default-freeze
	txids := make(map[string]string)

	tx, err := client.MakeUnsignedCurrencyCreateTx(100, false, manager, reserve, freeze, clawback, "nofreeze")
	txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids[txid] = account0

	tx, err = client.MakeUnsignedCurrencyCreateTx(100, true, manager, reserve, freeze, clawback, "frozen")
	txid, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids[txid] = account0

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "creating currencies")

	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.CurrencyParams), 2)
	var frozenIdx, nonFrozenIdx uint64
	for idx, cp := range info.CurrencyParams {
		if cp.UnitName == "frozen" {
			frozenIdx = idx
		}

		if cp.UnitName == "nofreeze" {
			nonFrozenIdx = idx
		}
	}

	// Sending currency to account that hasn't opted in should fail, but
	// after opting in, should succeed for non-frozen currency.
	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

	txids = make(map[string]string)
	tx, err = client.MakeUnsignedCurrencySendTx(account0, frozenIdx, 0, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)
	txids[txid] = extra

	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 0, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)
	txids[txid] = extra

	tx, err = client.MakeUnsignedCurrencySendTx(account0, frozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 10, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids[txid] = account0

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "creating currency slots")

	info, err = client.AccountInformation(extra)
	a.NoError(err)
	a.Equal(len(info.Currencies), 2)
	a.Equal(info.Currencies[frozenIdx].Amount, uint64(0))
	a.Equal(info.Currencies[frozenIdx].Frozen, true)
	a.Equal(info.Currencies[nonFrozenIdx].Amount, uint64(10))
	a.Equal(info.Currencies[nonFrozenIdx].Frozen, false)

	// Should not be able to send more than is available
	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 11, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.Error(err)

	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 10, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)

	// Swap frozen status on the extra account (and the wrong address should not
	// be able to change frozen status)
	tx, err = client.MakeUnsignedCurrencyFreezeTx(account0, nonFrozenIdx, extra, true)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

	tx, err = client.MakeUnsignedCurrencyFreezeTx(account0, nonFrozenIdx, extra, true)
	_, err = helperFillSignBroadcast(client, wh, freeze, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedCurrencyFreezeTx(account0, frozenIdx, extra, false)
	_, err = helperFillSignBroadcast(client, wh, freeze, tx, err)
	a.NoError(err)

	// Should be able to send money to the now-unfrozen account,
	// but should not be able to send money from the now-frozen account.
	tx, err = client.MakeUnsignedCurrencySendTx(account0, frozenIdx, 10, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.Error(err)

	// Clawback should be able to claim money out of both frozen and non-frozen accounts,
	// and the wrong address should not be able to clawback.
	txids = make(map[string]string)
	tx, err = client.MakeUnsignedCurrencySendTx(account0, frozenIdx, 5, account0, "", extra)
	txid, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.NoError(err)
	txids[txid] = clawback

	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 5, account0, "", extra)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 5, account0, "", extra)
	txid, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.NoError(err)
	txids[txid] = clawback

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "clawback")

	// Check that the currency balances are correct
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.Currencies), 2)
	a.Equal(info.Currencies[frozenIdx].Amount, uint64(95))
	a.Equal(info.Currencies[nonFrozenIdx].Amount, uint64(95))

	info, err = client.AccountInformation(extra)
	a.NoError(err)
	a.Equal(len(info.Currencies), 2)
	a.Equal(info.Currencies[frozenIdx].Amount, uint64(5))
	a.Equal(info.Currencies[nonFrozenIdx].Amount, uint64(5))

	// Should be able to close out currency slots and close entire account.
	tx, err = client.MakeUnsignedCurrencyFreezeTx(account0, nonFrozenIdx, extra, false)
	_, err = helperFillSignBroadcast(client, wh, freeze, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedCurrencySendTx(account0, nonFrozenIdx, 0, "", account0, "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedCurrencySendTx(account0, frozenIdx, 0, "", account0, "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)

	_, err = client.SendPaymentFromWallet(wh, nil, extra, "", 0, 0, nil, account0, 0, 0)
	a.NoError(err)
}
