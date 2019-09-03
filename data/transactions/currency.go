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

	"github.com/algorand/go-algorand/data/basics"
)

// CurrencyConfigTxnFields captures the fields used for currency
// allocation, re-configuration, and destruction.
type CurrencyConfigTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Currency is the currency being configured or destroyed.
	// A zero value (including the creator address) means allocation.
	ConfigCurrency basics.CurrencyID `codec:"ccid"`

	// CurrencyParams are the parameters for the currency being
	// created or re-configured.  A zero value means destruction.
	CurrencyParams basics.CurrencyParams `codec:"cpar"`
}

// CurrencyTransferTxnFields captures the fields used for currency transfers.
type CurrencyTransferTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	XferCurrency basics.CurrencyID `codec:"xcid"`

	// CurrencyAmount is the amount of currency to transfer.
	// A zero amount transferred to self allocates that currency
	// in the account's Currencies map.
	CurrencyAmount uint64 `codec:"camt"`

	// CurrencySender is the sender of the transfer.  If this is not
	// a zero value, the real transaction sender must be the Clawback
	// address from the CurrencyParams.  If this is the zero value,
	// the currency is sent from the transaction's Sender.
	CurrencySender basics.Address `codec:"csnd"`

	// CurrencyReceiver is the recipient of the transfer.
	CurrencyReceiver basics.Address `codec:"crcv"`

	// CurrencyCloseTo indicates that the currency should be removed
	// from the account's Currencies map, and specifies where the remaining
	// currency holdings should be transferred.  It's always valid to transfer
	// remaining currency holdings to the CurrencyID account.
	CurrencyCloseTo basics.Address `codec:"cclose"`
}

// CurrencyFreezeTxnFields captures the fields used for freezing currency slots.
type CurrencyFreezeTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Account is the address of the account whose currency
	// slot is being frozen or un-frozen.
	FreezeAccount basics.Address `codec:"cadd"`

	// Currency is the currency ID being frozen or un-frozen.
	FreezeCurrency basics.CurrencyID `codec:"fcid"`

	// Frozen is the new frozen value.
	CurrencyFrozen bool `codec:"cfrz"`
}

func clone(m map[basics.CurrencyID]basics.CurrencyHolding) map[basics.CurrencyID]basics.CurrencyHolding {
	res := make(map[basics.CurrencyID]basics.CurrencyHolding)
	for id, val := range m {
		res[id] = val
	}
	return res
}

func cloneParams(m map[uint64]basics.CurrencyParams) map[uint64]basics.CurrencyParams {
	res := make(map[uint64]basics.CurrencyParams)
	for id, val := range m {
		res[id] = val
	}
	return res
}

func getParams(balances Balances, cid basics.CurrencyID) (basics.CurrencyParams, error) {
	creator, err := balances.Get(cid.Creator, false)
	if err != nil {
		return basics.CurrencyParams{}, err
	}

	curr, ok := creator.CurrencyParams[cid.Index]
	if !ok {
		return basics.CurrencyParams{}, fmt.Errorf("currency index %d not found in account %v", cid.Index, cid.Creator)
	}

	return curr, nil
}

func (cc CurrencyConfigTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData, txnCounter uint64) error {
	if cc.ConfigCurrency == (basics.CurrencyID{}) {
		// Allocating a currency.
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}
		record.Currencies = clone(record.Currencies)
		record.CurrencyParams = cloneParams(record.CurrencyParams)

		// Ensure index is never zero
		newidx := txnCounter + 1

		// Sanity check that there isn't a currency with this counter value.
		_, present := record.CurrencyParams[newidx]
		if present {
			return fmt.Errorf("already found a currency with index %d", newidx)
		}

		cid := basics.CurrencyID{
			Creator: header.Sender,
			Index:   newidx,
		}

		record.CurrencyParams[cid.Index] = cc.CurrencyParams
		record.Currencies[cid] = basics.CurrencyHolding{
			Amount: cc.CurrencyParams.Total,
		}

		if len(record.Currencies) > balances.ConsensusParams().MaxCurrenciesPerAccount {
			return fmt.Errorf("too many currencies in account: %d > %d", len(record.Currencies), balances.ConsensusParams().MaxCurrenciesPerAccount)
		}

		return balances.Put(record)
	}

	// Re-configuration and destroying must be done by the manager key.
	params, err := getParams(balances, cc.ConfigCurrency)
	if err != nil {
		return err
	}

	if header.Sender != params.Manager {
		return fmt.Errorf("transaction issued by %v, not manager key %v", header.Sender, params.Manager)
	}

	record, err := balances.Get(cc.ConfigCurrency.Creator, false)
	if err != nil {
		return err
	}

	record.Currencies = clone(record.Currencies)
	record.CurrencyParams = cloneParams(record.CurrencyParams)

	if cc.CurrencyParams == (basics.CurrencyParams{}) {
		// Destroying a currency.  The creator account must hold
		// the entire outstanding currency amount.
		if record.Currencies[cc.ConfigCurrency].Amount != params.Total {
			return fmt.Errorf("cannot destroy currency: creator is holding only %d/%d", record.Currencies[cc.ConfigCurrency].Amount, params.Total)
		}

		delete(record.Currencies, cc.ConfigCurrency)
		delete(record.CurrencyParams, cc.ConfigCurrency.Index)
	} else {
		// Changing keys in a currency.
		if !params.Manager.IsZero() {
			params.Manager = cc.CurrencyParams.Manager
		}
		if !params.Reserve.IsZero() {
			params.Reserve = cc.CurrencyParams.Reserve
		}
		if !params.Freeze.IsZero() {
			params.Freeze = cc.CurrencyParams.Freeze
		}
		if !params.Clawback.IsZero() {
			params.Clawback = cc.CurrencyParams.Clawback
		}

		record.CurrencyParams[cc.ConfigCurrency.Index] = params
	}

	return balances.Put(record)
}

func takeOut(balances Balances, addr basics.Address, currency basics.CurrencyID, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	snd, err := balances.Get(addr, false)
	if err != nil {
		return err
	}

	snd.Currencies = clone(snd.Currencies)
	sndHolding, ok := snd.Currencies[currency]
	if !ok {
		return fmt.Errorf("currency %v missing from %v", currency, addr)
	}

	if sndHolding.Frozen && !bypassFreeze {
		return fmt.Errorf("currency %v frozen in %v", currency, addr)
	}

	var overflowed bool
	sndHolding.Amount, overflowed = basics.OSub(sndHolding.Amount, amount)
	if overflowed {
		return fmt.Errorf("underflow on subtracting %d from sender amount %d", amount, sndHolding.Amount)
	}

	snd.Currencies[currency] = sndHolding
	return balances.Put(snd)
}

func putIn(balances Balances, addr basics.Address, currency basics.CurrencyID, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	rcv, err := balances.Get(addr, false)
	if err != nil {
		return err
	}

	rcv.Currencies = clone(rcv.Currencies)
	rcvHolding, ok := rcv.Currencies[currency]
	if !ok {
		return fmt.Errorf("currency %v missing from %v", currency, addr)
	}

	if rcvHolding.Frozen && !bypassFreeze {
		return fmt.Errorf("currency frozen in recipient")
	}

	var overflowed bool
	rcvHolding.Amount, overflowed = basics.OAdd(rcvHolding.Amount, amount)
	if overflowed {
		return fmt.Errorf("overflow on adding %d to receiver amount %d", amount, rcvHolding.Amount)
	}

	rcv.Currencies[currency] = rcvHolding
	return balances.Put(rcv)
}

func (ct CurrencyTransferTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	// Default to sending from the transaction sender's account.
	source := header.Sender
	clawback := false

	if !ct.CurrencySender.IsZero() {
		// Clawback transaction.  Check that the transaction sender
		// is the Clawback address for this currency.
		params, err := getParams(balances, ct.XferCurrency)
		if err != nil {
			return err
		}

		if header.Sender != params.Clawback {
			return fmt.Errorf("clawback not allowed: sender %v != clawback %v", header.Sender, params.Clawback)
		}

		// Transaction sent from the correct clawback address,
		// execute currency transfer from specified source.
		source = ct.CurrencySender
		clawback = true
	}

	// Allocate a slot for currency (self-transfer of zero amount).
	if ct.CurrencyAmount == 0 && ct.CurrencyReceiver == source && !clawback {
		snd, err := balances.Get(source, false)
		if err != nil {
			return err
		}

		snd.Currencies = clone(snd.Currencies)
		sndHolding, ok := snd.Currencies[ct.XferCurrency]
		if !ok {
			// Initialize holding with default Frozen value.
			params, err := getParams(balances, ct.XferCurrency)
			if err != nil {
				return err
			}

			sndHolding.Frozen = params.DefaultFrozen
			snd.Currencies[ct.XferCurrency] = sndHolding

			if len(snd.Currencies) > balances.ConsensusParams().MaxCurrenciesPerAccount {
				return fmt.Errorf("too many currencies in account: %d > %d", len(snd.Currencies), balances.ConsensusParams().MaxCurrenciesPerAccount)
			}

			err = balances.Put(snd)
			if err != nil {
				return err
			}
		}
	}

	// Actually move the currency.  Zero transfers return right away
	// without looking up accounts, so it's fine to have a zero transfer
	// to an all-zero address (e.g., when the only meaningful part of
	// the transaction is the close-to address).
	err := takeOut(balances, source, ct.XferCurrency, ct.CurrencyAmount, clawback)
	if err != nil {
		return err
	}

	err = putIn(balances, ct.CurrencyReceiver, ct.XferCurrency, ct.CurrencyAmount, clawback)
	if err != nil {
		return err
	}

	if ct.CurrencyCloseTo != (basics.Address{}) {
		// Cannot close currency ID allocated by this account; must use destroy.
		if ct.XferCurrency.Creator == source {
			return fmt.Errorf("cannot close currency ID in allocating account")
		}

		// Cannot close by clawback.
		if clawback {
			return fmt.Errorf("cannot close currency by clawback")
		}

		// Figure out how much balance to move.
		snd, err := balances.Get(source, false)
		if err != nil {
			return err
		}

		sndHolding, ok := snd.Currencies[ct.XferCurrency]
		if !ok {
			return fmt.Errorf("currency %v not present in account %v", ct.XferCurrency, source)
		}

		// Move the balance out.
		err = takeOut(balances, source, ct.XferCurrency, sndHolding.Amount, clawback)
		if err != nil {
			return err
		}

		err = putIn(balances, ct.CurrencyCloseTo, ct.XferCurrency, sndHolding.Amount, clawback)
		if err != nil {
			return err
		}

		// Delete the slot from the account.
		snd, err = balances.Get(source, false)
		if err != nil {
			return err
		}

		snd.Currencies = clone(snd.Currencies)
		sndHolding = snd.Currencies[ct.XferCurrency]
		if sndHolding.Amount != 0 {
			return fmt.Errorf("currency %v not zero (%d) after closing", ct.XferCurrency, sndHolding.Amount)
		}

		delete(snd.Currencies, ct.XferCurrency)
		err = balances.Put(snd)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cf CurrencyFreezeTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	// Only the Freeze address can change the freeze value.
	params, err := getParams(balances, cf.FreezeCurrency)
	if err != nil {
		return err
	}

	if header.Sender != params.Freeze {
		return fmt.Errorf("freeze not allowed: sender %v != freeze %v", header.Sender, params.Freeze)
	}

	// Get the account to be frozen/unfrozen.
	record, err := balances.Get(cf.FreezeAccount, false)
	if err != nil {
		return err
	}
	record.Currencies = clone(record.Currencies)

	holding, ok := record.Currencies[cf.FreezeCurrency]
	if !ok {
		return fmt.Errorf("currency not found in account")
	}

	holding.Frozen = cf.CurrencyFrozen
	record.Currencies[cf.FreezeCurrency] = holding
	return balances.Put(record)
}
