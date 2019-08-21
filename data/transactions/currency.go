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

// CurrencyConfigTxnFields captures the fields used for sub-currency
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

// CurrencyTransferTxnFields captures the fields used for sub-currency transfers.
type CurrencyTransferTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	XferCurrency basics.CurrencyID `codec:"xcid"`

	// CurrencyAmount is the amount of sub-currency to transfer.
	// A zero amount transferred to self allocates that sub-currency
	// in the account's Currencies map.
	CurrencyAmount uint64 `codec:"camt"`

	// CurrencySender is the sender of the transfer.  If this is not
	// a zero value, the real transaction sender must be the Clawback
	// address from the CurrencyParams.  If this is the zero value,
	// the currency is sent from the transaction's Sender.
	CurrencySender basics.Address `codec:"csnd"`

	// CurrencyReceiver is the recipient of the transfer.
	CurrencyReceiver basics.Address `codec:"crcv"`

	// CurrencyCloseTo indicates that the sub-currency should be removed
	// from the account's Currencies map, and specifies where the remaining
	// currency holdings should be transferred.  It's always valid to transfer
	// remaining currency holdings to the CurrencyID account.
	CurrencyCloseTo basics.Address `codec:"cclose"`
}

// CurrencyFreezeTxnFields captures the fields used for freezing sub-currency slots.
type CurrencyFreezeTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Account is the address of the account whose sub-currency
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
	creator, err := balances.Get(cid.Creator)
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
		// Allocating a sub-currency.
		record, err := balances.Get(header.Sender)
		if err != nil {
			return err
		}
		record.Currencies = clone(record.Currencies)
		record.CurrencyParams = cloneParams(record.CurrencyParams)

		// Sanity check that there isn't a currency with this counter value.
		_, present := record.CurrencyParams[txnCounter]
		if present {
			return fmt.Errorf("already found a sub-currency with txnCounter=%d", txnCounter)
		}

		cid := basics.CurrencyID{
			Creator: header.Sender,
			Index:   txnCounter,
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

	record, err := balances.Get(cc.ConfigCurrency.Creator)
	if err != nil {
		return err
	}

	record.Currencies = clone(record.Currencies)
	record.CurrencyParams = cloneParams(record.CurrencyParams)

	if cc.CurrencyParams == (basics.CurrencyParams{}) {
		// Destroying a sub-currency.  The creator account must hold
		// the entire outstanding sub-currency amount.
		if record.Currencies[cc.ConfigCurrency].Amount != params.Total {
			return fmt.Errorf("cannot destroy sub-currency: holding only %d/%d", record.Currencies[cc.ConfigCurrency].Amount, params.Total)
		}

		delete(record.Currencies, cc.ConfigCurrency)
		delete(record.CurrencyParams, cc.ConfigCurrency.Index)
	} else {
		// Changing keys in a sub-currency.
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

	if ct.CurrencyAmount > 0 || ct.CurrencyReceiver != (basics.Address{}) {
		snd, err := balances.Get(source)
		if err != nil {
			return err
		}

		snd.Currencies = clone(snd.Currencies)
		sndHolding, ok := snd.Currencies[ct.XferCurrency]
		if !ok {
			// Allocating a slot for sub-currency (self-transfer of zero amount).
			// Initialize holding with default Frozen value.
			if clawback {
				return fmt.Errorf("cannot allocate sub-currency slot via clawback")
			}

			params, err := getParams(balances, ct.XferCurrency)
			if err != nil {
				return err
			}

			sndHolding.Frozen = params.DefaultFrozen
		}

		if sndHolding.Amount < ct.CurrencyAmount {
			return fmt.Errorf("sub-currency balance %d less than transfer amount %d", sndHolding.Amount, ct.CurrencyAmount)
		}

		if ct.CurrencyAmount > 0 && sndHolding.Frozen && !clawback {
			return fmt.Errorf("sub-currency frozen in sender")
		}

		sndHolding.Amount -= ct.CurrencyAmount
		snd.Currencies[ct.XferCurrency] = sndHolding
		err = balances.Put(snd)
		if err != nil {
			return err
		}

		if len(snd.Currencies) > balances.ConsensusParams().MaxCurrenciesPerAccount {
			return fmt.Errorf("too many currencies in account: %d > %d", len(snd.Currencies), balances.ConsensusParams().MaxCurrenciesPerAccount)
		}

		rcv, err := balances.Get(ct.CurrencyReceiver)
		if err != nil {
			return err
		}

		rcv.Currencies = clone(rcv.Currencies)
		rcvHolding, ok := rcv.Currencies[ct.XferCurrency]
		if !ok {
			return fmt.Errorf("sub-currency not present in receiver account")
		}

		if ct.CurrencyAmount > 0 && rcvHolding.Frozen {
			return fmt.Errorf("sub-currency frozen in recipient")
		}

		rcvHolding.Amount += ct.CurrencyAmount
		rcv.Currencies[ct.XferCurrency] = rcvHolding
		err = balances.Put(rcv)
		if err != nil {
			return err
		}
	}

	if ct.CurrencyCloseTo != (basics.Address{}) {
		// Cannot close currency ID allocated by this account; must use destroy.
		if ct.XferCurrency.Creator == source {
			return fmt.Errorf("cannot close sub-currency ID in allocating account")
		}

		snd, err := balances.Get(source)
		if err != nil {
			return err
		}

		snd.Currencies = clone(snd.Currencies)
		sndHolding := snd.Currencies[ct.XferCurrency]
		delete(snd.Currencies, ct.XferCurrency)
		err = balances.Put(snd)
		if err != nil {
			return err
		}

		if sndHolding.Amount > 0 {
			if sndHolding.Frozen && !clawback {
				return fmt.Errorf("sub-currency frozen in sender")
			}

			rcv, err := balances.Get(ct.CurrencyCloseTo)
			if err != nil {
				return err
			}

			rcv.Currencies = clone(rcv.Currencies)
			rcvHolding, ok := rcv.Currencies[ct.XferCurrency]
			if !ok {
				return fmt.Errorf("sub-currency not present in close-to account")
			}

			if rcvHolding.Frozen {
				return fmt.Errorf("sub-currency frozen in recipient")
			}

			rcvHolding.Amount += sndHolding.Amount
			rcv.Currencies[ct.XferCurrency] = rcvHolding
			err = balances.Put(rcv)
			if err != nil {
				return err
			}
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
	record, err := balances.Get(cf.FreezeAccount)
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
