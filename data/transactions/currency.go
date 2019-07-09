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

// CurrencyAllocTxnFields captures the fields used for sub-currency allocation transactions.
type CurrencyAllocTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// CurrencyTotal is the total amount of currency to allocate
	// (if allocating), or zero in order to destroy the sub-currency.
	CurrencyTotal uint64 `codec:"ctot"`
}

// CurrencyTransferTxnFields captures the fields used for sub-currency transfers.
type CurrencyTransferTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	CurrencyID basics.Address `codec:"cid"`

	// CurrencyAmount is the amount of sub-currency to transfer.
	// A zero amount transferred to self allocates that sub-currency
	// in the account's Currencies map.
	CurrencyAmount uint64 `codec:"camt"`

	// CurrencyReceiver is the recipient of the transfer.
	CurrencyReceiver basics.Address `codec:"crcv"`

	// CurrencyCloseTo indicates that the sub-currency should be removed
	// from the account's Currencies map, and specifies where the remaining
	// currency holdings should be transferred.  It's always valid to transfer
	// remaining currency holdings to the CurrencyID account.
	CurrencyCloseTo basics.Address `codec:"cclose"`
}

func clone(m map[basics.Address]uint64) map[basics.Address]uint64 {
	res := make(map[basics.Address]uint64)
	for id, val := range m {
		res[id] = val
	}
	return res
}

func (ca CurrencyAllocTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	record, err := balances.Get(header.Sender)
	if err != nil {
		return err
	}
	record.Currencies = clone(record.Currencies)

	if ca.CurrencyTotal > 0 {
		// If we are trying to allocate, there must not be an existing allocation.
		if record.ThisCurrencyTotal > 0 {
			return fmt.Errorf("sub-currency already allocated: ThisCurrencyTotal %d, requested total %d", record.ThisCurrencyTotal, ca.CurrencyTotal)
		}

		record.ThisCurrencyTotal = ca.CurrencyTotal
		record.Currencies[header.Sender] = ca.CurrencyTotal
		return balances.Put(record)
	}

	// CurrencyTotal==0 means destroy sub-currency
	if record.ThisCurrencyTotal == 0 {
		return fmt.Errorf("sub-currency not allocated")
	}

	// If we are trying to destroy a currency, this account must hold the
	// entire outstanding sub-currency amount.
	if record.Currencies[header.Sender] != record.ThisCurrencyTotal {
		return fmt.Errorf("cannot destroy sub-currency: holding only %d/%d", record.Currencies[header.Sender], record.ThisCurrencyTotal)
	}

	delete(record.Currencies, header.Sender)
	record.ThisCurrencyTotal = 0
	return balances.Put(record)
}

func (ct CurrencyTransferTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	if ct.CurrencyAmount > 0 || ct.CurrencyReceiver != (basics.Address{}) {
		snd, err := balances.Get(header.Sender)
		if err != nil {
			return err
		}

		snd.Currencies = clone(snd.Currencies)
		if snd.Currencies[ct.CurrencyID] < ct.CurrencyAmount {
			return fmt.Errorf("sub-currency balance %d less than transfer amount %d", snd.Currencies[ct.CurrencyID], ct.CurrencyAmount)
		}
		snd.Currencies[ct.CurrencyID] = snd.Currencies[ct.CurrencyID] - ct.CurrencyAmount
		err = balances.Put(snd)
		if err != nil {
			return err
		}

		rcv, err := balances.Get(ct.CurrencyReceiver)
		if err != nil {
			return err
		}

		rcv.Currencies = clone(rcv.Currencies)
		_, ok := rcv.Currencies[ct.CurrencyID]
		if !ok {
			return fmt.Errorf("sub-currency not present in receiver account")
		}
		rcv.Currencies[ct.CurrencyID] = rcv.Currencies[ct.CurrencyID] + ct.CurrencyAmount
		err = balances.Put(rcv)
		if err != nil {
			return err
		}
	}

	if ct.CurrencyCloseTo != (basics.Address{}) {
		// Cannot close currency ID allocated by this account; must use destroy.
		if ct.CurrencyID == header.Sender {
			return fmt.Errorf("cannot close sub-currency ID of allocating account")
		}

		snd, err := balances.Get(header.Sender)
		if err != nil {
			return err
		}

		snd.Currencies = clone(snd.Currencies)
		amt := snd.Currencies[ct.CurrencyID]
		delete(snd.Currencies, ct.CurrencyID)
		err = balances.Put(snd)
		if err != nil {
			return err
		}

		if amt > 0 {
			rcv, err := balances.Get(ct.CurrencyCloseTo)
			if err != nil {
				return err
			}

			rcv.Currencies = clone(rcv.Currencies)
			_, ok := rcv.Currencies[ct.CurrencyID]
			if !ok {
				return fmt.Errorf("sub-currency not present in close-to account")
			}
			rcv.Currencies[ct.CurrencyID] = rcv.Currencies[ct.CurrencyID] + amt
			err = balances.Put(rcv)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
