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

package generickv

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

// LookupOnline pulls the Online Account data for a given account+round
func (r *accountsReader) LookupOnline(addr basics.Address, rnd basics.Round) (data trackerdb.PersistedOnlineAccountData, err error) {
	// SQL at the time of writing this:
	//
	// SELECT
	// 		onlineaccounts.rowid, onlineaccounts.updround,
	//	    acctrounds.rnd,
	//      onlineaccounts.data
	// FROM acctrounds
	//		LEFT JOIN onlineaccounts ON address=? AND updround <= ?
	// WHERE id='acctbase'
	// ORDER BY updround DESC LIMIT 1

	// read the current db round
	data.Round, err = r.AccountsRound()
	if err != nil {
		return
	}

	// read latest account up to `rnd``
	low := onlineAccountOnlyPartialKey(addr)
	high := onlineAccountKey(addr, rnd)
	// inc the last byte to make it inclusive
	high[len(high)-1]++
	iter := r.kvr.NewIter(low, high, true)
	defer iter.Close()

	var value []byte
	var updRound uint64

	if iter.Next() {
		// schema: <prefix>-<addr>-<rnd>
		key := iter.Key()

		// extract updround, its the last section after the "-"
		rndOffset := len(kvPrefixOnlineAccount) + 1 + 32 + 1
		updRound = binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])
		if err != nil {
			return
		}
		data.Addr = addr
		data.UpdRound = basics.Round(updRound)

		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return
		}

		// parse the value
		err = protocol.Decode(value, &data.AccountData)
		if err != nil {
			return
		}

		normBalance := data.AccountData.NormalizedOnlineBalance(r.proto)
		data.Ref = onlineAccountRef{addr, normBalance, rnd}

		// we have the record, we can leave
		return
	}

	// nothing was found
	// Note: the SQL implementation returns a data value and no error even when the account does not exist.
	return data, nil
}

// LookupOnlineTotalsHistory pulls the total Online Algos on a given round
func (r *accountsReader) LookupOnlineTotalsHistory(round basics.Round) (basics.MicroAlgos, error) {
	// SQL at the time of writing this:
	//
	// SELECT data FROM onlineroundparamstail WHERE rnd=?

	value, closer, err := r.kvr.Get(onlineAccountRoundParamsKey(round))
	if err != nil {
		return basics.MicroAlgos{}, err
	}
	defer closer.Close()
	data := ledgercore.OnlineRoundParamsData{}
	err = protocol.Decode(value, &data)
	if err != nil {
		return basics.MicroAlgos{}, err
	}
	return basics.MicroAlgos{Raw: data.OnlineSupply}, nil
}

func (r *accountsReader) LookupOnlineHistory(addr basics.Address) (result []trackerdb.PersistedOnlineAccountData, rnd basics.Round, err error) {
	low := onlineAccountOnlyPartialKey(addr)
	high := onlineAccountOnlyPartialKey(addr)
	high[len(high)-1]++
	iter := r.kvr.NewIter(low, high, false)
	defer iter.Close()

	var value []byte
	var updround uint64

	// read the current db round
	rnd, err = r.AccountsRound()
	if err != nil {
		return
	}

	for iter.Next() {
		pitem := trackerdb.PersistedOnlineAccountData{}

		// schema: <prefix>-<addr>-<rnd>
		key := iter.Key()
		// extract updround, its the last section after the "-"
		rndOffset := len(kvPrefixOnlineAccount) + 1 + 32 + 1
		updround = binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])
		if err != nil {
			return
		}
		pitem.Addr = addr
		pitem.UpdRound = basics.Round(updround)
		// Note: for compatibility with the SQL impl, this is not included on each item
		// pitem.Round = rnd

		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return
		}
		// decode raw value
		err = protocol.Decode(value, &pitem.AccountData)
		if err != nil {
			return
		}

		// set the ref
		pitem.Ref = onlineAccountRef{addr, pitem.AccountData.NormalizedOnlineBalance(r.proto), pitem.UpdRound}

		// append entry to accum
		result = append(result, pitem)
	}

	return
}
