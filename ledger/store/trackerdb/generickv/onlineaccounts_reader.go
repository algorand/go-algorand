// Copyright (C) 2019-2025 Algorand, Inc.
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

	// addr is set in the sqlite impl even if we dont find the account
	data.Addr = addr

	// read latest account up to `rnd``
	low, high := onlineAccountLatestRangePrefix(addr, rnd)
	iter := r.kvr.NewIter(low[:], high[:], true)
	defer iter.Close()

	var value []byte

	if iter.Next() {
		key := iter.Key()

		// extract round
		updRound := extractOnlineAccountRound(key)

		data.UpdRound = updRound

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

		normBalance := data.AccountData.NormalizedOnlineBalance(r.proto.RewardUnit)
		data.Ref = onlineAccountRef{addr, normBalance, rnd}

		// we have the record, we can leave
		return
	}

	// nothing was found
	// Note: the SQL implementation returns a data value and no error even when the account does not exist.
	return data, nil
}

func (r *accountsReader) LookupOnlineHistory(addr basics.Address) (result []trackerdb.PersistedOnlineAccountData, rnd basics.Round, err error) {
	low, high := onlineAccountAddressRangePrefix(addr)
	iter := r.kvr.NewIter(low[:], high[:], false)
	defer iter.Close()

	var value []byte

	// read the current db round
	rnd, err = r.AccountsRound()
	if err != nil {
		return
	}

	for iter.Next() {
		pitem := trackerdb.PersistedOnlineAccountData{}

		key := iter.Key()

		// extract round
		updRound := extractOnlineAccountRound(key)

		pitem.Addr = addr
		pitem.UpdRound = updRound
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
		pitem.Ref = onlineAccountRef{addr, pitem.AccountData.NormalizedOnlineBalance(r.proto.RewardUnit), pitem.UpdRound}

		// append entry to accum
		result = append(result, pitem)
	}

	return
}

func (r *accountsReader) LookupOnlineRoundParams(rnd basics.Round) (onlineRoundParamsData ledgercore.OnlineRoundParamsData, err error) {
	// SQL impl at time of writing:
	//
	// SELECT data
	// FROM onlineroundparamstail
	// WHERE rnd=?

	key := onlineAccountRoundParamsKey(rnd)
	value, closer, err := r.kvr.Get(key[:])
	if err != nil {
		return
	}
	defer closer.Close()

	err = protocol.Decode(value, &onlineRoundParamsData)
	if err != nil {
		return
	}

	return
}
