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

package generickv

import (
	"context"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

func (w *accountsWriter) AccountsReset(ctx context.Context) error {
	// TODO: catchpoint
	return nil
}

func (w *accountsWriter) ResetAccountHashes(ctx context.Context) (err error) {
	// TODO: catchpoint
	return
}

func (w *accountsWriter) TxtailNewRound(ctx context.Context, baseRound basics.Round, roundData [][]byte, forgetBeforeRound basics.Round) error {
	// The SQL at the time fo writing:
	//
	// for i, data := range roundData:
	// 		the inserted rnd value is baseRound + i
	//
	// 		INSERT INTO txtail(rnd, data) VALUES(?, ?)
	//
	// then it also cleans up everything before `forgetBeforeRound`:
	//
	// DELETE FROM txtail WHERE rnd < ?

	// insert the new txTail's
	for i, data := range roundData {
		rnd := basics.Round(int(baseRound) + i)
		key := txTailKey(rnd)
		err := w.kvw.Set(key[:], data)
		if err != nil {
			return err
		}
	}

	// delete old ones
	start, end := txTailRoundRangePrefix(forgetBeforeRound)
	err := w.kvw.DeleteRange(start[:], end[:])
	if err != nil {
		return err
	}

	return nil
}

func (w *accountsWriter) UpdateAccountsRound(rnd basics.Round) (err error) {
	// The SQL at the time of writing:
	//
	// UPDATE acctrounds SET rnd=? WHERE id='acctbase' AND rnd<?",

	// TODO: read the row for sanity? wont help the kv with race conditions, but we will need it for test parity
	//       inside a batch we wont have a read ptr..

	// write round entry
	raw := bigEndianUint64(uint64(rnd))
	key := roundKey()
	err = w.kvw.Set(key[:], raw[:])
	if err != nil {
		return err
	}

	return nil
}

func (w *accountsWriter) UpdateAccountsHashRound(ctx context.Context, hashRound basics.Round) (err error) {
	// TODO: catchpoint
	return nil
}

func (w *accountsWriter) AccountsPutTotals(totals ledgercore.AccountTotals, catchpointStaging bool) (err error) {
	// The SQL at the time of impl:
	//
	// id := ""
	// if catchpointStaging {
	// 	id = "catchpointStaging"
	// }
	// "REPLACE INTO accounttotals
	//		(id, online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel)
	// VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

	// write totals entry
	raw := protocol.Encode(&totals)
	key := totalsKey(catchpointStaging)
	err = w.kvw.Set(key[:], raw)
	if err != nil {
		return err
	}

	return nil
}

func (w *accountsWriter) OnlineAccountsDelete(forgetBefore basics.Round) (err error) {
	// The SQL at the time of impl:
	//
	// SELECT
	//		rowid, address, updRound, data
	// FROM onlineaccounts
	// WHERE updRound < ?
	// ORDER BY address, updRound DESC
	//
	// The it would delete by  rowid in chunks with:
	//
	// 		DELETE FROM onlineaccounts WHERE rowid IN (..)

	// On the KV implmentation:
	//
	// We have two ranges of keys associated with online accounts:
	// - the `onlineAccountKey(address, round)` -> "-".join(kvPrefixOnlineAccount, addr, round)
	// - and the `onlineAccountBalanceKey(round, normBalance, addr) -> "-".join(kvPrefixOnlineAccountBalance, round, normBalance, addr)

	// 1. read from the `onlineAccountBalanceKey` range since we need the addresses that will need to be deleted
	start, end := onlineAccountBalanceForRoundRangePrefix(forgetBefore)
	iter := w.kvr.NewIter(start[:], end[:], true)
	defer iter.Close()

	seenAddrs := make(map[basics.Address]struct{})

	toDeletePrimaryIndex := make([]struct {
		basics.Address
		basics.Round
	}, 0)

	toDeleteSecondaryIndex := make([][]byte, 0)

	// loop through the rounds in reverse order (latest first)
	for iter.Next() {
		key := iter.Key()

		// extract address & round from the key
		addr := extractOnlineAccountBalanceAddress(key)
		round := extractOnlineAccountBalanceRound(key)

		// check that we have NOT seen this address before
		if _, ok := seenAddrs[addr]; !ok {
			// new address
			// if the first time (latest in rnd, order reversed) we see it the entry is:
			//  - offline -> then delete all
			//  - online -> then safe to delete all previous except this first (latest)

			// check if voting data is empty (it means the account is offline)
			var oad trackerdb.BaseOnlineAccountData
			var data []byte
			data, err = iter.Value()
			if err != nil {
				return err
			}
			err = protocol.Decode(data, &oad)
			if err != nil {
				return err
			}
			if oad.IsVotingEmpty() {
				// delete this entry (all subsequent will be deleted too outside the if)
				toDeletePrimaryIndex = append(toDeletePrimaryIndex, struct {
					basics.Address
					basics.Round
				}{addr, round})
				toDeleteSecondaryIndex = append(toDeleteSecondaryIndex, key)
			}

			// mark addr as seen
			seenAddrs[addr] = struct{}{}

			// restart the loop
			// if there are some subsequent entries, they will deleted on the next iteration
			// if no subsequent entries, the loop will reset the state and the latest entry does not get deleted
			continue
		}

		// mark the item for deletion
		toDeletePrimaryIndex = append(toDeletePrimaryIndex, struct {
			basics.Address
			basics.Round
		}{addr, round})
		toDeleteSecondaryIndex = append(toDeleteSecondaryIndex, key)
	}

	// 2. delete the individual addr+round entries
	for _, item := range toDeletePrimaryIndex {
		// TODO: [perf] we might be able to optimize this with a SingleDelete call
		key := onlineAccountKey(item.Address, item.Round)
		err = w.kvw.Delete(key[:])
		if err != nil {
			return
		}
	}

	// 3. delete the range from `onlineAccountBalanceKey`
	for _, key := range toDeleteSecondaryIndex {
		// TODO: [perf] we might be able to optimize this with a SingleDelete call
		err = w.kvw.Delete(key)
		if err != nil {
			return
		}
	}

	return
}

func (w *accountsWriter) AccountsPutOnlineRoundParams(onlineRoundParamsData []ledgercore.OnlineRoundParamsData, startRound basics.Round) error {
	// The SQL at the time of impl:
	//
	// for i, data := range onlineRoundParamsData {
	// 		the inserted rnd value is startRound + i
	//
	//		INSERT INTO onlineroundparamstail (rnd, data) VALUES (?, ?)
	//

	// insert the round params
	for i := range onlineRoundParamsData {
		rnd := basics.Round(int(startRound) + i)
		raw := protocol.Encode(&onlineRoundParamsData[i])
		key := onlineAccountRoundParamsKey(rnd)
		err := w.kvw.Set(key[:], raw)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *accountsWriter) AccountsPruneOnlineRoundParams(deleteBeforeRound basics.Round) error {
	// The SQL at the time of impl:
	//
	// DELETE FROM onlineroundparamstail WHERE rnd<?

	// delete old ones
	start, end := onlineAccountRoundParamsRoundRangePrefix(deleteBeforeRound)
	err := w.kvw.DeleteRange(start[:], end[:])
	if err != nil {
		return err
	}

	return nil
}
