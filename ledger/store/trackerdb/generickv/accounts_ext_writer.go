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
	"context"
	"encoding/binary"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
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
		err := w.kvw.Set(txTailKey(rnd), data)
		if err != nil {
			return err
		}
	}

	// delete old ones
	start := []byte(kvTxTail + "-")
	end := txTailKey(forgetBeforeRound)
	err := w.kvw.DeleteRange(start, end)
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
	err = w.kvw.Set(roundKey(), raw)
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
	err = w.kvw.Set(totalsKey(catchpointStaging), raw)
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

	// 1. read from the `onlineAccountBalanceKey` range since we can the addr's that will need to be deleted
	start := []byte(kvPrefixOnlineAccountBalance + "-")
	end := []byte(kvPrefixOnlineAccountBalance + "-")
	end = append(end, bigEndianUint64(uint64(forgetBefore))...)
	iter := w.kvr.NewIter(start, end, false)
	defer iter.Close()

	toDelete := make([]struct {
		basics.Address
		basics.Round
	}, 0)

	for iter.Next() {
		// read the key
		// schema: <prefix>-<rnd>-<balance>-<addr>
		key := iter.Key()

		// extract the round from the key (offset: 1)
		rndOffset := len(kvPrefixOnlineAccountBalance) + 1
		u64Rnd := binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])
		round := basics.Round(u64Rnd)

		// get the offset where the address starts
		addrOffset := len(kvPrefixOnlineAccountBalance) + 1 + 8 + 1 + 8 + 1
		var addr basics.Address
		copy(addr[:], key[addrOffset:addrOffset+32])

		// mark the item for deletion
		toDelete = append(toDelete, struct {
			basics.Address
			basics.Round
		}{addr, round})
	}

	// 2. delete the individual addr+round entries
	for _, item := range toDelete {
		// TODO: [perf] we might be able to optimize this with a SingleDelete call
		err = w.kvw.Delete(onlineAccountKey(item.Address, item.Round))
		if err != nil {
			return
		}
	}

	// 3. delete the range from `onlineAccountBalanceKey`
	err = w.kvw.DeleteRange(start, end)
	if err != nil {
		return err
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
	for i, params := range onlineRoundParamsData {
		rnd := basics.Round(int(startRound) + i)
		raw := protocol.Encode(&params)
		err := w.kvw.Set(onlineAccountRoundParamsKey(rnd), raw)
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
	start := []byte(kvOnlineAccountRoundParams + "-")
	end := onlineAccountRoundParamsKey(deleteBeforeRound)
	err := w.kvw.DeleteRange(start, end)
	if err != nil {
		return err
	}

	return nil
}
