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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

func (r *accountsReader) AccountsRound() (rnd basics.Round, err error) {
	// SQL at time of impl:
	//
	// "SELECT rnd FROM acctrounds WHERE id='acctbase'"

	// read round entry
	value, closer, err := r.kvr.Get(roundKey())
	if err != nil {
		return
	}
	defer closer.Close()

	// parse the bytes into a u64
	rnd = basics.Round(binary.BigEndian.Uint64(value))

	return
}

func (r *accountsReader) AccountsTotals(ctx context.Context, catchpointStaging bool) (totals ledgercore.AccountTotals, err error) {
	// read round entry
	value, closer, err := r.kvr.Get(totalsKey(catchpointStaging))
	if err != nil {
		return
	}
	defer closer.Close()

	err = protocol.Decode(value, &totals)
	if err != nil {
		return
	}

	return
}

func (r *accountsReader) AccountsHashRound(ctx context.Context) (hashrnd basics.Round, err error) {
	// TODO: catchpoint
	return
}

func (r *accountsReader) LookupAccountAddressFromAddressID(ctx context.Context, ref trackerdb.AccountRef) (address basics.Address, err error) {
	// TODO: catchpoint
	return
}

func (r *accountsReader) LookupAccountRowID(addr basics.Address) (ref trackerdb.AccountRef, err error) {
	// Note: [perf] this is not a very cheap operation since we have to pull up the entire record
	acc, err := r.LookupAccount(addr)
	if err != nil {
		return
	}

	if acc.Ref == nil {
		return nil, trackerdb.ErrNotFound
	}

	return acc.Ref, nil
}

func (r *accountsReader) LookupResourceDataByAddrID(accRef trackerdb.AccountRef, aidx basics.CreatableIndex) (data []byte, err error) {
	// TODO: this can probably get removed in favor of LookupResources
	//       the only issue here is that the only caller of this is not doing anything with the ctype
	//       so we might have to change the signature of LookupResources to skip the ctype, which might be reasonable
	xref := accRef.(accountRef)

	value, closer, err := r.kvr.Get(resourceKey(xref.addr, aidx))
	if err != nil {
		return
	}
	defer closer.Close()

	return value, nil
}

func (r *accountsReader) TotalResources(ctx context.Context) (total uint64, err error) {
	// TODO: catchpoint
	return
}

func (r *accountsReader) TotalAccounts(ctx context.Context) (total uint64, err error) {
	// TODO: catchpoint
	return
}

func (r *accountsReader) TotalKVs(ctx context.Context) (total uint64, err error) {
	// TODO: catchpoint
	return
}

// TODO: this replicates some functionality from LookupOnlineHistory, implemented for onlineAccountsReader
func (r *accountsReader) LookupOnlineAccountDataByAddress(addr basics.Address) (ref trackerdb.OnlineAccountRef, data []byte, err error) {
	low := onlineAccountOnlyPartialKey(addr)
	high := onlineAccountOnlyPartialKey(addr)
	high[len(high)-1]++
	iter := r.kvr.NewIter(low, high, true)
	defer iter.Close()

	if iter.Next() {
		// key is <prefix>-<addr>-<rnd> = <content>
		key := iter.Key()

		rndOffset := len(kvPrefixOnlineAccount) + 1 + 32 + 1
		u64Rnd := binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])

		addrOffset := len(kvPrefixOnlineAccount) + 1
		var addr basics.Address
		copy(addr[:], key[addrOffset:addrOffset+32])

		data, err = iter.Value()
		if err != nil {
			return
		}

		var oa trackerdb.BaseOnlineAccountData
		err = protocol.Decode(data, &oa)
		if err != nil {
			return
		}

		ref = onlineAccountRef{
			addr:        addr,
			round:       basics.Round(u64Rnd),
			normBalance: oa.NormalizedOnlineBalance(r.proto),
		}
	} else {
		err = trackerdb.ErrNotFound
		return
	}

	return
}

// AccountsOnlineTop returns the top n online accounts starting at position offset
// (that is, the top offset'th account through the top offset+n-1'th account).
//
// The accounts are sorted by their normalized balance and address.  The normalized
// balance has to do with the reward parts of online account balances.  See the
// normalization procedure in AccountData.NormalizedOnlineBalance().
//
// Note that this does not check if the accounts have a vote key valid for any
// particular round (past, present, or future).
func (r *accountsReader) AccountsOnlineTop(rnd basics.Round, offset uint64, n uint64, proto config.ConsensusParams) (data map[basics.Address]*ledgercore.OnlineAccount, err error) {
	// The SQL before the impl
	// SELECT
	// 		address, normalizedonlinebalance, data, max(updround) FROM onlineaccounts
	// WHERE updround <= ?
	// GROUP BY address HAVING normalizedonlinebalance > 0
	// ORDER BY normalizedonlinebalance DESC, address
	// DESC LIMIT ?
	// OFFSET ?

	// initialize return map
	data = make(map[basics.Address]*ledgercore.OnlineAccount)

	// prepare iter over online accounts (by balance)
	low := []byte(kvPrefixOnlineAccountBalance)
	low = append(low, "-"...)
	high := onlineAccountBalanceOnlyPartialKey(rnd)
	high[len(high)-1]++
	// reverse order iterator to get high-to-low
	iter := r.kvr.NewIter(low, high, true)
	defer iter.Close()

	var value []byte

	// first, drop the results from 0 to the offset
	for i := uint64(0); i < offset; i++ {
		iter.Next()
	}

	// add the other results to the map
	for i := uint64(0); i < n; i++ {
		// if no more results, return early
		if !iter.Next() {
			return
		}

		// key is <prefix>-<rnd>-<balance>-<addr> = <content>
		key := iter.Key()

		// TODO: make this cleaner
		// get the offset where the address starts
		offset := len(kvPrefixOnlineAccountBalance) + 1 + 8 + 1 + 8 + 1

		// extract address
		var addr basics.Address
		copy(addr[:], key[offset:])

		// skip if already in map
		if _, ok := data[addr]; ok {
			continue
		}

		value, err = iter.Value()
		if err != nil {
			return
		}

		oa := trackerdb.BaseOnlineAccountData{}
		err = protocol.Decode(value, &oa)
		if err != nil {
			return
		}
		// load the data as a ledgercore OnlineAccount
		data[addr] = &ledgercore.OnlineAccount{
			Address:                 addr,
			MicroAlgos:              oa.MicroAlgos,
			RewardsBase:             oa.RewardsBase,
			NormalizedOnlineBalance: oa.NormalizedOnlineBalance(proto),
			VoteFirstValid:          oa.VoteFirstValid,
			VoteLastValid:           oa.VoteLastValid,
			StateProofID:            oa.StateProofID,
		}
	}
	return
}

func (r *accountsReader) AccountsOnlineRoundParams() (onlineRoundParamsData []ledgercore.OnlineRoundParamsData, endRound basics.Round, err error) {
	// The SQL at the time of writing:
	//
	// SELECT rnd, data FROM onlineroundparamstail ORDER BY rnd ASC

	start := []byte(kvOnlineAccountRoundParams + "-")
	end := []byte(kvOnlineAccountRoundParams + ".")
	iter := r.kvr.NewIter(start, end, false)
	defer iter.Close()

	var value []byte

	for iter.Next() {
		// read the key
		// schema: <prefix>-<rnd>
		key := iter.Key()

		// extract the round from the key
		rndOffset := len(kvOnlineAccountRoundParams) + 1
		u64Rnd := binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])
		// assign current item round as endRound
		endRound = basics.Round(u64Rnd)

		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return nil, endRound, err
		}

		// decode the param
		roundParams := ledgercore.OnlineRoundParamsData{}
		err = protocol.Decode(value, &roundParams)
		if err != nil {
			return nil, endRound, err
		}

		// add the params to the return list
		onlineRoundParamsData = append(onlineRoundParamsData, roundParams)
	}

	return
}

// OnlineAccountsAll returns all online accounts up to a provided maximum
// the returned list of PersistedOnlineAccountData includes all of the available
// data for each included account in ascending order of account and round
// (example [account-1-round-1, account1-round-2, ..., account2-round-1, ...])
func (r *accountsReader) OnlineAccountsAll(maxAccounts uint64) (data []trackerdb.PersistedOnlineAccountData, err error) {
	// The SQL at the time of impl:
	//
	// SELECT rowid, address, updround, data
	// FROM onlineaccounts
	// ORDER BY address, updround ASC
	//
	// Note: the SQL implementation does not seem to load the current db round to the resulting objects

	// read the current db round
	var round basics.Round
	round, err = r.AccountsRound()
	if err != nil {
		return
	}

	low := []byte(kvPrefixOnlineAccount + "-")
	high := []byte(kvPrefixOnlineAccount + ".")
	iter := r.kvr.NewIter(low, high, false)
	defer iter.Close()

	var value []byte
	var updround uint64

	// keep track of the most recently seen account so we can tally up the total number seen
	lastAddr := basics.Address{}
	seen := uint64(0)

	for iter.Next() {
		pitem := trackerdb.PersistedOnlineAccountData{Round: round}

		// schema: <prefix>-<addr>-<rnd>
		key := iter.Key()

		addrOffset := len(kvPrefixOnlineAccount) + 1
		var addr basics.Address
		copy(addr[:], key[addrOffset:addrOffset+32])
		// extract updround, it's the last section after the "-"

		rndOffset := addrOffset + 32 + 1
		updround = binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])

		// load addr, round and data into the persisted item
		pitem.Addr = addr
		pitem.UpdRound = basics.Round(updround)
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

		// if maxAccounts is supplied, potentially stop reading data if we've collected enough
		if maxAccounts > 0 {
			// we have encountered a new address
			if !bytes.Equal(addr[:], lastAddr[:]) {
				copy(lastAddr[:], addr[:])
				seen++
			}
			// this newest account seen is beyond the maxAccounts requested, meaning we've seen all the data we need
			if seen > maxAccounts {
				return
			}
		}

		// append entry to accum
		data = append(data, pitem)
	}

	return
}

func (r *accountsReader) LoadTxTail(ctx context.Context, dbRound basics.Round) (roundData []*trackerdb.TxTailRound, roundHash []crypto.Digest, baseRound basics.Round, err error) {
	// The SQL at the time of writing:
	//
	// "SELECT rnd, data FROM txtail ORDER BY rnd DESC"

	start := []byte(kvTxTail + "-")
	end := []byte(kvTxTail + ".")
	iter := r.kvr.NewIter(start, end, true)
	defer iter.Close()

	var value []byte

	expectedRound := dbRound
	for iter.Next() {
		// read the key
		key := iter.Key()

		// extract the txTail round from the key
		rndOffset := len(kvTxTail) + 1
		u64Rnd := binary.BigEndian.Uint64(key[rndOffset : rndOffset+8])
		round := basics.Round(u64Rnd)
		// check that we are on the right round
		if round != expectedRound {
			return nil, nil, 0, fmt.Errorf("txtail table contain unexpected round %d; round %d was expected", round, expectedRound)
		}

		// get value for current item in the iterator
		value, err = iter.Value()
		if err != nil {
			return nil, nil, 0, err
		}

		// decode the TxTail
		tail := &trackerdb.TxTailRound{}
		err = protocol.Decode(value, tail)
		if err != nil {
			return nil, nil, 0, err
		}

		// add the tail
		roundData = append(roundData, tail)
		// add the hash
		roundHash = append(roundHash, crypto.Hash(value))

		// step the round down (we expect the "previous" round next..)
		expectedRound--
	}

	// reverse the array ordering in-place so that it would be incremental order.
	for i := 0; i < len(roundData)/2; i++ {
		roundData[i], roundData[len(roundData)-i-1] = roundData[len(roundData)-i-1], roundData[i]
		roundHash[i], roundHash[len(roundHash)-i-1] = roundHash[len(roundHash)-i-1], roundHash[i]
	}
	return roundData, roundHash, expectedRound + 1, nil
}

func (r *accountsReader) LoadAllFullAccounts(ctx context.Context, balancesTable string, resourcesTable string, acctCb func(basics.Address, basics.AccountData)) (count int, err error) {
	// TODO: catchpoint CLI
	return
}

func (r *accountsReader) Testing() trackerdb.TestAccountsReaderExt {
	// TODO: this can wait
	return nil
}
