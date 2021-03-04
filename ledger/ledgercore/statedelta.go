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

package ledgercore

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

// ModifiedCreatable defines the changes to a single single creatable state
type ModifiedCreatable struct {
	// Type of the creatable: app or asset
	Ctype basics.CreatableType

	// Created if true, deleted if false
	Created bool

	// creator of the app/asset
	Creator basics.Address

	// Keeps track of how many times this app/asset appears in
	// accountUpdates.creatableDeltas
	Ndeltas int
}

// A Txlease is a transaction (sender, lease) pair which uniquely specifies a
// transaction lease.
type Txlease struct {
	Sender basics.Address
	Lease  [32]byte
}

// StateDelta describes the delta between a given round to the previous round
type StateDelta struct {
	// modified accounts
	Accts AccountDeltas

	// new Txids for the txtail and TxnCounter, mapped to txn.LastValid
	Txids map[transactions.Txid]basics.Round

	// new txleases for the txtail mapped to expiration
	Txleases map[Txlease]basics.Round

	// new creatables creator lookup table
	Creatables map[basics.CreatableIndex]ModifiedCreatable

	// new block header; read-only
	Hdr *bookkeeping.BlockHeader

	// next round for which we expect a compact cert.
	// zero if no compact cert is expected.
	CompactCertNext basics.Round

	// previous block timestamp
	PrevTimestamp int64
}

// AccountDeltas stores ordered accounts and allows fast lookup by address
type AccountDeltas struct {
	// actual data
	accts []basics.BalanceRecord
	// cache for addr to deltas index resolution
	acctsCache map[basics.Address]int
}

// MakeStateDelta creates a new instance of StateDelta
func MakeStateDelta(hdr *bookkeeping.BlockHeader, prevTimestamp int64, hint int) StateDelta {
	return StateDelta{
		Accts: AccountDeltas{
			accts:      make([]basics.BalanceRecord, 0, hint*2),
			acctsCache: make(map[basics.Address]int, hint*2),
		},
		Txids:         make(map[transactions.Txid]basics.Round, hint),
		Txleases:      make(map[Txlease]basics.Round, hint),
		Creatables:    make(map[basics.CreatableIndex]ModifiedCreatable, hint),
		Hdr:           hdr,
		PrevTimestamp: prevTimestamp,
	}
}

// Get lookups AccountData by address
func (ad *AccountDeltas) Get(addr basics.Address) (basics.AccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return basics.AccountData{}, false
	}
	return ad.accts[idx].AccountData, true
}

// ModifiedAccounts returns list of addresses of modified accounts
func (ad *AccountDeltas) ModifiedAccounts() []basics.Address {
	result := make([]basics.Address, len(ad.accts))
	for i := 0; i < len(ad.accts); i++ {
		result[i] = ad.accts[i].Addr
	}
	return result
}

// MergeAccounts applies other accounts into this StateDelta accounts
func (ad *AccountDeltas) MergeAccounts(other AccountDeltas) {
	for new := range other.accts {
		ad.upsert(other.accts[new])
	}
}

// Len returns number of stored accounts
func (ad *AccountDeltas) Len() int {
	return len(ad.accts)
}

// GetByIdx returns address and AccountData
// It does NOT check boundaries.
func (ad *AccountDeltas) GetByIdx(i int) (basics.Address, basics.AccountData) {
	return ad.accts[i].Addr, ad.accts[i].AccountData
}

// Upsert adds new or updates existing account account
func (ad *AccountDeltas) Upsert(addr basics.Address, data basics.AccountData) {
	ad.upsert(basics.BalanceRecord{Addr: addr, AccountData: data})
}

func (ad *AccountDeltas) upsert(br basics.BalanceRecord) {
	addr := br.Addr
	if idx, exist := ad.acctsCache[addr]; exist { // nil map lookup is OK
		ad.accts[idx] = br
		return
	}

	last := len(ad.accts)
	ad.accts = append(ad.accts, br)

	if ad.acctsCache == nil {
		ad.acctsCache = make(map[basics.Address]int)
	}
	ad.acctsCache[addr] = last
}
