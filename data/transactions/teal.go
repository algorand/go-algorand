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

package transactions

import (
	"bytes"
	"maps"
	"slices"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// EvalDelta stores StateDeltas for an application's global key/value store, as
// well as StateDeltas for some number of accounts holding local state for that
// application
type EvalDelta struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	GlobalDelta basics.StateDelta `codec:"gd"`

	// When decoding EvalDeltas, the integer key represents an offset into
	// [txn.Sender, txn.Accounts[0], txn.Accounts[1], ..., SharedAccts[0], SharedAccts[1], ...]
	LocalDeltas map[uint64]basics.StateDelta `codec:"ld,allocbound=bounds.MaxEvalDeltaAccounts"`

	// If a program modifies the local of an account that is not the Sender, or
	// in txn.Accounts, it must be recorded here, so that the key in LocalDeltas
	// can refer to it.
	SharedAccts []basics.Address `codec:"sa,allocbound=bounds.MaxEvalDeltaAccounts"`

	// The total allocbound calculation here accounts for the worse possible case of having bounds.MaxLogCalls individual log entries
	// with the length of all of them summing up to bounds.MaxEvalDeltaTotalLogSize which is the limit for the sum of individual log lengths
	Logs []string `codec:"lg,allocbound=bounds.MaxLogCalls,maxtotalbytes=(bounds.MaxLogCalls*msgp.StringPrefixSize) + bounds.MaxEvalDeltaTotalLogSize"`

	InnerTxns []SignedTxnWithAD `codec:"itx,allocbound=bounds.MaxInnerTransactionsPerDelta"`
}

// Equal compares two EvalDeltas and returns whether or not they are
// equivalent. It does not care about nilness equality of LocalDeltas,
// because the msgpack codec will encode/decode an empty map as nil, and we want
// an empty generated EvalDelta to equal an empty one we decode off the wire.
func (ed EvalDelta) Equal(o EvalDelta) bool {
	if !maps.EqualFunc(ed.LocalDeltas, o.LocalDeltas, maps.Equal[basics.StateDelta, basics.StateDelta]) {
		return false
	}

	if !ed.GlobalDelta.Equal(o.GlobalDelta) {
		return false
	}

	if !slices.Equal(ed.SharedAccts, o.SharedAccts) {
		return false
	}

	if !slices.Equal(ed.Logs, o.Logs) {
		return false
	}

	if len(ed.InnerTxns) != len(o.InnerTxns) {
		return false
	}
	for i, txn := range ed.InnerTxns {
		if !txn.SignedTxn.equal(o.InnerTxns[i].SignedTxn) {
			return false
		}
		if !txn.ApplyData.Equal(o.InnerTxns[i].ApplyData) {
			return false
		}
	}

	return true
}

// equal compares two SignedTransactions for equality.  It's not
// exported because it ought to be written as (many, very, very
// tedious) field comparisons. == is not defined on almost any of the
// subfields because of slices.
func (stx SignedTxn) equal(o SignedTxn) bool {
	buf1 := protocol.GetEncodingBuf()
	stxenc := stx.MarshalMsg(buf1.Bytes())
	defer protocol.PutEncodingBuf(buf1.Update(stxenc))

	buf2 := protocol.GetEncodingBuf()
	oenc := o.MarshalMsg(buf2.Bytes())
	defer protocol.PutEncodingBuf(buf2.Update(oenc))

	return bytes.Equal(stxenc, oenc)
}
