// Copyright (C) 2019-2022 Algorand, Inc.
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

package pooldata

import (
	"math"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// SignedTxGroup used as the in-memory representation of a signed transaction group.
// unlike the plain array of signed transactions, this includes transaction origination and counter
// used by the transaction pool and the transaction sync
//msgp:ignore SignedTxGroup
type SignedTxGroup struct {
	// Transactions contains the signed transactions that are included in this transaction group.
	Transactions SignedTxnSlice
	// LocallyOriginated specify whether the trancation group was inroduced via the REST API or
	// by the transaction sync.
	LocallyOriginated bool
	// GroupCounter is a monotonic increasing counter, that provides an identify for each transaction group.
	// The transaction sync is using it as a way to scan the transactions group list more efficiently, as it
	// can continue scanning the list from the place where it last stopped.
	// GroupCounter is local, assigned when the group is first seen by the local transaction pool.
	GroupCounter uint64
	// GroupTransactionID is the hash of the entire transaction group.
	GroupTransactionID transactions.Txid
	// EncodedLength is the length, in bytes, of the messagepack encoding of all the transaction
	// within this transaction group.
	EncodedLength int
}

// SignedTxnSlice is a slice of SignedTxn(s), allowing us to
// easily define the ID() function.
//msgp:allocbound SignedTxnSlice config.MaxTxGroupSize
type SignedTxnSlice []transactions.SignedTxn

// ID calculate the hash of the signed transaction group.
func (s SignedTxnSlice) ID() transactions.Txid {
	enc := s.MarshalMsg(append(protocol.GetEncodingBuf(), []byte(protocol.TxGroup)...))
	defer protocol.PutEncodingBuf(enc)
	return transactions.Txid(crypto.Hash(enc))
}

// InvalidSignedTxGroupCounter is used to represent an invalid GroupCounter value. It's being used to indicate
// the absence of an entry within a []SignedTxGroup with a particular GroupCounter value.
const InvalidSignedTxGroupCounter = uint64(math.MaxUint64)
