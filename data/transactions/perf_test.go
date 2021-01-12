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

package transactions

import (
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

func BenchmarkEncoding(b *testing.B) {
	var stxn SignedTxn
	stxn.Txn.Type = protocol.PaymentTx
	crypto.RandBytes(stxn.Sig[:])
	crypto.RandBytes(stxn.Txn.Sender[:])
	crypto.RandBytes(stxn.Txn.Receiver[:])
	stxn.Txn.Amount.Raw = crypto.RandUint64()
	stxn.Txn.Fee.Raw = crypto.RandUint64()
	stxn.Txn.FirstValid = basics.Round(crypto.RandUint64())
	stxn.Txn.LastValid = basics.Round(crypto.RandUint64())

	b.Run("Encode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			protocol.Encode(&stxn)
		}
	})

	b.Run("EncodeLen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			stxn.GetEncodedLength()
		}
	})

	b.Run("ID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			stxn.Txn.ID()
		}
	})
}
