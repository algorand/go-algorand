// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package rpcs

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestTxSyncResponseDecode covers decoding a txsync response body.
func TestTxSyncResponseDecode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// emptyTxnArray encodes an array of n msgpack nil elements.
	emptyTxnArray := func(n int) []byte {
		var buf bytes.Buffer
		buf.WriteByte(0xdd) // msgpack array32
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(n))
		buf.Write(hdr[:])
		for i := 0; i < n; i++ {
			buf.WriteByte(0xc0) // msgpack nil
		}
		return buf.Bytes()
	}

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		txns := []transactions.SignedTxn{
			{Txn: transactions.Transaction{
				Type:             protocol.PaymentTx,
				Header:           transactions.Header{Sender: basics.Address{1}, Fee: basics.MicroAlgos{Raw: 1000}},
				PaymentTxnFields: transactions.PaymentTxnFields{Receiver: basics.Address{2}, Amount: basics.MicroAlgos{Raw: 7}},
			}},
			{Txn: transactions.Transaction{
				Type:   protocol.KeyRegistrationTx,
				Header: transactions.Header{Sender: basics.Address{3}, Fee: basics.MicroAlgos{Raw: 1000}},
			}},
		}
		var decoded txSyncResponse
		require.NoError(t, protocol.Decode(protocol.EncodeReflect(txns), &decoded))
		require.Equal(t, txns, []transactions.SignedTxn(decoded))
	})

	// a server with nothing to send encodes a nil slice, which is msgpack nil
	t.Run("empty response", func(t *testing.T) {
		t.Parallel()
		var none []transactions.SignedTxn
		var decoded txSyncResponse
		require.NoError(t, protocol.Decode(protocol.EncodeReflect(none), &decoded))
		require.Empty(t, decoded)
	})

	// Reflection decoded msgpack nil into a zero SignedTxn. The generated decoder
	// rejects it, since txn is a required field, though only after allocating from
	// the declared length, which is why the bound below is what limits the allocation.
	t.Run("nil elements", func(t *testing.T) {
		t.Parallel()
		var decoded txSyncResponse
		err := protocol.Decode(emptyTxnArray(8), &decoded)
		require.ErrorContains(t, err, "missing required field: txn")
	})

	// minimal carries only the fields the decoder requires.
	minimal := transactions.SignedTxn{Txn: transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: transactions.Header{Sender: basics.Address{1}},
	}}
	repeated := func(n int) []transactions.SignedTxn {
		txns := make([]transactions.SignedTxn, n)
		for i := range txns {
			txns[i] = minimal
		}
		return txns
	}

	t.Run("at the bound", func(t *testing.T) {
		t.Parallel()
		var decoded txSyncResponse
		require.NoError(t, protocol.Decode(protocol.EncodeReflect(repeated(maxTxSyncResponseTxns)), &decoded))
		require.Len(t, decoded, maxTxSyncResponseTxns)
	})

	// This many transactions exceed the default byte cap when encoded, so the
	// bound also covers a raised TxSyncServeResponseSize.
	t.Run("over the bound", func(t *testing.T) {
		t.Parallel()
		body := protocol.EncodeReflect(repeated(maxTxSyncResponseTxns + 1))
		require.Greater(t, uint64(len(body)), uint64(config.GetDefaultLocal().TxSyncServeResponseSize))

		var decoded txSyncResponse
		err := protocol.Decode(body, &decoded)
		require.ErrorContains(t, err, "length overflow")
		require.Empty(t, decoded, "oversized array was allocated before being rejected")
	})
}
