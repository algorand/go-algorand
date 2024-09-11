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

package transactions_test

/* These tests are pretty low-value now.  They test something very basic about
   our codec for encoding []byte as base64 strings in json. The test were
   written when BoxRef contained a string instead of []byte.  When that was true,
   these tests were more important because there was work that had to be done to
   make it happen (implement MarshalJSON and UnmarshalJSON) */

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func decode(t *testing.T, data string, v interface{}) {
	t.Helper()
	err := protocol.DecodeJSON([]byte(data), v)
	require.NoErrorf(t, err, "Cannot decode %s", data)
}

func compact(data []byte) string {
	return strings.ReplaceAll(strings.ReplaceAll(string(data), " ", ""), "\n", "")
}

// TestJsonMarshal ensures that BoxRef names are b64 encoded, since they may not be characters.
func TestJsonMarshal(t *testing.T) {
	partitiontest.PartitionTest(t)

	marshal := protocol.EncodeJSON(transactions.BoxRef{Index: 4, Name: []byte("joe")})
	require.Equal(t, `{"i":4,"n":"am9l"}`, compact(marshal))

	marshal = protocol.EncodeJSON(transactions.BoxRef{Index: 0, Name: []byte("joe")})
	require.Equal(t, `{"n":"am9l"}`, compact(marshal))

	marshal = protocol.EncodeJSON(transactions.BoxRef{Index: 1, Name: []byte("")})
	require.Equal(t, `{"i":1}`, compact(marshal))

	marshal = protocol.EncodeJSON(transactions.BoxRef{Index: 0, Name: []byte("")})
	require.Equal(t, `{}`, compact(marshal))
}

// TestJsonUnmarshal ensures that BoxRef unmarshaling expects b64 names
func TestJsonUnmarshal(t *testing.T) {
	partitiontest.PartitionTest(t)
	var br transactions.BoxRef

	decode(t, `{"i":4,"n":"am9l"}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 4, Name: []byte("joe")}, br)

	br = transactions.BoxRef{}
	decode(t, `{"n":"am9l"}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 0, Name: []byte("joe")}, br)

	br = transactions.BoxRef{}
	decode(t, `{"i":4}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 4, Name: nil}, br)

	br = transactions.BoxRef{}
	decode(t, `{}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 0, Name: nil}, br)
}

// TestTxnJson tests a few more things about how our Transactions get JSON
// encoded. These things could change without breaking the protocol, should stay
// the same for the sake of REST API compatibility.
func TestTxnJson(t *testing.T) {
	partitiontest.PartitionTest(t)

	txn := txntest.Txn{
		Sender: basics.Address{0x01, 0x02, 0x03},
	}
	marshal := protocol.EncodeJSON(txn.Txn())
	require.Contains(t, compact(marshal), `"snd":"AEBA`)

	txn = txntest.Txn{
		Boxes: []transactions.BoxRef{{Index: 3, Name: []byte("john")}},
	}
	marshal = protocol.EncodeJSON(txn.Txn())
	require.Contains(t, compact(marshal), `"apbx":[{"i":3,"n":"am9obg=="}]`)
}
