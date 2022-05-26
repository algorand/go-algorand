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

package transactions_test

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func decode(data string, v interface{}) error {
	err := protocol.DecodeJSON([]byte(data), v)
	if err != nil {
		panic(err)
	}
	return err
}

func compact(data []byte) string {
	return strings.ReplaceAll(strings.ReplaceAll(string(data), " ", ""), "\n", "")
}

// TestJsonMarshal ensures that BoxRef names are b64 encoded, since they may not be characters.
func TestJsonMarshal(t *testing.T) {
	marshal := protocol.EncodeJSON(transactions.BoxRef{Index: 4, Name: "joe"})
	require.Equal(t, `{"i":4,"n":"am9l"}`, compact(marshal))

	marshal = protocol.EncodeJSON(transactions.BoxRef{Index: 0, Name: "joe"})
	require.Equal(t, `{"n":"am9l"}`, compact(marshal))

	marshal = protocol.EncodeJSON(transactions.BoxRef{Index: 1, Name: ""})
	require.Equal(t, `{"i":1}`, compact(marshal))

	marshal = protocol.EncodeJSON(transactions.BoxRef{Index: 0, Name: ""})
	require.Equal(t, `{}`, compact(marshal))
}

// TestJsonUnmarshal ensures that BoxRef unmarshaling expects b64 names
func TestJsonUnmarshal(t *testing.T) {
	var br transactions.BoxRef

	decode(`{"i":4,"n":"am9l"}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 4, Name: "joe"}, br)

	decode(`{"n":"am9l"}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 0, Name: "joe"}, br)

	decode(`{"i":4}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 4, Name: ""}, br)

	decode(`{}`, &br)
	require.Equal(t, transactions.BoxRef{Index: 0, Name: ""}, br)
}

// TestTxnJson tests a few more things about how our Transactions get JSON
// encoded. These things could change without breaking the protocol, should stay
// the same for the sake of REST API compatibility.
func TestTxnJson(t *testing.T) {
	txn := txntest.Txn{
		Sender: basics.Address{0x01, 0x02, 0x03},
	}
	marshal := protocol.EncodeJSON(txn.Txn())
	require.Contains(t, compact(marshal), `"snd":"AEBA`)

	txn = txntest.Txn{
		Boxes: []transactions.BoxRef{{Index: 3, Name: "john"}},
	}
	marshal = protocol.EncodeJSON(txn.Txn())
	require.Contains(t, compact(marshal), `"apbx":[{"i":3,"n":"am9obg=="}]`)

	marshal = protocol.EncodeJSON(txn.Txn())
}
