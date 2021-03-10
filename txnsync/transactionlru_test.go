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

package txnsync

import (
	"testing"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/stretchr/testify/require"
)

func TestTransactionLru(t *testing.T) {
	var txid transactions.Txid
	a := makeTransactionLru(5)
	// add 5
	for i := 0; i < 5; i++ {
		txid[0] = byte(i)
		a.add(txid)
	}

	// all 5 still there
	for i := 0; i < 5; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}

	// repeatedly adding existing data doesn't lose anything
	txid[0] = 1
	a.add(txid)
	a.add(txid)
	a.add(txid)
	for i := 0; i < 5; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}

	// adding a sixth forgets the first
	txid[0] = 5
	a.add(txid)
	for i := 1; i < 6; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}
	txid[0] = 0
	require.False(t, a.contained(txid))

	// adding a seventh forgets the second
	txid[0] = 6
	a.add(txid)
	for i := 2; i < 7; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}
	txid[0] = 1
	require.False(t, a.contained(txid))
}
