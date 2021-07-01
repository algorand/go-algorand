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

package ledger

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/testpartitioning"
)

func TestOnlineTopHeap_Less(t *testing.T) {
	testpartitioning.PartitionTest(t)

	h := onlineTopHeap{
		accts: []*onlineAccount{
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 0,
			},
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 1,
			},
			{
				Address:                 basics.Address(crypto.Hash([]byte("address"))),
				NormalizedOnlineBalance: 0,
			},
		},
	}

	require.True(t, h.Less(1, 0))
	require.True(t, h.Less(1, 2))
	require.True(t, h.Less(2, 0))

	require.False(t, h.Less(0, 1))
	require.False(t, h.Less(0, 2))
	require.False(t, h.Less(2, 1))
}

func TestOnlineTopHeap_Swap(t *testing.T) {
	testpartitioning.PartitionTest(t)

	h := onlineTopHeap{
		accts: []*onlineAccount{
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 0,
			},
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 1,
			},
			{
				Address:                 basics.Address(crypto.Hash([]byte("address"))),
				NormalizedOnlineBalance: 0,
			},
		},
	}

	acct0 := h.accts[0]
	acct2 := h.accts[2]

	h.Swap(0, 2)

	require.Equal(t, acct0, h.accts[2])
	require.Equal(t, acct2, h.accts[0])
}

func TestOnlineTopHeap_Push(t *testing.T) {
	testpartitioning.PartitionTest(t)

	h := onlineTopHeap{
		accts: []*onlineAccount{
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 0,
			},
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 1,
			},
		},
	}

	acct0 := h.accts[0]
	acct1 := h.accts[1]
	acct2 := &onlineAccount{
		Address:                 basics.Address(crypto.Hash([]byte("address"))),
		NormalizedOnlineBalance: 0,
	}

	h.Push(acct2)

	require.Equal(t, 3, h.Len())
	require.Equal(t, acct0, h.accts[0])
	require.Equal(t, acct1, h.accts[1])
	require.Equal(t, acct2, h.accts[2])
}

func TestOnlineTopHeap_Pop(t *testing.T) {
	testpartitioning.PartitionTest(t)

	h := onlineTopHeap{
		accts: []*onlineAccount{
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 0,
			},
			{
				Address:                 basics.Address{},
				NormalizedOnlineBalance: 1,
			},
			{
				Address:                 basics.Address(crypto.Hash([]byte("address"))),
				NormalizedOnlineBalance: 0,
			},
		},
	}

	originalAccounts := h.accts

	h.Pop()

	require.Equal(t, 2, h.Len())
	require.Equal(t, 3, cap(h.accts))
	require.Equal(t, originalAccounts[0], h.accts[0])
	require.Equal(t, originalAccounts[1], h.accts[1])
	require.Nil(t, originalAccounts[2])
}
