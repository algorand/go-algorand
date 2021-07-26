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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func randomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

func TestAccountDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ad := AccountDeltas{}
	data, ok := ad.Get(basics.Address{})
	a.False(ok)
	a.Equal(basics.AccountData{}, data)

	addr := randomAddress()
	data, ok = ad.Get(addr)
	a.False(ok)
	a.Equal(basics.AccountData{}, data)

	a.Equal(0, ad.Len())
	a.Panics(func() { ad.GetByIdx(0) })

	a.Equal([]basics.Address{}, ad.ModifiedAccounts())

	sample1 := basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 123}}
	ad.Upsert(addr, sample1)
	data, ok = ad.Get(addr)
	a.True(ok)
	a.Equal(sample1, data)

	a.Equal(1, ad.Len())
	address, data := ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample1, data)

	sample2 := basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 456}}
	ad.Upsert(addr, sample2)
	data, ok = ad.Get(addr)
	a.True(ok)
	a.Equal(sample2, data)

	a.Equal(1, ad.Len())
	address, data = ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)

	a.Equal([]basics.Address{addr}, ad.ModifiedAccounts())

	ad2 := AccountDeltas{}
	ad2.Upsert(addr, sample2)
	ad.MergeAccounts(ad2)
	a.Equal(1, ad.Len())
	address, data = ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)

	addr1 := randomAddress()
	ad2.Upsert(addr1, sample1)
	ad.MergeAccounts(ad2)
	a.Equal(2, ad.Len())
	address, data = ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)
	address, data = ad.GetByIdx(1)
	a.Equal(addr1, address)
	a.Equal(sample1, data)
}

func BenchmarkMakeStateDelta(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MakeStateDelta(nil, 0, hint, 0)
	}
}

func BenchmarkBalanceRecord(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make([]basics.BalanceRecord, 0, hint*2)
		if len(x) > 0 {
			return
		}
	}
}

func BenchmarkAcctCache(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make(map[basics.Address]int, hint*2)
		if len(x) > 0 {
			return
		}
	}
}

func BenchmarkCreatables(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make(map[basics.CreatableIndex]ModifiedCreatable, hint)
		if len(x) > 0 {
			return
		}
	}
}

func BenchmarkTxLeases(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make(map[Txlease]basics.Round, hint)
		if len(x) > 0 {
			return
		}
	}
}
