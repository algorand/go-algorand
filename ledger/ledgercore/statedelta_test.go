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
)

func randomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

func TestAccountDeltas(t *testing.T) {
	a := require.New(t)

	ad := AccountDeltas{}
	data, ok := ad.Get(basics.Address{})
	a.False(ok)
	a.Equal(PersistedAccountData{}, data)

	addr := randomAddress()
	data, ok = ad.Get(addr)
	a.False(ok)
	a.Equal(PersistedAccountData{}, data)

	a.Equal(0, ad.Len())
	a.Panics(func() { ad.GetByIdx(0) })

	a.Equal([]basics.Address{}, ad.ModifiedAccounts())

	sample1 := PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 123}}}
	ad.Upsert(addr, sample1)
	data, ok = ad.Get(addr)
	a.True(ok)
	a.Equal(sample1, data)

	a.Equal(1, ad.Len())
	address, data := ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample1, data)

	sample2 := PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 456}}}
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
