// Copyright (C) 2019-2020 Algorand, Inc.
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

package compactcert

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

func rand32() uint32 {
	return uint32(crypto.RandUint64() & 0xffffffff)
}

func TestApproxBigFloat(t *testing.T) {
	a := &approxBigFloat{}
	b := &approxBigFloat{}

	a.setu64(1)
	require.Equal(t, a.base, uint32(1<<31))
	require.Equal(t, a.exp, int32(-31))

	a.setu32(1)
	require.Equal(t, a.base, uint32(1<<31))
	require.Equal(t, a.exp, int32(-31))

	for i := int32(-256); i < 256; i++ {
		a.setpow2(i)
		require.Equal(t, a.base, uint32(1<<31))
		require.Equal(t, a.exp, i-31)
	}

	for i := 0; i < 8192; i++ {
		x := rand32()
		a.setu32(x)
		require.True(t, a.exp <= 0)
		require.Equal(t, x, a.base>>(-a.exp))
	}

	for i := 0; i < 8192; i++ {
		x := rand32()
		a.setu64(uint64(x))
		require.True(t, a.exp <= 0)
		require.Equal(t, x, a.base>>(-a.exp))
	}

	for i := 0; i < 8192; i++ {
		x := rand32()
		y := rand32()
		a.setu64(uint64(x))
		b.setu64(uint64(y))

		require.Equal(t, x >= y, a.ge(b))
		require.Equal(t, x < y, b.ge(a))
		require.True(t, a.ge(a))
		require.True(t, b.ge(b))
	}

	xx := &big.Int{}
	yy := &big.Int{}

	for i := 0; i < 8192; i++ {
		x := rand32()
		y := rand32()
		a.setu64(uint64(x))
		b.setu64(uint64(y))
		a.mul(b)

		xx.SetUint64(uint64(x))
		yy.SetUint64(uint64(y))
		xx.Mul(xx, yy)
		if a.exp > 0 {
			xx.Rsh(xx, uint(a.exp))
		}
		if a.exp < 0 {
			xx.Lsh(xx, uint(-a.exp))
		}
		require.Equal(t, a.base, uint32(xx.Uint64()))
	}
}
