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

package compactcert

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/testPartitioning"
)

func rand32() uint32 {
	return uint32(crypto.RandUint64() & 0xffffffff)
}

func TestBigFloatRounding(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := &bigFloatDn{}
	b := &bigFloatUp{}

	a.setu64(1 << 63)
	b.setu64(1 << 63)

	require.True(t, a.geRaw(&b.bigFloat))
	require.True(t, b.geRaw(&a.bigFloat))

	a.mul(a)
	b.mul(b)

	require.True(t, a.geRaw(&b.bigFloat))
	require.True(t, b.geRaw(&a.bigFloat))

	a.setu64((1 << 64) - 1)
	b.setu64((1 << 64) - 1)

	require.False(t, a.geRaw(&b.bigFloat))
	require.True(t, b.geRaw(&a.bigFloat))

	a.setu32((1 << 32) - 1)
	b.setu32((1 << 32) - 1)

	a.mul(a)
	b.mul(b)

	require.False(t, a.geRaw(&b.bigFloat))
	require.True(t, b.geRaw(&a.bigFloat))
}

func TestBigFloat(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := &bigFloatDn{}
	b := &bigFloatDn{}

	a.setu64(1)
	require.Equal(t, a.mantissa, uint32(1<<31))
	require.Equal(t, a.exp, int32(-31))

	a.setu32(1)
	require.Equal(t, a.mantissa, uint32(1<<31))
	require.Equal(t, a.exp, int32(-31))

	for i := int32(-256); i < 256; i++ {
		a.setpow2(i)
		require.Equal(t, a.mantissa, uint32(1<<31))
		require.Equal(t, a.exp, i-31)
	}

	for i := 0; i < 8192; i++ {
		x := rand32()
		a.setu32(x)
		require.True(t, a.exp <= 0)
		require.Equal(t, x, a.mantissa>>(-a.exp))
	}

	for i := 0; i < 8192; i++ {
		x := uint64(rand32())
		a.setu64(x)
		if a.exp <= 0 {
			require.Equal(t, x, uint64(a.mantissa>>(-a.exp)))
		}
		if a.exp >= 0 {
			require.Equal(t, x>>a.exp, uint64(a.mantissa))
		}
	}

	for i := 0; i < 8192; i++ {
		x := crypto.RandUint64()
		a.setu64(x)
		if a.exp <= 0 {
			require.Equal(t, x, uint64(a.mantissa>>(-a.exp)))
		}
		if a.exp >= 0 {
			require.Equal(t, x>>a.exp, uint64(a.mantissa))
		}
	}

	for i := 0; i < 8192; i++ {
		x := rand32()
		y := rand32()
		a.setu64(uint64(x))
		b.setu64(uint64(y))

		require.Equal(t, x >= y, a.geRaw(&b.bigFloat))
		require.Equal(t, x < y, b.geRaw(&a.bigFloat))
		require.True(t, a.geRaw(&a.bigFloat))
		require.True(t, b.geRaw(&b.bigFloat))
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
		require.Equal(t, a.mantissa, uint32(xx.Uint64()))
	}
}

func BenchmarkBigFloatMulUp(b *testing.B) {
	a := &bigFloatUp{}
	a.setu32((1 << 32) - 1)

	for i := 0; i < b.N; i++ {
		a.mul(a)
	}
}

func BenchmarkBigFloatMulDn(b *testing.B) {
	a := &bigFloatDn{}
	a.setu32((1 << 32) - 1)

	for i := 0; i < b.N; i++ {
		a.mul(a)
	}
}
