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

func TestApproxBigFloat(t *testing.T) {
	a := &approxBigFloat{}
	b := &approxBigFloat{}

	a.setu64(1)
	require.Equal(t, a.base, uint64(1<<63))
	require.Equal(t, a.exp, int64(-63))

	for i := int64(-256); i < 256; i++ {
		a.setpow2(i)
		require.Equal(t, a.base, uint64(1<<63))
		require.Equal(t, a.exp, i-63)
	}

	for i := 0; i < 8192; i++ {
		x := crypto.RandUint64()
		a.setu64(x)
		require.True(t, a.exp <= 0)
		require.Equal(t, x, a.base >> (-a.exp))
	}

	for i := 0; i < 8192; i++ {
		x := crypto.RandUint64()
		y := crypto.RandUint64()
		a.setu64(x)
		b.setu64(y)

		require.Equal(t, x >= y, a.ge(b))
		require.Equal(t, x < y, b.ge(a))
		require.True(t, a.ge(a))
		require.True(t, b.ge(b))
	}

	xx := &big.Int{}
	yy := &big.Int{}

	for i := 0; i < 8192; i++ {
		x := crypto.RandUint64()
		y := crypto.RandUint64()
		a.setu64(x)
		b.setu64(y)
		a.mul(b)

		xx.SetUint64(x)
		yy.SetUint64(y)
		xx.Mul(xx, yy)
		if a.exp > 0 {
			xx.Rsh(xx, uint(a.exp))
		}
		if a.exp < 0 {
			xx.Lsh(xx, uint(-a.exp))
		}
		require.Equal(t, a.base, xx.Uint64())
	}
}
