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

package basics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignedOverflow(t *testing.T) {
	b := int64(1<<63-1)
	c := int64(-1<<63)

	d, overflowed := OSubS(0, b)
	require.False(t, overflowed)
	require.Equal(t, d, -b)

	e, overflowed := OSubS(d, 1)
	require.False(t, overflowed)
	require.Equal(t, e, c)

	_, overflowed = OSubS(e, 1)
	require.True(t, overflowed)

	_, overflowed = OSubS(0, c)
	require.True(t, overflowed)

	x, overflowed := OAddS(0, b)
	require.False(t, overflowed)
	require.Equal(t, x, b)

	_, overflowed = OAddS(x, 1)
	require.True(t, overflowed)

	_, overflowed = OAddS(c, c)
	require.True(t, overflowed)

	u := uint64(1<<64-1)
	_, overflowed = OAddUS(u, 0)
	require.False(t, overflowed)

	_, overflowed = OAddUS(u, -1)
	require.False(t, overflowed)

	_, overflowed = OAddUS(u, 1)
	require.True(t, overflowed)

	_, overflowed = OAddUS(0, 0)
	require.False(t, overflowed)

	_, overflowed = OAddUS(0, 1)
	require.False(t, overflowed)

	_, overflowed = OAddUS(0, -1)
	require.True(t, overflowed)
}
