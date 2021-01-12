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

package main

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBlockToPath(t *testing.T) {
	require.Equal(t, "00/00/000000", blockToPath(0))
	require.Equal(t, "00/00/0000rs", blockToPath(1000))
	require.Equal(t, "05/yc/05ycfo", blockToPath(10000500))
	require.Equal(t, "4ll/2c/4ll2cic", blockToPath(10012300500))
}

func TestBlockToFileName(t *testing.T) {
	require.Equal(t, "000000", blockToFileName(0))
	require.Equal(t, "0000rs", blockToFileName(1000))
	require.Equal(t, "05ycfo", blockToFileName(10000500))
	require.Equal(t, "4ll2cic", blockToFileName(10012300500))
}

func TestBlockToString(t *testing.T) {
	require.Equal(t, "0", blockToString(0))
	require.Equal(t, "rs", blockToString(1000))
	require.Equal(t, "5ycfo", blockToString(10000500))
	require.Equal(t, "4ll2cic", blockToString(10012300500))
}
