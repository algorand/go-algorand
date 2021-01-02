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

func TestSubSaturate(t *testing.T) {
	a := Round(1)
	b := Round(2)
	require.Equal(t, a.SubSaturate(b), Round(0))
	require.Equal(t, a.SubSaturate(a), Round(0))
	require.Equal(t, b.SubSaturate(a), Round(1))
}
