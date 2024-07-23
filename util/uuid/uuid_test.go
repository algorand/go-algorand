// Copyright (C) 2019-2024 Algorand, Inc.
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

package uuid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestUUID(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := 0; i < 500; i++ {
		s := New()
		require.Equal(t, 36, len(s))
		require.Equal(t, "-", string(s[8]))
		require.Equal(t, "-", string(s[13]))
		require.Equal(t, "-", string(s[18]))
		require.Equal(t, "-", string(s[23]))
		require.Equal(t, "4", string(s[14]))
	}
}
