// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPQSchemeSize(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	// PQSchemeSize is consensus-visible through PQ address preimages and the
	// PQScheme msgp allocbound, so keep it deliberately pinned.
	require.Equal(t, 2, PQSchemeSize)
}

func TestPQSchemes(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	values := getConstValues(t, "pq_scheme.go", "PQScheme", false)
	require.NotEmpty(t, values)

	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		require.Len(t, value, PQSchemeSize, "PQScheme %q must be exactly %d bytes", value, PQSchemeSize)
		for i := 0; i < len(value); i++ {
			require.Truef(t, value[i] >= 0x20 && value[i] < 0x7f, "PQScheme %q must be printable ASCII", value)
		}

		_, ok := seen[value]
		require.False(t, ok, "PQScheme %q is repeated", value)
		seen[value] = struct{}{}
	}
}

func TestPQSchemeFalcon1024(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	require.Equal(t, PQScheme("f1"), PQSchemeFalcon1024)
}
