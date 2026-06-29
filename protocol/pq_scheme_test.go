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

func TestPQSchemes(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	schemes := []PQScheme{
		PQSchemeFalcon1024,
		PQSchemeFalcon512,
	}

	seen := make(map[PQScheme]struct{}, len(schemes))
	for _, scheme := range schemes {
		for _, b := range scheme {
			require.Truef(t, b >= 0x20 && b < 0x7f, "PQScheme %q must be printable ASCII", scheme)
		}

		_, ok := seen[scheme]
		require.False(t, ok, "PQScheme %q is repeated", scheme)
		seen[scheme] = struct{}{}
	}
}
