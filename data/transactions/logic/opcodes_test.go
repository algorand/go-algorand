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

package logic

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpSpecs(t *testing.T) {
	t.Parallel()

	for _, spec := range OpSpecs {
		require.NotEmpty(t, spec.opSize, spec)
	}
}

func TestOpcodesByVersion(t *testing.T) {
	t.Parallel()

	opSpecs := make([][]OpSpec, 2)
	for v := uint64(1); v <= LogicVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			opSpecs[v-1] = OpcodesByVersion(v)
			isOk := true
			for i := 0; i < len(opSpecs[v-1])-1; i++ {
				cur := opSpecs[v-1][i]
				next := opSpecs[v-1][i+1]
				// check duplicates
				if cur.Opcode == next.Opcode {
					isOk = false
					break
				}
				// check sorted
				if cur.Opcode > next.Opcode {
					isOk = false
					break
				}

			}
			require.True(t, isOk)
		})
	}
	require.Greater(t, len(opSpecs[1]), len(opSpecs[0]))
}
