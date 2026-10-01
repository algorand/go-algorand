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

package txntest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestGenerateUnsaltedProgramOfSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, version := range []uint{1, logic.LogicSigOffCurveVersion, 14} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			for size := uint(5); size < 80; size++ {
				program, err := GenerateUnsaltedProgramOfSize(size, version)
				if version >= 14 && size < 7 {
					require.ErrorContains(t, err, "size must be at least 7 bytes")
					continue
				}
				require.NoError(t, err)
				require.Len(t, program, int(size))
				disassembled, err := logic.Disassemble(program)
				require.NoError(t, err)
				if version >= 14 {
					require.Contains(t, disassembled, "allow_all")
				}
			}
		})
	}
}
