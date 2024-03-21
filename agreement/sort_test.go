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

package agreement

import (
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestSortProposalValueLess(t *testing.T) {
	partitiontest.PartitionTest(t)
	// initialize a new digest with all bytes being 'a'
	d1 := new(crypto.Digest)
	for i := range d1 {
		d1[i] = byte('a')
	}
	p1 := proposalValue{
		OriginalPeriod:   1,
		OriginalProposer: basics.Address(*d1),
		BlockDigest:      *d1,
		EncodingDigest:   *d1,
	}
	sp := SortProposalValue{p1, p1}
	// They are both equal so Less should return false regardless of order
	require.Falsef(t, sp.Less(0, 1), "%v < %v is true for equal values", sp[0], sp[1])
	require.Falsef(t, sp.Less(1, 0), "%v < %v is true for equal values", sp[1], sp[0])

	// working our way backwards from the order of checks in sortProposalValue.Less()
	// the test is tied to the implementation because it defines what the canonical order of checks is
	sp[1].EncodingDigest[3] = byte('b')
	require.Truef(t, sp.Less(0, 1), "expected %v < % v", sp[0], sp[1])
	sp[0].BlockDigest[3] = byte('b')
	require.Falsef(t, sp.Less(0, 1), "expected %v >= %v", sp[0], sp[1])
	sp[1].BlockDigest[3] = byte('c')
	require.Truef(t, sp.Less(0, 1), "expected %v < %v", sp[0], sp[1])
	sp[0].OriginalProposer[3] = byte('b')
	require.Falsef(t, sp.Less(0, 1), "expected %v >= %v", sp[0], sp[1])
	sp[1].OriginalProposer[3] = byte('c')
	require.Truef(t, sp.Less(0, 1), "expected %v < %v", sp[0], sp[1])
	sp[0].OriginalPeriod = 2
	require.Falsef(t, sp.Less(0, 1), "expected %v >= %v", sp[0], sp[1])
}
