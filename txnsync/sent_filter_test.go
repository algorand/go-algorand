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

package txnsync

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestSentFilterSet(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var sf sentFilters

	ep := requestParams{Offset: 4, Modulator: 255}
	bf := bloomFilter{
		containedTxnsRange: transactionsRange{1, 42, 99},
		encoded:            encodedBloomFilter{EncodingParams: ep},
	}

	// what goes in ..
	sf.setSentFilter(bf, basics.Round(13))

	// .. comes out
	lastCounter, lcRound := sf.nextFilterGroup(ep)
	a.Equal(uint64(42+1), lastCounter)
	a.Equal(basics.Round(13), lcRound)

	for i := 0; i < maxIncrementalFilters; i++ {
		sf.setSentFilter(bf, basics.Round(13))
	}

	lastCounter, lcRound = sf.nextFilterGroup(ep)
	a.Equal(uint64(0), lastCounter)
	a.Equal(basics.Round(0), lcRound)

	for i := 0; i < maxSentFilterSet; i++ {
		bf.encoded.EncodingParams.Offset++
		sf.setSentFilter(bf, basics.Round(14+i))
	}

	// first oldest entry will have been lost
	lastCounter, lcRound = sf.nextFilterGroup(ep)
	a.Equal(uint64(0), lastCounter)
	a.Equal(basics.Round(0), lcRound)
}
