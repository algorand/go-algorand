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
	"github.com/algorand/go-algorand/data/basics"
)

//msgp:ignore sentFilterStat
type sentFilterStat struct {
	// .Modulator .Offset
	EncodingParams requestParams

	// lastCounter is the group counter of the last txn group included in a sent filter
	lastCounter uint64

	round basics.Round

	// incrementalFilterCount records how many incremental filters have been sent to determine whether to send a fresh filter.
	incrementalFilterCount int
}

// sentFilters is the set of filter stats for one peer to another peer.
// There should be at most one entry per (Modulator,Offset)
//msgp:ignore sentFilters
type sentFilters []sentFilterStat

const maxSentFilterSet = 10
const maxIncrementalFilters = 10

func (sf *sentFilters) setSentFilter(filter bloomFilter, round basics.Round) {
	encodingParams := filter.encoded.EncodingParams
	for i, sfs := range *sf {
		if sfs.EncodingParams == encodingParams {
			(*sf)[i].lastCounter = filter.containedTxnsRange.lastCounter
			(*sf)[i].round = round
			if filter.encoded.ClearPrevious == 1 {
				(*sf)[i].incrementalFilterCount = 0
			} else {
				(*sf)[i].incrementalFilterCount++
			}
			return
		}
	}
	nsf := sentFilterStat{
		EncodingParams: encodingParams,
		lastCounter:    filter.containedTxnsRange.lastCounter,
		round:          round,
	}
	if filter.encoded.ClearPrevious == 0 {
		nsf.incrementalFilterCount = 1
	}
	*sf = append(*sf, nsf)
	// trim oldest content if we're too long
	for len(*sf) > maxSentFilterSet {
		oldestRound := round
		popCandidate := -1
		for i, sfs := range *sf {
			if sfs.round < oldestRound {
				oldestRound = sfs.round
				popCandidate = i
			}
		}
		if popCandidate >= 0 {
			last := len(*sf) - 1
			(*sf)[popCandidate] = (*sf)[last]
			*sf = (*sf)[:last]
			break
		}
	}
}

func (sf *sentFilters) nextFilterGroup(encodingParams requestParams) (lastCounter uint64, round basics.Round) {
	for _, sfs := range *sf {
		if sfs.EncodingParams == encodingParams {
			if sfs.incrementalFilterCount > maxIncrementalFilters {
				return 0, 0
			}
			return sfs.lastCounter + 1, sfs.round
		}
	}
	return 0, 0 // include everything since the start
}
