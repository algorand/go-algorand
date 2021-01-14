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

package ledger

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

type timeTracker struct {
	timestamps map[basics.Round]int64
}

func (tt *timeTracker) loadFromDisk(l ledgerForTracker) error {
	latest := l.Latest()
	blkhdr, err := l.BlockHdr(latest)
	if err != nil {
		return err
	}

	tt.timestamps = make(map[basics.Round]int64)
	tt.timestamps[latest] = blkhdr.TimeStamp
	return nil
}

func (tt *timeTracker) close() {
}

func (tt *timeTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	rnd := blk.Round()
	tt.timestamps[rnd] = delta.Hdr.TimeStamp
}

func (tt *timeTracker) committedUpTo(committedRnd basics.Round) basics.Round {
	for rnd := range tt.timestamps {
		if rnd < committedRnd {
			delete(tt.timestamps, rnd)
		}
	}
	return committedRnd
}

func (tt *timeTracker) timestamp(r basics.Round) (int64, error) {
	ts, ok := tt.timestamps[r]
	if ok {
		return ts, nil
	}

	return 0, fmt.Errorf("no record of timestamp for round %d", r)
}
