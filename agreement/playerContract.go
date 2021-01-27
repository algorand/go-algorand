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

package agreement

import (
	"fmt"
)

type playerContract struct{}

func (c playerContract) call(aold, anew actor, in event, out []action) (pre, post []error) {
	pold := aold.(*player)
	pnew := anew.(*player)
	_ = pnew

	if in.t() == none {
		if len(out) > 0 {
			post = append(post, fmt.Errorf("action emitted against no event"))
		}
		return pre, post
	}

	switch e := in.(type) {
	case timeoutEvent:
		if pold.Step == propose {
			pre = append(pre, fmt.Errorf("timeout event delivered while pold.Step = %v", pold.Step))
		} else if pold.Step < next && pold.Napping {
			pre = append(pre, fmt.Errorf("pold.Napping but pold.Step < next"))
		}

	case thresholdEvent:
		if e.Round != pold.Round {
			pre = append(pre, fmt.Errorf("threshold delivered with wrong round: e.Round != pold.Round: %v != %v", e.Round, pold.Round))
		}

		switch e.t() {
		case softThreshold:
			if e.Period < pold.Period {
				pre = append(pre, fmt.Errorf("stale soft threshold delivered: e.Period < pold.Period: %v != %v", e.Period, pold.Period))
			}
		case nextThreshold:
			if e.Period <= pold.Period {
				pre = append(pre, fmt.Errorf("stale next threshold delivered: e.Period <= pold.Period: %v != %v", e.Period, pold.Period))
			}
		}

	case messageEvent:
		switch e.t() {
		case bundlePresent:
			if len(out) != 1 {
				post = append(post, fmt.Errorf("event type is %v but emitted %v != 1 actions", e.t(), len(out)))
			} else if out[0].t() != ignore && out[0].t() != verifyBundle {
				post = append(post, fmt.Errorf("action type is %v which is not in {ignore,verify}; event type was %v", out[0].t(), e.t()))
			}
		}

	case roundInterruptionEvent:
		if e.Round <= pold.Round {
			pre = append(pre, fmt.Errorf("stale round interruption event delivered: e.Round <= pold.Round: %v <= %v", e.Round, pold.Round))
		}

	case checkpointEvent:
		// this is an expcted event that has no preconditions. If there was an issue with the persistence, it would have loggeed already
		// when generated.

	default:
		pre = append(pre, fmt.Errorf("bad event type delivered to player: e.(type) = %T", in))
	}

	if pold.Step == propose {
		pre = append(pre, fmt.Errorf("event delivered but pold.Step = propose"))
	}

	return pre, post
}

func (c playerContract) trace(aold, anew []actor, in []event, out [][]action) (pre, post []error) {
	return pre, post
}
