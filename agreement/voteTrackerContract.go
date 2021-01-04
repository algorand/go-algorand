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

// A voteMachine should track a new vote.
//
// Preconditions:
//  - e.T = voteAccepted or voteFilterRequest
//  - v.R.Step != propose
//  - for all votes v = e.Vote, v.R.Step is the same
//  - (Algorand safety assumptions on the equivocation of votes)
//
// Postconditions (let e be the returned event):
//  if Input is of type voteAccepted:
//  - e.T is one of {none, {soft,cert,next}Threshold}
//  - e.T corresponds to the input event's step (e.g. if the input event had v.R.Step = soft, then e.T is either none or softThreshold)
//  - e.T != none if and only if e.Bundle contains a valid bundle for e.Proposal
//  - if e.T is a {soft,cert}Threshold event, it will be emitted at most once and e.Proposal != bottom
//  - if e.T is a {next}Threshold event, it will be emitted at most once and e.Proposal != bottom
//  if Input is of type voteFilterRequest:
//  - e.T is one of {none, voteFilteredStep}
//  - e.T = none for a given input only once (the first time the vote is seen, if we have not previously detected equivocation
//
// Trace properties
//  - voteFilterRequest is idempotent
type voteTrackerContract struct {
	Step   step
	StepOk bool

	Emitted bool
}

func (c *voteTrackerContract) pre(p player, in0 event) (pre []error) {
	switch in0.t() {
	case voteAccepted:
		in := in0.(voteAcceptedEvent)
		if in.Vote.R.Step == propose {
			pre = append(pre, fmt.Errorf("incoming event has step propose"))
		}

		if !c.StepOk {
			c.StepOk = true
			c.Step = in.Vote.R.Step
		} else {
			if c.Step != in.Vote.R.Step {
				pre = append(pre, fmt.Errorf("incoming event has step %d but expected step %d", in.Vote.R.Step, c.Step))
			}
		}
		return
	case voteFilterRequest, dumpVotesRequest:
		return
	default:
		pre = append(pre, fmt.Errorf("incoming event has invalid type: %v", in0.t()))
	}
	return
}

func (c *voteTrackerContract) post(p player, in0, out0 event) (post []error) {
	switch in0.t() {
	case voteAccepted:
		in := in0.(voteAcceptedEvent)

		switch out0.t() {
		case none:
		case softThreshold:
			if in.Vote.R.Step != soft {
				post = append(post, fmt.Errorf("incoming event has step %d but outgoing event has type softThreshold", in.Vote.R.Step))
			}
		case certThreshold:
			if in.Vote.R.Step != cert {
				post = append(post, fmt.Errorf("incoming event has step %d but outgoing event has type certThreshold", in.Vote.R.Step))
			}
		case nextThreshold:
			if in.Vote.R.Step <= cert {
				post = append(post, fmt.Errorf("incoming event has step %d but outgoing event has type nextThreshold", in.Vote.R.Step))
			}
		default:
			post = append(post, fmt.Errorf("outgoing event has invalid type: %v", out0.t()))
		}

		switch out0.t() {
		case softThreshold, certThreshold, nextThreshold:
			if c.Emitted {
				post = append(post, fmt.Errorf("event %v was emitted twice", out0))
			} else {
				c.Emitted = true
			}
		}

		out := out0.(thresholdEvent)
		switch out0.t() {
		case softThreshold, certThreshold:
			if out.Proposal == bottom {
				post = append(post, fmt.Errorf("out.Proposal = bottom but out.T = %v", out.T))
			}
		}

		emptyBundle := len(out.Bundle.Votes) == 0
		if (out.T == none) != emptyBundle {
			post = append(post, fmt.Errorf("out.T must be none if and only if out.Bundle is empty, but out.T = %v while len(out.Bundle.Votes) = %d", out.T, len(out.Bundle.Votes)))
		}
		if out.T != none && out.Proposal == bottom && out.Step < next {
			post = append(post, fmt.Errorf("outgoing event has bottom proposal but step %d", out.Step))
		}
		return
	case voteFilterRequest:
		switch out0.t() {
		case none:
		case voteFilteredStep:
			// once we write safety properties/contracts on traces, we can test the duplication detection
		default:
			post = append(post, fmt.Errorf("outgoing filter event has invalid type: %v", out0.t()))
		}
	default:
	}
	return
}
