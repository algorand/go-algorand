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

type proposalTrackerContract struct {
	SawOneVote       bool
	Froze            bool
	SawSoftThreshold bool
	SawCertThreshold bool
}

// TODO check concrete types of events
func (c *proposalTrackerContract) pre(p player, in event) (pre []error) {
	switch in.t() {
	case voteVerified, proposalFrozen, softThreshold, certThreshold, voteFilterRequest, readStaging:
	default:
		pre = append(pre, fmt.Errorf("incoming event has invalid type: %v", in.t()))
	}

	switch in.t() {
	case proposalFrozen:
		if c.Froze {
			pre = append(pre, fmt.Errorf("delivered proposalFrozen event twice"))
		}
	case softThreshold:
		if c.SawSoftThreshold {
			pre = append(pre, fmt.Errorf("delivered softThreshold event twice"))
		}
		if in.(thresholdEvent).Proposal == bottom {
			pre = append(pre, fmt.Errorf("delivered softThreshold event with bottom proposal-value"))
		}
	}
	return
}

func (c *proposalTrackerContract) post(p player, in, out event) (post []error) {
	switch in.t() {
	case voteVerified:
		switch out.t() {
		case proposalAccepted:
			_, ok := out.(proposalAcceptedEvent)
			if !ok {
				post = append(post, fmt.Errorf("output event does not cast to proposalAcceptedEvent: output is %#v", out))
			}
		case voteFiltered:
			_, ok := out.(filteredEvent)
			if !ok {
				post = append(post, fmt.Errorf("output event does not cast to voteFilteredEvent: output is %#v", out))
			}
		default:
			post = append(post, fmt.Errorf("output event from voteVerified has bad type: %v", out.t()))
		}
		if len(post) != 0 {
			return
		}

		if !c.SawOneVote && !c.Froze && !c.SawSoftThreshold && !c.SawCertThreshold {
			if out.t() != proposalAccepted {
				post = append(post, fmt.Errorf("expected first vote to have event type %v; had %v", proposalAccepted, out.t()))
			} else if out.(proposalAcceptedEvent).Proposal != in.(messageEvent).Input.Vote.R.Proposal {
				post = append(post, fmt.Errorf("expected ouptut event to have proposal %v; got %v", in.(messageEvent).Input.Vote.R.Proposal, out.(proposalAcceptedEvent).Proposal))
			}
		}

		if (c.Froze || c.SawSoftThreshold || c.SawCertThreshold) && out.t() != voteFiltered {
			post = append(post, fmt.Errorf("Frozen state = %v and soft threshold state = %v and cert threshold state = %v but got event type %v != voteFiltered", c.Froze, c.SawSoftThreshold, c.SawCertThreshold, out.t()))
		}

		if !c.SawOneVote {
			c.SawOneVote = true
		}

	case proposalFrozen:
		if out.t() != proposalFrozen {
			post = append(post, fmt.Errorf("output event from proposalFrozen has bad type: %v", out.t()))
		}
		_, ok := out.(proposalFrozenEvent)
		if !ok {
			post = append(post, fmt.Errorf("output event does not cast to proposalFrozenEvent: output is %#v", out))
		}

		outProp := out.(proposalFrozenEvent).Proposal
		if !c.SawOneVote && outProp != bottom {
			post = append(post, fmt.Errorf("expected bottom value (i.e., no value) to be Frozen; instead got %v", outProp))
		}

		c.Froze = true
	case softThreshold:
		if out.t() != proposalAccepted {
			post = append(post, fmt.Errorf("output event from proposalFrozen has bad type: %v", out.t()))
		}
		_, ok := out.(proposalAcceptedEvent)
		if !ok {
			post = append(post, fmt.Errorf("output event does not cast to proposalAcceptedEvent: output is %#v", out))
		}

		outProp := out.(proposalAcceptedEvent).Proposal
		if out.t() != proposalAccepted {
			post = append(post, fmt.Errorf("expected proposalAccepted event for softThreshold but got %v", out.t()))
		} else if outProp != in.(thresholdEvent).Proposal {
			post = append(post, fmt.Errorf("expected proposal-value %v; instead got %v", outProp, in.(thresholdEvent).Proposal))
		}

		c.SawSoftThreshold = true
	case certThreshold:
		if out.t() != proposalAccepted {
			post = append(post, fmt.Errorf("output event from certThreshold has bad type: %v", out.t()))
		}
		_, ok := out.(proposalAcceptedEvent)
		if !ok {
			post = append(post, fmt.Errorf("output event does not cast to proposalAcceptedEvent: output is %#v", out))
		}
		outProp := out.(proposalAcceptedEvent).Proposal
		if outProp != in.(thresholdEvent).Proposal {
			post = append(post, fmt.Errorf("expected proposal-value %v; instead got %v", outProp, in.(thresholdEvent).Proposal))
		}
		c.SawCertThreshold = true
	}
	return
}
