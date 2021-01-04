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

package agreement

import (
	"fmt"
)

type proposalManagerContract struct{}

func (c proposalManagerContract) pre(p player, in event) (pre []error) {
	switch in.t() {
	case votePresent, voteVerified, payloadPresent, payloadScanned, payloadVerified, roundInterruption, certThreshold, softThreshold, nextThreshold:
	default:
		pre = append(pre, fmt.Errorf("bad event type delivered: %v", in.t()))
	}

	switch e := in.(type) {
	case thresholdEvent:
		if p.Round != e.Round {
			pre = append(pre, fmt.Errorf("received a threshold event for the wrong round: %v != %v", p.Round, e.Round))
		}

		if e.t() != certThreshold && p.Period > e.Period {
			pre = append(pre, fmt.Errorf("received a stale quorum for an old period: %v > %v", p.Period, e.Period))
		}
		if e.t() == softThreshold && e.Proposal == bottom {
			pre = append(pre, fmt.Errorf("received a soft quorum for bottom"))
		}
	}

	return
}

func (c proposalManagerContract) post(p player, in, out event) []error {
	return nil
}
