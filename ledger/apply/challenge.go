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

package apply

import (
	"bytes"
	"math/bits"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
)

// ChallengePeriod indicates which part of the challenge period is under discussion.
type ChallengePeriod int

const (
	// ChRisky indicates that a challenge is in effect, and the initial grace period is running out.
	ChRisky ChallengePeriod = iota
	// ChActive indicates that a challenege is in effect, and the grace period
	// has run out, so accounts can be suspended
	ChActive
)

type challenge struct {
	// round is when the challenge occurred. 0 means this is not a challenge.
	round basics.Round
	// accounts that match the first `bits` of `seed` must propose or heartbeat to stay online
	seed committee.Seed
	bits int
}

// FindChallenge returns the Challenge that was last issued if it's in the period requested.
func FindChallenge(rules config.ProposerPayoutRules, current basics.Round, headers hdrProvider, period ChallengePeriod) challenge {
	// are challenges active?
	interval := basics.Round(rules.ChallengeInterval)
	if rules.ChallengeInterval == 0 || current < interval {
		return challenge{}
	}
	lastChallenge := current - (current % interval)
	grace := basics.Round(rules.ChallengeGracePeriod)
	// FindChallenge is structured this way, instead of returning the challenge
	// and letting the caller determine the period it cares about, to avoid
	// using BlockHdr unnecessarily.
	switch period {
	case ChRisky:
		if current <= lastChallenge+grace/2 || current > lastChallenge+grace {
			return challenge{}
		}
	case ChActive:
		if current <= lastChallenge+grace || current > lastChallenge+2*grace {
			return challenge{}
		}
	}
	challengeHdr, err := headers.BlockHdr(lastChallenge)
	if err != nil {
		return challenge{}
	}
	challengeProto := config.Consensus[challengeHdr.CurrentProtocol]
	// challenge is not considered if rules have changed since that round
	if challengeProto.Payouts != rules {
		return challenge{}
	}
	return challenge{lastChallenge, challengeHdr.Seed, rules.ChallengeBits}
}

// IsZero returns true if the challenge is empty (used to indicate no challenege)
func (ch challenge) IsZero() bool {
	return ch == challenge{}
}

// Failed returns true iff ch is in effect, matches address, and lastSeen is
// before the challenge issue.  When an address "Fails" in this way, the
// _meaning_ depends on how the challenged was obtained. If it was "risky" then
// it means the address is at risk, not that it should be suspended.  It it's an
// "active" challenge, then the account should be suspended.
func (ch challenge) Failed(address basics.Address, lastSeen basics.Round) bool {
	return ch.round != 0 && bitsMatch(ch.seed[:], address[:], ch.bits) && lastSeen < ch.round
}

// bitsMatch checks if the first n bits of two byte slices match. Written to
// work on arbitrary slices, but we expect that n is small. Only user today
// calls with n=5.
func bitsMatch(a, b []byte, n int) bool {
	// Ensure n is a valid number of bits to compare
	if n < 0 || n > len(a)*8 || n > len(b)*8 {
		return false
	}

	// Compare entire bytes when we care about enough bits
	if !bytes.Equal(a[:n/8], b[:n/8]) {
		return false
	}

	remaining := n % 8
	if remaining == 0 {
		return true
	}
	return bits.LeadingZeros8(a[n/8]^b[n/8]) >= remaining
}
