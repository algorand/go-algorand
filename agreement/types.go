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
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// TimeoutType defines the type of a Deadline, to distinguish between different timeouts
// set by agreement.
type TimeoutType int8

const (
	// TimeoutDeadline annotates timeout events in the agreement protocol (e.g.,
	// for receiving a block).
	TimeoutDeadline TimeoutType = iota
	// TimeoutFastRecovery annotates the fast recovery timeout in the agreement
	// protocol.
	TimeoutFastRecovery
	// TimeoutFilter annotates the filter step timeout event in the agreement
	// protocol.
	TimeoutFilter
)

// Deadline marks a timeout event of type Type that the player schedules to
// happen after Duration time.
type Deadline struct {
	_struct  struct{} `codec:","`
	Duration time.Duration
	// Type is used to allow tests fire timeouts of specific types.
	Type TimeoutType
}

var defaultDeadlineTimeout = config.Protocol.BigLambda + config.Protocol.SmallLambda
var partitionStep = next + 3
var recoveryExtraTimeout = config.Protocol.SmallLambda

// FilterTimeout is the duration of the first agreement step.
func FilterTimeout(p period, v protocol.ConsensusVersion) time.Duration {
	if p == 0 {
		return config.Consensus[v].AgreementFilterTimeoutPeriod0
	}
	// timeout is expected to be 2 * SmallLambda, value moved to consensusParams
	return config.Consensus[v].AgreementFilterTimeout
}

// DeadlineTimeout is the duration of the second agreement step, varying based on period and consensus version.
func DeadlineTimeout(p period, v protocol.ConsensusVersion) time.Duration {
	if p == 0 {
		return config.Consensus[v].AgreementDeadlineTimeoutPeriod0
	}
	return defaultDeadlineTimeout
}

// DefaultDeadlineTimeout is the default duration of the second agreement step.
func DefaultDeadlineTimeout() time.Duration {
	return defaultDeadlineTimeout
}

type (
	// round denotes a single round of the agreement protocol
	round = basics.Round

	// step is a sequence number denoting distinct stages in Algorand
	step uint64

	// period is used to track progress with a given round in the protocol
	period uint64
)

// Algorand 2.0 steps
const (
	propose step = iota
	soft
	cert
	next
)
const (
	late step = 253 + iota
	redo
	down
)

func (s step) nextVoteRanges(deadlineTimeout time.Duration) (lower, upper time.Duration) {
	extra := recoveryExtraTimeout // eg  2000 ms
	lower = deadlineTimeout       // based on types.DeadlineTimeout()
	upper = lower + extra

	for i := next; i < s; i++ {
		extra *= 2
		lower = upper
		upper = lower + extra
	}

	// e.g. if s == 11
	// extra = 2 ^ 8 * 2000ms = 256 * 2.0 = 512s

	return lower, upper
}

// ReachesQuorum compares the current weight to the thresholds appropriate for the step,
// to determine if we've reached a quorum.
func (s step) reachesQuorum(proto config.ConsensusParams, weight uint64) bool {
	switch s {
	case propose:
		logging.Base().Warn("Called Propose.ReachesQuorum")
		return false
	case soft:
		return weight >= proto.SoftCommitteeThreshold
	case cert:
		return weight >= proto.CertCommitteeThreshold
	case late:
		return weight >= proto.LateCommitteeThreshold
	case redo:
		return weight >= proto.RedoCommitteeThreshold
	case down:
		return weight >= proto.DownCommitteeThreshold
	default:
		return weight >= proto.NextCommitteeThreshold
	}
}

// threshold returns the threshold necessary for the given step.
// Do not compare values to the output of this function directly;
// instead, use s.reachesQuorum to avoid off-by-one errors.
func (s step) threshold(proto config.ConsensusParams) uint64 {
	switch s {
	case propose:
		logging.Base().Warn("Called propose.threshold")
		return 0
	case soft:
		return proto.SoftCommitteeThreshold
	case cert:
		return proto.CertCommitteeThreshold
	case late:
		return proto.LateCommitteeThreshold
	case redo:
		return proto.RedoCommitteeThreshold
	case down:
		return proto.DownCommitteeThreshold
	default:
		return proto.NextCommitteeThreshold
	}
}

// CommitteeSize returns the size of the committee required for the step
func (s step) committeeSize(proto config.ConsensusParams) uint64 {
	switch s {
	case propose:
		return proto.NumProposers
	case soft:
		return proto.SoftCommitteeSize
	case cert:
		return proto.CertCommitteeSize
	case late:
		return proto.LateCommitteeSize
	case redo:
		return proto.RedoCommitteeSize
	case down:
		return proto.DownCommitteeSize
	default:
		return proto.NextCommitteeSize
	}
}
