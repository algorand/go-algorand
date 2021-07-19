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
	"sort"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/timers"
)

var deadlineTimeout = config.Protocol.BigLambda + config.Protocol.SmallLambda
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

// DeadlineTimeout is the duration of the second agreement step.
func DeadlineTimeout() time.Duration {
	return deadlineTimeout
}

type roundBranch struct {
	number basics.Round
	branch crypto.Digest
}

var roundZero = round{number: 0}

func makeRoundBranch(n basics.Round, b crypto.Digest) round {
	return round{number: n, branch: b}
}

type (
	// round denotes a single round of the agreement protocol
	round = roundBranch

	// step is a sequence number denoting distinct stages in Algorand
	step uint64

	// period is used to track progress with a given round in the protocol
	period uint64
)

// RPS captures a round, period, and step.
type RPS struct {
	round  round
	period period
	step   step
}

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

func (s step) nextVoteRanges() (lower, upper time.Duration) {
	extra := recoveryExtraTimeout // eg  2500 ms
	lower = deadlineTimeout       // eg 17500 ms (15000 + 2500)
	upper = lower + extra         // eg 20000 ms

	for i := next; i < s; i++ {
		extra *= 2
		lower = upper
		upper = lower + extra
	}

	// e.g. if s == 14
	// extra = 2 ^ 8 * 2500ms = 256 * 2.5 = 512 + 128 = 640s

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

// clockManager managers multiple clocks used by different pipelined rounds.
// XXX garbage-collect old rounds
type clockManager struct {
	m map[round]timers.Clock
	f timers.ClockFactory
}

func makeClockManager(f timers.ClockFactory) *clockManager {
	return &clockManager{m: make(map[round]timers.Clock), f: f}
}

func (cm *clockManager) setZero(r round) {
	cm.m[r] = cm.f.Zero()
}

// nextDeadlineCh returns a timeout channel that will fire when the earliest Deadline among all of
// the rounds described in externalDemuxSignals has occurred. It also returns the corresponding
// round (including speculative branch) this timeout channel corresponds to.
func (cm *clockManager) nextDeadlineCh(es []externalDemuxSignals) (<-chan time.Time, round) {
	if len(es) == 0 {
		return nil, roundZero
	}
	sort.Slice(es, func(i, j int) bool {
		ti := cm.m[es[i].CurrentRound].GetTimeout(es[i].Deadline)
		tj := cm.m[es[j].CurrentRound].GetTimeout(es[j].Deadline)
		return ti.Before(tj)
	})
	return cm.m[es[0].CurrentRound].TimeoutAt(es[0].Deadline), es[0].CurrentRound
}

// nextFastDeadlineCh returns a timeout channel that will fire when the earliest FastRecoveryDeadline among all of
// the rounds described in externalDemuxSignals has occurred. It also returns the corresponding
// round (including speculative branch) this timeout channel corresponds to.
func (cm clockManager) nextFastDeadlineCh(es []externalDemuxSignals) (<-chan time.Time, round) {
	if len(es) == 0 {
		return nil, roundZero
	}
	sort.Slice(es, func(i, j int) bool {
		ti := cm.m[es[i].CurrentRound].GetTimeout(es[i].FastRecoveryDeadline)
		tj := cm.m[es[j].CurrentRound].GetTimeout(es[j].FastRecoveryDeadline)
		return ti.Before(tj)
	})
	return cm.m[es[0].CurrentRound].TimeoutAt(es[0].FastRecoveryDeadline), es[0].CurrentRound
}

func (cm *clockManager) Decode(data []byte) (*clockManager, error) {
	m := make(map[round]timers.Clock)
	err := protocol.DecodeReflect(data, m)
	if err != nil {
		logging.Base().Errorf("clockManager decode error: %v", err)
	} else {
		logging.Base().Debugf("clockManager decoded with map %+v", m)
	}
	return &clockManager{m: m, f: cm.f}, err
}

func (cm *clockManager) Encode() []byte {
	return protocol.EncodeReflect(cm.m)
}
