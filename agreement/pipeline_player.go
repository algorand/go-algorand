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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// pipelinePlayer manages an ensemble of players and implements the actor interface.
// It tracks the last committed agreement round, and manages speculative agreement rounds.
type pipelinePlayer struct {
	lastCommittedRound basics.Round
	players            map[round]player
}

func makePipelinePlayer(nextRound basics.Round, nextVersion protocol.ConsensusVersion) pipelinePlayer {
	ret := pipelinePlayer{lastCommittedRound: nextRound}
	// ret.players[0] = &player{
	// 	Round:    makeRoundBranch(nextRound, crypto.Digest{}),
	// 	Step:     soft,
	// 	Deadline: FilterTimeout(0, nextVersion)}
	return ret
}

func (p *pipelinePlayer) T() stateMachineTag { return playerMachine } // XXX different tag?
func (p *pipelinePlayer) underlying() actor  { return p }

// handle an event, usually by delegating to a child player implementation.
func (p *pipelinePlayer) handle(r routerHandle, e event) []action {
	if e.t() == none {
		return nil
	}

	switch e := e.(type) {
	case messageEvent:
		switch e.t() {
		// always use UnauthenticatedX here?
		case votePresent, voteVerified:
			return p.handleRoundEvent(r, e, e.Input.UnauthenticatedVote.R.roundBranch())
		case payloadPresent, payloadVerified:
			return p.handleRoundEvent(r, e, e.Input.UnauthenticatedProposal.roundBranch())
		case bundlePresent, bundleVerified:
			return p.handleRoundEvent(r, e, e.Input.UnauthenticatedBundle.roundBranch())
		default:
			panic("bad messageEvent")
		}
	case thresholdEvent:
		switch e.t() {
		case certThreshold, softThreshold, nextThreshold:
			return p.handleRoundEvent(r, e, e.Round)
		default:
			panic("bad thresholdEvent")
		}
	case timeoutEvent:
		return p.handleRoundEvent(r, e, e.Round)
	case roundInterruptionEvent:
		// XXX handle enterRound ourselves and reshuffle players
		// could have come from ledgerNextRoundCh
		return p.enterRound(r, e, e.Round)
	case checkpointEvent:
		return p.handleRoundEvent(r, e, e.Round)
	default:
		panic("bad event")
	}
}

// protoForEvent returns the consensus version of an event, or error
func protoForEvent(e event) (protocol.ConsensusVersion, error) {
	switch e := e.(type) {
	case messageEvent:
		return e.Proto.Version, e.Proto.Err
	case timeoutEvent:
		return e.Proto.Version, e.Proto.Err
	case roundInterruptionEvent:
		return e.Proto.Version, e.Proto.Err
	case thresholdEvent:
		return e.Proto, nil
	default:
		panic("protoForEvent unsupported event")
	}
}

// handleRoundEvent looks up a player for a given round to handle an event.
func (p *pipelinePlayer) handleRoundEvent(r routerHandle, e event, rnd round) []action {
	state, ok := p.players[rnd]
	if !ok {
		// XXXX haven't seen this round before; create player or drop event
		switch e := e.(type) {
		// for now, only create new players for messageEvents
		case messageEvent:
			cv, err := protoForEvent(e)
			if err != nil {
				// XXX check when ConsensusVersionView.Err is set by LedgerReader
				logging.Base().Debugf("protoForEvent error %v", err)
				return nil
			}
			state = player{Round: rnd, Step: soft, Deadline: FilterTimeout(0, cv)}
			p.players[rnd] = state
		}
		// drop events that we don't have a player for
		logging.Base().Debugf("couldn't find player for rnd %+v, dropping event", rnd)
		return nil
	}

	// TODO move cadaver calls to somewhere cleaner
	r.t.traceInput(state.Round, state.Period, state, e) // cadaver
	r.t.ainTop(demultiplexer, playerMachine, state, e, roundZero, 0, 0)

	// pass event to corresponding child player for this round
	a := state.handle(r, e)

	r.t.aoutTop(demultiplexer, playerMachine, a, roundZero, 0, 0)
	r.t.traceOutput(state.Round, state.Period, state, a) // cadaver

	return a
}

func (p *pipelinePlayer) enterRound(r routerHandle, source event, target round) []action {
	// XXXX create new players and GC old ones
	return nil
}

func (p *pipelinePlayer) externalDemuxSignals() pipelineExternalDemuxSignals {
	s := make([]externalDemuxSignals, len(p.players))
	i := 0
	for _, p := range p.players {
		s[i] = externalDemuxSignals{
			Deadline:             p.Deadline,
			FastRecoveryDeadline: p.FastRecoveryDeadline,
			CurrentRound:         p.Round,
		}
		i += 1
	}
	return pipelineExternalDemuxSignals{signals: s, lastCommittedRound: p.lastCommittedRound}
}
