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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// pipelinePlayer manages an ensemble of players and implements the actor interface.
// It tracks the last committed agreement round, and manages speculative agreement rounds.
type pipelinePlayer struct {
	LastCommittedRound basics.Round
	Players            map[round]*player
}

func makePipelinePlayer(nextRound basics.Round, nextVersion protocol.ConsensusVersion) pipelinePlayer {
	return pipelinePlayer{
		LastCommittedRound: nextRound,
		Players:            make(map[round]*player),
	}
}

func (p *pipelinePlayer) T() stateMachineTag { return playerMachine } // XXX different tag?
func (p *pipelinePlayer) underlying() actor  { return p }

func (p *pipelinePlayer) forgetBeforeRound() basics.Round {
	return p.LastCommittedRound // XXX actually lastCommittedRound+1?
}

// decode implements serializableActor
func (*pipelinePlayer) decode(buf []byte) (serializableActor, error) {
	ret := pipelinePlayer{}
	err := protocol.DecodeReflect(buf, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// encode implements serializableActor
func (p *pipelinePlayer) encode() []byte {
	return protocol.EncodeReflect(p)
}

// handle an event, usually by delegating to a child player implementation.
func (p *pipelinePlayer) handle(r routerHandle, e event) []action {
	if e.t() == none { // ignore emptyEvent
		return nil
	}

	ee, ok := e.(externalEvent)
	if !ok {
		panic("pipelinePlayer.handle didn't receive externalEvent")
	}
	rnd := ee.ConsensusRound()

	switch e := e.(type) {
	case messageEvent, timeoutEvent, checkpointEvent:
		return p.handleRoundEvent(r, ee, rnd)
	case roundInterruptionEvent:
		// XXX handle enterRound ourselves and reshuffle players
		// could have come from ledgerNextRoundCh
		return p.enterRound(r, e, e.Round)
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

func newPlayerForEvent(e externalEvent, rnd round) (*player, error) {
	switch e := e.(type) {
	// for now, only create new players for messageEvents
	case messageEvent:
		cv, err := protoForEvent(e)
		if err != nil {
			return nil, err
		}
		// XXX check when ConsensusVersionView.Err is set by LedgerReader
		return &player{Round: rnd, Step: soft, Deadline: FilterTimeout(0, cv)}, nil
	default:
		return nil, fmt.Errorf("can't make player for event %+v", e)
	}
}

// handleRoundEvent looks up a player for a given round to handle an event.
func (p *pipelinePlayer) handleRoundEvent(r routerHandle, e externalEvent, rnd round) []action {
	state, ok := p.Players[rnd]
	if !ok {
		// XXXX haven't seen this round before; create player or drop event
		state, err := newPlayerForEvent(e, rnd)
		if err != nil {
			logging.Base().Debugf("couldn't make player for rnd %+v, dropping event", rnd)
			return nil
		}
		p.Players[rnd] = state
	}

	// TODO move cadaver calls to somewhere cleanerxtern
	r.t.traceInput(state.Round, state.Period, *state, e) // cadaver
	r.t.ainTop(demultiplexer, playerMachine, *state, e, roundZero, 0, 0)

	// pass event to corresponding child player for this round
	a := state.handle(r, e)

	r.t.aoutTop(demultiplexer, playerMachine, a, roundZero, 0, 0)
	r.t.traceOutput(state.Round, state.Period, *state, a) // cadaver

	return a
}

func (p *pipelinePlayer) enterRound(r routerHandle, source event, target round) []action {
	// XXXX create new players and GC old ones
	return nil
}

// externalDemuxSignals returns a list of per-player signals allowing demux.next to wait for
// multiple pipelined per-round deadlines, as well as the last committed round.
func (p *pipelinePlayer) externalDemuxSignals() pipelineExternalDemuxSignals {
	s := make([]externalDemuxSignals, len(p.Players))
	i := 0
	for _, p := range p.Players {
		s[i] = externalDemuxSignals{
			Deadline:             p.Deadline,
			FastRecoveryDeadline: p.FastRecoveryDeadline,
			CurrentRound:         p.Round,
		}
		i++
	}
	return pipelineExternalDemuxSignals{signals: s, currentRound: p.LastCommittedRound}
}

// allPlayersRPS returns a list of per-player (round, period, step) tuples reflecting the current
// state of the pipelinePlayer's child players.
func (p *pipelinePlayer) allPlayersRPS() []RPS {
	ret := make([]RPS, len(p.Players))
	i := 0
	for _, p := range p.Players {
		ret[i] = RPS{Round: p.Round, Period: p.Period, Step: p.Step}
		i++
	}
	return ret
}
