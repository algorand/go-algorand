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

const pipelineDepth = 1 // XXX consensus param/flag

// pipelinePlayer manages an ensemble of players and implements the actor interface.
// It tracks the last committed agreement round, and manages speculative agreement rounds.
type pipelinePlayer struct {
	Round basics.Round
	//players [pipelineDepth]*player
}

func makePipelinePlayer(nextRound basics.Round, nextVersion protocol.ConsensusVersion) pipelinePlayer {
	ret := pipelinePlayer{Round: nextRound}
	// ret.players[0] = &player{
	// 	Round:    makeRoundBranch(nextRound, crypto.Digest{}),
	// 	Step:     soft,
	// 	Deadline: FilterTimeout(0, nextVersion)}
	return ret
}

func (p *pipelinePlayer) T() stateMachineTag { return playerMachine } // XXX different tag?
func (p *pipelinePlayer) underlying() actor  { return p }

/// XXX while below was copied from player, this seems like routing -- move to pipelineRouter?
func (p *pipelinePlayer) handle(r routerHandle, e event) []action {
	var actions []action

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

	return actions
}

// XXX should this be in router or player?
func (p *pipelinePlayer) handleRoundEvent(r routerHandle, e event, rnd round) []action {

	pr := r.r.(*pipelineRouter) // pull pipelineRouter out of routerHandle

	rr, ok := pr.Children[rnd]
	if !ok {
		// XXX typically router.update() creates Children before state machine handle()s are called
		logging.Base().Panicf("couldn't find child for rnd %+v", rnd)
	}

	// pass event to corresponding child player for this round
	rr.submitTop(r.t, *rr.root.underlying().(*player), e)
	return nil
}

func (p *pipelinePlayer) enterRound(r routerHandle, source event, target round) []action {
	// XXX router owns all the per-player router.Children now
	return nil
}

// XXX should pipelineRouter or pipelinePlayer track this?
func (p *pipelineRouter) externalDemuxSignals() []externalDemuxSignals {
	//	ret := make([]externalDemuxSignals, len(p.players))
	//	for i, p := range p.players {
	ret := make([]externalDemuxSignals, len(p.Children))
	i := 0
	for _, rootRouter := range p.Children {
		p := rootRouter.root.(*player)
		ret[i] = externalDemuxSignals{
			Deadline:             p.Deadline,
			FastRecoveryDeadline: p.FastRecoveryDeadline,
			CurrentRound:         p.Round,
		}
		i += 1
	}
	return ret
}
