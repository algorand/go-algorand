// Copyright (C) 2019-2025 Algorand, Inc.
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
	"github.com/algorand/go-algorand/config"
)

// A stateMachineTag uniquely identifies the type of a state machine.
//
// Rounds, periods, and steps may be used to further identify different state machine instances of the same type.
//
//msgp:ignore stateMachineTag
type stateMachineTag int

//go:generate stringer -type=stateMachineTag
const (
	demultiplexer stateMachineTag = iota // type demux

	playerMachine // type player

	voteMachine       // type voteAggregator
	voteMachineRound  // type voteTrackerRound
	voteMachinePeriod // type voteTrackerPeriod
	voteMachineStep   // type voteTracker

	proposalMachine       // type proposalManager
	proposalMachineRound  // type proposalStore
	proposalMachinePeriod // type proposalTracker
)

// A routerHandle is a handle to a router which is passed into state machines.
//
// It ensures that all bookkeeping is done correctly and that state is correctly propagated downward.
type routerHandle struct {
	t   *tracer
	r   router
	src stateMachineTag
}

// credentialRoundLag the maximal number of rounds that could pass before a credential from
// an honest party for an old round may arrive. It uses the
// dynamicFilterTimeoutLowerBound parameter as the minimal round time.
var credentialRoundLag round

func init() {
	// credential arrival time should be at most 2*config.Protocol.SmallLambda after it was sent
	// Note that the credentialRoundLag is inversely proportional to the dynamicFilterTimeoutLowerBound
	// in the default formula. Since we are adjusting this lower bound over time,
	// for consistency in analytics we are setting the minimum to be 8 rounds
	// (equivalent to a dynamicFilterTimeoutLowerBound of 500 ms).
	minCredentialRoundLag := round(8) // round 2*2000ms / 500ms
	credentialRoundLag = max(round(2*config.Protocol.SmallLambda/dynamicFilterTimeoutLowerBound), minCredentialRoundLag)
	if credentialRoundLag*round(dynamicFilterTimeoutLowerBound) < round(2*config.Protocol.SmallLambda) {
		credentialRoundLag++
	}
}

// dispatch sends an event to the given state machine listener with the given stateMachineTag.
//
// If there are many state machines of this type (for instance, there is one voteMachineStep for each step)
// then the sender must specify a round, period, and step to disambiguate between these state machines.
func (h *routerHandle) dispatch(state player, e event, dest stateMachineTag, r round, p period, s step) event {
	h.t.ein(h.src, dest, e, r, p, s)
	e = h.r.dispatch(h.t, state, e, h.src, dest, r, p, s)
	h.t.eout(h.src, dest, e, r, p, s)
	return e
}

// router routes events and queries to the correct receiving state machine.
//
// router also encapsulates the garbage collection of old state machines.
type router interface {
	dispatch(t *tracer, state player, e event, src stateMachineTag, dest stateMachineTag, r round, p period, s step) event
}

type rootRouter struct {
	_struct struct{} `codec:","`

	root         actor    // playerMachine   (not restored: explicitly set on construction)
	proposalRoot listener // proposalMachine
	voteRoot     listener // voteMachine

	ProposalManager proposalManager
	VoteAggregator  voteAggregator

	Children map[round]*roundRouter `codec:"Children,allocbound=-"`
}

type roundRouter struct {
	_struct struct{} `codec:","`

	proposalRoot listener // proposalMachineRound
	voteRoot     listener // voteMachineRound

	ProposalStore    proposalStore
	VoteTrackerRound voteTrackerRound

	Children map[period]*periodRouter `codec:"Children,allocbound=-"`
}

type periodRouter struct {
	_struct struct{} `codec:","`

	proposalRoot listener // proposalMachinePeriod
	voteRoot     listener // voteMachinePeriod

	ProposalTracker   proposalTracker
	VoteTrackerPeriod voteTrackerPeriod

	ProposalTrackerContract proposalTrackerContract

	Children map[step]*stepRouter `codec:"Children,allocbound=-"`
}

type stepRouter struct {
	_struct  struct{} `codec:","`
	voteRoot listener // voteMachineStep

	VoteTracker voteTracker

	VoteTrackerContract voteTrackerContract
}

func makeRootRouter(p player) (res rootRouter) {
	res.root = checkedActor{actor: &p, actorContract: playerContract{}}
	return
}

func (router *rootRouter) update(state player, r round, gc bool) {
	if router.proposalRoot == nil {
		router.proposalRoot = checkedListener{listener: &router.ProposalManager, listenerContract: proposalManagerContract{}}
	}
	if router.voteRoot == nil {
		router.voteRoot = checkedListener{listener: &router.VoteAggregator, listenerContract: voteAggregatorContract{}}
	}
	if router.Children == nil {
		router.Children = make(map[round]*roundRouter)
	}
	if router.Children[r] == nil {
		router.Children[r] = new(roundRouter)
	}

	if gc {
		children := make(map[round]*roundRouter)
		for r, c := range router.Children {
			// We may still receive credential messages from old rounds. Keep
			// old round routers around, for as long as those credentials may
			// arrive to keep track of them.
			rr := r + credentialRoundLag
			if rr >= state.Round {
				children[r] = c
			}
		}
		router.Children = children
	}
}

// submitTop is a convenience method used to submit the event directly into the root of the state machine tree
// (i.e., to the playerMachine).
func (router *rootRouter) submitTop(t *tracer, state player, e event) (player, []action) {
	// TODO move cadaver calls to somewhere cleaner
	t.traceInput(state.Round, state.Period, state, e) // cadaver
	t.ainTop(demultiplexer, playerMachine, state, e, 0, 0, 0)

	router.update(state, 0, true)
	handle := routerHandle{t: t, r: router, src: playerMachine}
	a := router.root.handle(handle, e)

	t.aoutTop(demultiplexer, playerMachine, a, 0, 0, 0)
	t.traceOutput(state.Round, state.Period, state, a) // cadaver

	p := router.root.underlying().(*player)
	return *p, a
}

func (router *rootRouter) dispatch(t *tracer, state player, e event, src stateMachineTag, dest stateMachineTag, r round, p period, s step) event {
	router.update(state, r, true)
	if router.proposalRoot.T() == dest {
		handle := routerHandle{t: t, r: router, src: proposalMachine}
		return router.proposalRoot.handle(handle, state, e)
	}
	if router.voteRoot.T() == dest {
		handle := routerHandle{t: t, r: router, src: voteMachine}
		return router.voteRoot.handle(handle, state, e)
	}
	return router.Children[r].dispatch(t, state, e, src, dest, r, p, s)
}

func (router *roundRouter) update(state player, p period, gc bool) {
	if router.proposalRoot == nil {
		router.proposalRoot = checkedListener{listener: &(router.ProposalStore), listenerContract: proposalStoreContract{}}
	}
	if router.voteRoot == nil {
		router.voteRoot = checkedListener{listener: &router.VoteTrackerRound, listenerContract: voteTrackerRoundContract{}}
	}
	if router.Children == nil {
		router.Children = make(map[period]*periodRouter)
	}
	if router.Children[p] == nil {
		router.Children[p] = new(periodRouter)
	}

	if gc {
		children := make(map[period]*periodRouter)
		for p, c := range router.Children {
			if p+1 >= state.Period {
				children[p] = c
			} else if p <= 1 {
				// avoid garbage-collecting (next round, period 0/1) state
				// this is conservative:
				// we can collect more eagerly if router's round is passed in
				// TODO may want regression test for correct pipelining behavior
				children[p] = c
			}
		}
		router.Children = children
	}
}

func (router *roundRouter) dispatch(t *tracer, state player, e event, src stateMachineTag, dest stateMachineTag, r round, p period, s step) event {
	router.update(state, p, true)
	if router.proposalRoot.T() == dest {
		handle := routerHandle{t: t, r: router, src: proposalMachineRound}
		return router.proposalRoot.handle(handle, state, e)
	}
	if router.voteRoot.T() == dest {
		handle := routerHandle{t: t, r: router, src: voteMachineRound}
		return router.voteRoot.handle(handle, state, e)
	}
	return router.Children[p].dispatch(t, state, e, src, dest, r, p, s)
}

// we do not garbage-collect step because memory use here grows logarithmically slowly
func (router *periodRouter) update(s step) {
	if router.proposalRoot == nil {
		router.proposalRoot = checkedListener{listener: &router.ProposalTracker, listenerContract: &router.ProposalTrackerContract}
	}
	if router.voteRoot == nil {
		router.voteRoot = checkedListener{listener: &router.VoteTrackerPeriod, listenerContract: voteTrackerPeriodContract{}}
	}
	if router.Children == nil {
		router.Children = make(map[step]*stepRouter)
	}
	if router.Children[s] == nil {
		router.Children[s] = new(stepRouter)
	}
}

func (router *periodRouter) dispatch(t *tracer, state player, e event, src stateMachineTag, dest stateMachineTag, r round, p period, s step) event {
	router.update(s)
	if router.proposalRoot.T() == dest {
		handle := routerHandle{t: t, r: router, src: proposalMachinePeriod}
		return router.proposalRoot.handle(handle, state, e)
	}
	if router.voteRoot.T() == dest {
		handle := routerHandle{t: t, r: router, src: voteMachinePeriod}
		return router.voteRoot.handle(handle, state, e)
	}
	return router.Children[s].dispatch(t, state, e, src, dest, r, p, s)
}

func (router *stepRouter) update(state player, gc bool) {
	if router.voteRoot == nil {
		router.voteRoot = checkedListener{listener: &router.VoteTracker, listenerContract: &router.VoteTrackerContract}
	}
}

func (router *stepRouter) dispatch(t *tracer, state player, e event, src stateMachineTag, dest stateMachineTag, r round, p period, s step) event {
	router.update(state, true)
	if router.voteRoot.T() == dest {
		handle := routerHandle{t: t, r: router, src: voteMachineStep}
		return router.voteRoot.handle(handle, state, e)
	}
	panic("bad dispatch")
}

// helpers

// stagedValue gets the staged value for some (r, p)
// i.e., sigma(state, r, p)
func stagedValue(p0 player, h routerHandle, r round, p period) stagingValueEvent {
	qe := stagingValueEvent{Round: r, Period: p}
	e := h.dispatch(p0, qe, proposalMachineRound, r, p, 0)
	return e.(stagingValueEvent)
}

// pinnedValue gets the current pinned value for some (r)
func pinnedValue(p0 player, h routerHandle, r round) pinnedValueEvent {
	qe := pinnedValueEvent{Round: r}
	e := h.dispatch(p0, qe, proposalMachineRound, r, 0, 0)
	return e.(pinnedValueEvent)
}
