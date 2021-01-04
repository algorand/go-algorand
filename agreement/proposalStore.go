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

	"github.com/algorand/go-algorand/logging"
)

// An blockAssembler contains the proposal data associated with some
// proposal-value.
//
// When an unauthenticated proposal first arrives at the state machine, it
// is pipelined by the blockAssembler.  Subsequent duplicates are filtered.
//
// Once a proposal is successfully validated, it is stored by the
// blockAssembler.
type blockAssembler struct {
	// Pipeline contains a proposal which has not yet been validated.  The
	// proposal might be inside the cryptoVerifier, or it might be a
	// pipelined proposal from the next round.
	Pipeline unauthenticatedProposal
	// Filled is set if the blockAssembler has seen a pipelined proposal.
	Filled bool

	// Payload contains a valid proposal seen by the blockAssembler.
	Payload proposal
	// Assembled is set if the blockAssembler has seen a valid proposal.
	Assembled bool

	// Authenticators caches the set of proposal-votes which have been seen
	// for a given proposal-value.  When a proposal payload is relayed by
	// the state machine, a matching can be concatenated with the vote to
	// ensure that peers do not drop the proposal payload.
	Authenticators []vote
}

// pipeline adds the given unvalidated proposal to the blockAssembler, returning
// an error if the pipelining operation is redundant.
func (a blockAssembler) pipeline(p unauthenticatedProposal) (blockAssembler, error) {
	if a.Assembled {
		return a, fmt.Errorf("blockAssembler.pipeline: already assembled")
	}

	if a.Filled {
		return a, fmt.Errorf("blockAssembler.pipeline: already filled")
	}

	a.Pipeline = p
	a.Filled = true

	return a, nil
}

// bind adds the given validated proposal to the blockAssembler, returning an
// error if a validated proposal has already been received.
func (a blockAssembler) bind(p proposal) (blockAssembler, error) {
	if a.Assembled {
		return a, fmt.Errorf("blockAssembler.pipeline: already assembled")
	}

	a.Payload = p
	a.Assembled = true

	return a, nil
}

// authenticator returns a proposal-vote which matches the blockAssembler's
// proposal for the given period, or vote{} if none exists.
func (a blockAssembler) authenticator(p period) vote {
	for _, v := range a.Authenticators {
		if v.R.Period == p {
			return v
		}
	}
	return vote{}
}

// trim removes authenticators older than the given period from the
// blockAssembler.
func (a blockAssembler) trim(p period) blockAssembler {
	old := a.Authenticators
	a.Authenticators = make([]vote, 0)
	for _, v := range old {
		if v.R.Period >= p {
			a.Authenticators = append(a.Authenticators, v)
		}
	}
	return a
}

// A proposalStore is a proposalMachineRound which stores payload data and
// caches proposal-votes for a given round in a space-efficient manner.
//
// It handles the following type(s) of event: voteVerified,
// payload{Present,Verified}, new{Round,Period}, and softThreshold.
// It returns the following type(s) of event: none, voteFiltered,
// proposal{Accepted,Committable}, and payload{Pipelined,Rejected}.
type proposalStore struct {
	// Relevant contains a current collection of important proposal-values
	// in the round. Relevant is indexed by period, and the proposalValue is
	// the last one reported by the corresponding proposalMachinePeriod.
	// Each corresponding proposal is tracked in Assemblers.
	Relevant map[period]proposalValue
	// Pinned contains the extra proposal-value, not tracked in Relevant,
	// for which a certificate may have formed (i.e., vbar in the spec).
	// The proposal corresponding to Pinned is tracked in Assemblers.
	Pinned proposalValue

	// Assemblers contains the set of proposal-values currently tracked and
	// held by the proposalStore.
	Assemblers map[proposalValue]blockAssembler
}

func (store *proposalStore) T() stateMachineTag {
	return proposalMachineRound
}

func (store *proposalStore) underlying() listener {
	return store
}

// A proposalStore handles six types of events:
//
// - A voteVerified event is delivered when a relevant proposal-vote has passed
//   cryptographic verification.  The proposalStore dispatches the event to the
//   proposalMachinePeriod and returns the resulting event.  If the
//   proposalMachinePeriod accepts the event, the set of relevant
//   proposal-values is updated to match the one in the event.  If there exists
//   a validated proposal payload matching the proposal-value specified by the
//   proposal-vote, it is attached to the event.  The proposalStore is then
//   trimmed.  The valid vote is cached as an authenticator.
//
// - A payloadPresent event is delivered when the state machine receives a
//   proposal payloads.  If the payload fails to match any relevant proposal, or
//   if the payload has already been seen by the state machine, payloadRejected
//   is returned.  Otherwise, a payloadPipelined event is returned, with a
//   cached proposal-vote possibly set.
//
// - A payloadVerified event is delivered when a relevant proposal payload has
//   passed cryptographic verification.  If the payload fails to match any
//   relevant proposal, or if the payload has already been seen by the state
//   machine, payloadRejected is returned.  Otherwise, either a
//   proposalCommittable event or a payloadAccepted event is returned, depending
//   on whether the proposal matches the current staging value.  This returned
//   event may have a cached authenticator set.
//
// - A newPeriod event is delivered when the player state machine enters a new
//   period.  When this happens, the proposalStore updates Pinned, cleans up old
//   state, and then returns an empty event.
//
// - A newRound event is delivered when the player state machine enters a new
//   round.  When this happens, the proposalStore returns a payloadPipelined
//   event with the proposal payload for the proposal-vote with the lowest
//   credential it has seen and possibly a cached authenticator (if not, it
//   returns an empty event).
//
// - A soft/certThreshold event is delivered when the player state has observed a
//   quorum of soft/cert votes for the current round and period.  The proposalStore
//   dispatches this event to the proposalMachinePeriod.  If the proposalStore
//   has the proposal payload corresponding to the proposal-value of the quorum,
//   it returns a proposalCommittable event; otherwise, it propagates the
//   proposalAccepted event.
//
// - A readStaging event is dispatched to the proposalMachinePeriod.  The proposalStore
//   sets the matching proposal payload (if one exists) in the response.
//
// - A readPinned event is delivered when the player wants to query the current
//   pinned proposalValue, and corresponding payload if one exists. This occurs
//   during resynchronization when players may relay the pinned value.
//   The event is handled exclusively by the proposalStore and not forwarded.
func (store *proposalStore) handle(r routerHandle, p player, e event) event {
	if store.Relevant == nil {
		store.Relevant = make(map[period]proposalValue)
	}
	if store.Assemblers == nil {
		store.Assemblers = make(map[proposalValue]blockAssembler)
	}

	switch e.t() {
	case voteVerified:
		v := e.(messageEvent).Input.Vote

		ev := r.dispatch(p, e, proposalMachinePeriod, v.R.Round, v.R.Period, 0)
		if ev.t() == proposalAccepted {
			e := ev.(proposalAcceptedEvent)
			ea := store.Assemblers[e.Proposal]
			ea.Authenticators = append(ea.Authenticators, v)
			store.Assemblers[e.Proposal] = ea
			store.Relevant[v.R.Period] = e.Proposal
			store.trim(p)

			e.Payload = ea.Payload
			e.PayloadOk = ea.Assembled
			return e
		}

		return ev

	case payloadPresent:
		up := e.(messageEvent).Input.UnauthenticatedProposal
		pv := up.value()
		ea, ok := store.Assemblers[pv]
		if !ok {
			return payloadProcessedEvent{
				T:   payloadRejected,
				Err: makeSerErrStr("proposalStore: no accepting blockAssembler found on payloadPresent"),
			}
		}

		var err error
		store.Assemblers[pv], err = ea.pipeline(up)
		if err != nil {
			return payloadProcessedEvent{T: payloadRejected, Err: makeSerErr(err)}
		}

		relevantPeriod, pinned := store.lastRelevant(pv)
		authVote := ea.authenticator(p.Period)
		return payloadProcessedEvent{
			T:                      payloadPipelined,
			Vote:                   authVote,
			Period:                 relevantPeriod,
			Pinned:                 pinned,
			Proposal:               pv,
			UnauthenticatedPayload: up,
		}

	case payloadVerified:
		pp := e.(messageEvent).Input.Proposal
		pv := pp.value()
		ea, ok := store.Assemblers[pp.value()]
		if !ok {
			return payloadProcessedEvent{
				T:   payloadRejected,
				Err: makeSerErrStr("proposalStore: no accepting blockAssembler found on payloadVerified"),
			}
		}

		var err error
		store.Assemblers[pv], err = ea.bind(pp)
		if err != nil {
			return payloadProcessedEvent{T: payloadRejected, Err: makeSerErr(err)}
		}

		a := stagedValue(p, r, p.Round, p.Period)
		authVote := ea.authenticator(p.Period)
		if a.Proposal == pv {
			return committableEvent{Proposal: pv, Vote: authVote}
		}
		return payloadProcessedEvent{
			T:        payloadAccepted,
			Vote:     authVote,
			Proposal: pv,
		}

	case newPeriod:
		// called before p.Period actually changes (if it does)
		starting := e.(newPeriodEvent).Proposal
		staged := stagedValue(p, r, p.Round, p.Period).Proposal
		if starting != bottom {
			store.Pinned = starting
		} else if staged != bottom {
			store.Pinned = staged
		}

		for per := range store.Relevant {
			if per+1 < e.(newPeriodEvent).Period {
				delete(store.Relevant, per)
			}
		}
		store.trim(p)
		return emptyEvent{}

	case newRound:
		if len(store.Assemblers) > 1 {
			// TODO this check is really an implementation invariant; move it into a whitebox test
			logging.Base().Panic("too many assemblers")
		}
		for pv, ea := range store.Assemblers {
			if ea.Filled {
				authVote := ea.authenticator(p.Period)
				relevantPeriod, pinned := store.lastRelevant(pv)
				return payloadProcessedEvent{
					T:                      payloadPipelined,
					Vote:                   authVote,
					Period:                 relevantPeriod,
					Pinned:                 pinned,
					Proposal:               pv,
					UnauthenticatedPayload: ea.Pipeline,
				}
			}
		}
		return emptyEvent{}

	case softThreshold, certThreshold:
		te := e.(thresholdEvent)
		// in particular, this will set te.Period.Staging = val(softThreshold/certThreshold)
		// as a consequence, only val(softThreshold/certThreshold) will generate proposalAccepted in the future
		// for this period, therefore store.Relevant[te.Period] will not be reset
		e := r.dispatch(p, e, proposalMachinePeriod, te.Round, te.Period, 0).(proposalAcceptedEvent)
		// return committableEvent if ready; else, return proposalAcceptedEvent
		if store.Assemblers[e.Proposal].Assembled {
			authVote := store.Assemblers[e.Proposal].authenticator(p.Period)
			return committableEvent{
				Proposal: e.Proposal,
				Vote:     authVote,
			}
		}
		// an assembler may not exist - we should add a new one, if it doesn't
		// we don't pin a value here - new period logic should have done that if we fast forward
		ea := store.Assemblers[e.Proposal]
		store.Assemblers[e.Proposal] = ea
		store.Relevant[te.Period] = e.Proposal
		store.trim(p)
		// no subsequent softThreshold logic uses these fields, but for completeness...
		e.Payload = ea.Payload
		e.PayloadOk = ea.Assembled
		return e

	case readStaging:
		se := e.(stagingValueEvent)
		se = r.dispatch(p, e, proposalMachinePeriod, se.Round, se.Period, 0).(stagingValueEvent)
		ea := store.Assemblers[se.Proposal]
		se.Committable = ea.Assembled
		se.Payload = ea.Payload
		return se
	case readPinned:
		se := e.(pinnedValueEvent)
		ea := store.Assemblers[store.Pinned] // If pinned is bottom, assembled/payloadOK = false, payload = bottom
		se.Proposal = store.Pinned
		se.PayloadOK = ea.Assembled
		se.Payload = ea.Payload
		return se
	}
	logging.Base().Panicf("proposalStore: bad event type: observed an event of type %v", e.t())
	panic("not reached")
}

// trim reduces the size of store.Assemblers to account for a minimal set of
// proposal-values.
func (store *proposalStore) trim(p player) {
	old := store.Assemblers
	store.Assemblers = make(map[proposalValue]blockAssembler)
	store.Assemblers[store.Pinned] = old[store.Pinned].trim(p.Period)
	for _, pv := range store.Relevant {
		store.Assemblers[pv] = old[pv].trim(p.Period)
	}

	// store.Assemblers[bottom] will be copied if store.Pinned is not set
	delete(store.Assemblers, bottom)
}

// lastRelevant returns (0, true) if the given proposal-value is pinned;
// otherwise, it returns the greatest period for which the proposal-value is relevant.
func (store *proposalStore) lastRelevant(pv proposalValue) (p period, pinned bool) {
	if store.Pinned == pv {
		pinned = true
		return
	}

	for per := range store.Relevant {
		if per > p && store.Relevant[per] == pv {
			p = per
		}
	}
	return
}
