// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/algorand/go-algorand/util/metrics"
)

var proposalAlreadyFilledCounter = metrics.MakeCounter(
	metrics.MetricName{Name: "algod_agreement_proposal_already_filled", Description: "Number of times a duplicate proposal payload was received before validation"})

var proposalAlreadyAssembledCounter = metrics.MakeCounter(
	metrics.MetricName{Name: "algod_agreement_proposal_already_assembled", Description: "Number of times a duplicate proposal payload was received after validation"})

// An blockAssembler contains the proposal data associated with some
// proposal-value.
//
// When an unauthenticated proposal first arrives at the state machine, it
// is pipelined by the blockAssembler.  Subsequent duplicates are filtered.
//
// Once a proposal is successfully validated, it is stored by the
// blockAssembler.
type blockAssembler struct {
	_struct struct{} `codec:","`
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
	Authenticators []vote `codec:"Authenticators,allocbound=-"`

	// held is set if Pipeline has no validation request because, when it
	// was pipelined or when its validation was cancelled, only a period
	// which had not started was interested in it.  Validation is requested
	// once a period which has started is interested in it (see
	// proposalStore.resumeHeld).
	//
	// held is not serialized to disk.  After a crash, agreement does not
	// request validation of a held Pipeline, as for a Pipeline whose
	// validation was in the cryptoVerifier.
	held bool
}

// pipeline adds the given unvalidated proposal to the blockAssembler, returning
// an error if the pipelining operation is redundant.
func (a blockAssembler) pipeline(p unauthenticatedProposal) (blockAssembler, error) {
	if a.Assembled {
		proposalAlreadyAssembledCounter.Inc(nil)
		return a, fmt.Errorf("blockAssembler.pipeline: already assembled")
	}

	if a.Filled {
		proposalAlreadyFilledCounter.Inc(nil)
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

	// remember when the original unauthenticatedProposal was received
	a.Payload.receivedAt = a.Pipeline.receivedAt

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
	_struct struct{} `codec:","`
	// Relevant contains a current collection of important proposal-values
	// in the round. Relevant is indexed by period, and the proposalValue is
	// the last one reported by the corresponding proposalMachinePeriod.
	// Each corresponding proposal is tracked in Assemblers.
	Relevant map[period]proposalValue `codec:"Relevant,allocbound=-"`
	// Pinned contains the extra proposal-value, not tracked in Relevant,
	// for which a certificate may have formed (i.e., vbar in the spec).
	// The proposal corresponding to Pinned is tracked in Assemblers.
	Pinned proposalValue

	// Assemblers contains the set of proposal-values currently tracked and
	// held by the proposalStore.
	Assemblers map[proposalValue]blockAssembler `codec:"Assemblers,allocbound=-"`
}

func (store *proposalStore) T() stateMachineTag {
	return proposalMachineRound
}

func (store *proposalStore) underlying() listener {
	return store
}

// A proposalStore handles six types of events:
//
//   - A voteVerified event is delivered when a relevant proposal-vote has passed
//     cryptographic verification.  The proposalStore dispatches the event to the
//     proposalMachinePeriod and returns the resulting event.  If the
//     proposalMachinePeriod accepts the event, the set of relevant
//     proposal-values is updated to match the one in the event.  If there exists
//     a validated proposal payload matching the proposal-value specified by the
//     proposal-vote, it is attached to the event.  The proposalStore is then
//     trimmed.  The valid vote is cached as an authenticator.
//
//   - A payloadPresent event is delivered when the state machine receives a
//     proposal payloads.  If the payload fails to match any relevant proposal, or
//     if the payload has already been seen by the state machine, payloadRejected
//     is returned.  Otherwise, a payloadPipelined event is returned, with a
//     cached proposal-vote possibly set.  If only a period which has not
//     started is interested in the payload, the event's Held is set, and the
//     payload is held without a validation request until a period which has
//     started is interested in it.
//
//   - A payloadVerified event is delivered when a relevant proposal payload has
//     passed cryptographic verification.  If the payload fails to match any
//     relevant proposal, or if the payload has already been seen by the state
//     machine, payloadRejected is returned.  Otherwise, either a
//     proposalCommittable event or a payloadAccepted event is returned, depending
//     on whether the proposal matches the current staging value.  This returned
//     event may have a cached authenticator set.  If the verification was
//     cancelled and the payload is still tracked and not assembled, the
//     payload is held again as on payloadPresent, and payloadPipelined is
//     returned.
//
//   - A newPeriod event is delivered when the player state machine enters a new
//     period.  When this happens, the proposalStore updates Pinned, cleans up old
//     state, and then, if the event's ResumeHeld is set, returns a
//     payloadPipelined event for a held payload whose validation is now due,
//     if there is one; otherwise it returns an empty event.
//
//   - A newRound event is delivered when the player state machine enters a new
//     round.  When this happens, the proposalStore returns a payloadPipelined
//     event with the proposal payload for the proposal-vote with the lowest
//     credential it has seen and possibly a cached authenticator (if not, it
//     returns an empty event).
//
//   - A soft/certThreshold event is delivered when the player state has observed a
//     quorum of soft/cert votes for the current round and period.  The proposalStore
//     dispatches this event to the proposalMachinePeriod.  If the proposalStore
//     has the proposal payload corresponding to the proposal-value of the quorum,
//     it returns a proposalCommittable event; otherwise, it propagates the
//     proposalAccepted event.
//
//   - When a voteVerified or soft/certThreshold event makes a period which has
//     started interested in a held payload, the
//     returned proposalAccepted or proposalCommittable event carries the
//     payloadPipelined event for that payload in Pipelined.
//
//   - A readStaging event is dispatched to the proposalMachinePeriod.  The proposalStore
//     sets the matching proposal payload (if one exists) in the response.
//
//   - A readPinned event is delivered when the player wants to query the current
//     pinned proposalValue, and corresponding payload if one exists. This occurs
//     during resynchronization when players may relay the pinned value.
//     The event is handled exclusively by the proposalStore and not forwarded.
//
//   - A readWantedPayloads event is delivered when the player has a
//     payload it has not decoded yet, to ask which proposal-values from its
//     original period and proposer could still take a payload. It is handled
//     exclusively by the proposalStore.
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
			e.Pipelined = store.resumeHeld(p.Period)
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
		ea, err = ea.pipeline(up)
		if err != nil {
			return payloadProcessedEvent{T: payloadRejected, Err: makeSerErr(err)}
		}
		return store.requestOrHold(pv, ea, p.Period)

	case payloadVerified:
		if me := e.(messageEvent); me.Cancelled {
			// The payload was neither validated nor refuted, and its
			// blockAssembler rejects later copies, so request its validation
			// again or hold it, as if it had just been pipelined.
			up := me.Input.UnauthenticatedProposal
			pv := up.value()
			ea, ok := store.Assemblers[pv]
			if !ok || ea.Assembled {
				return payloadProcessedEvent{T: payloadRejected, Err: me.Err}
			}
			ea.Pipeline = up
			ea.Filled = true
			return store.requestOrHold(pv, ea, p.Period)
		}

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
		if e.(newPeriodEvent).ResumeHeld {
			if ep := store.resumeHeld(e.(newPeriodEvent).Period); ep.T == payloadPipelined {
				return ep
			}
		}
		return emptyEvent{}

	case newRound:
		if len(store.Assemblers) > 1 {
			// TODO this check is really an implementation invariant; move it into a whitebox test
			r.t.log.Panic("too many assemblers")
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
		// an assembler may not exist - we should add a new one, if it doesn't
		// we don't pin a value here - new period logic should have done that if we fast forward
		ea := store.Assemblers[e.Proposal]
		store.Assemblers[e.Proposal] = ea
		store.Relevant[te.Period] = e.Proposal
		store.trim(p)

		// Resume held payloads only now that Relevant and Assemblers
		// reflect the threshold: a payload which the threshold's value
		// replaced in Relevant[te.Period] is no longer tracked.  te.Period
		// has started once the player handles the threshold.
		pipelined := store.resumeHeld(max(p.Period, te.Period))

		// return committableEvent if ready; else, return proposalAcceptedEvent
		if ea.Assembled {
			return committableEvent{
				Proposal:  e.Proposal,
				Vote:      ea.authenticator(p.Period),
				Pipelined: pipelined,
			}
		}
		// no subsequent softThreshold logic uses these fields, but for completeness...
		e.Payload = ea.Payload
		e.PayloadOk = ea.Assembled
		e.Pipelined = pipelined
		return e

	case readStaging:
		se := e.(stagingValueEvent)
		se = r.dispatch(p, e, proposalMachinePeriod, se.Round, se.Period, 0).(stagingValueEvent)
		ea := store.Assemblers[se.Proposal]
		se.Committable = ea.Assembled
		se.Payload = ea.Payload
		return se
	case readLowestVote:
		re := e.(readLowestEvent)
		return r.dispatch(p, re, proposalMachinePeriod, re.Round, re.Period, 0).(readLowestEvent)
	case readWantedPayloads:
		ce := e.(wantedPayloadsEvent)
		var filled, assembled bool
		for pv, ea := range store.Assemblers {
			if pv.OriginalPeriod != ce.OriginalPeriod || pv.OriginalProposer != ce.OriginalProposer {
				continue
			}
			switch {
			case ea.Assembled:
				assembled = true
			case ea.Filled:
				filled = true
			default:
				ce.EncodingDigests = append(ce.EncodingDigests, pv.EncodingDigest)
			}
		}
		// A payload that no proposal-value is waiting for is refused without
		// reaching blockAssembler.pipeline, which counts duplicate payloads,
		// so it is counted here. It has not been hashed, so it is counted as
		// a duplicate of any payload from its original period and proposer.
		if len(ce.EncodingDigests) == 0 {
			if assembled {
				proposalAlreadyAssembledCounter.Inc(nil)
			} else if filled {
				proposalAlreadyFilledCounter.Inc(nil)
			}
		}
		return ce
	case readPinned:
		se := e.(pinnedValueEvent)
		ea := store.Assemblers[store.Pinned] // If pinned is bottom, assembled/payloadOK = false, payload = bottom
		se.Proposal = store.Pinned
		se.PayloadOK = ea.Assembled
		se.Payload = ea.Payload
		return se
	}
	r.t.log.Panicf("proposalStore: bad event type: observed an event of type %v", e.t())
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

// requestOrHold stores ea, whose Pipeline has no validation request in
// flight.  If pv is pinned or relevant to a period no later than cur, it
// returns the payloadPipelined event on which the player requests validation
// of the Pipeline.  Otherwise only a period after cur is interested in pv: it
// marks ea held and returns an event with Held set, on which the player does
// not request validation.
func (store *proposalStore) requestOrHold(pv proposalValue, ea blockAssembler, cur period) payloadProcessedEvent {
	per, pinned, ok := store.requestKey(pv, cur)
	ea.held = !ok
	store.Assemblers[pv] = ea
	return payloadProcessedEvent{
		T:                      payloadPipelined,
		Vote:                   ea.authenticator(cur),
		Period:                 per,
		Pinned:                 pinned,
		Held:                   ea.held,
		Proposal:               pv,
		UnauthenticatedPayload: ea.Pipeline,
	}
}

// resumeHeld returns the payloadPipelined event for a held payload whose
// proposal-value is now pinned or relevant to a period no later than cur,
// and clears its held flag.  It returns a zero event if there is no such
// payload.  A payload stays held only while its proposal-value is relevant to
// the next period alone, so at most one blockAssembler is held at a time.
func (store *proposalStore) resumeHeld(cur period) payloadProcessedEvent {
	for pv, ea := range store.Assemblers {
		if !ea.held || ea.Assembled {
			continue
		}
		ep := store.requestOrHold(pv, ea, cur)
		if !store.Assemblers[pv].held {
			return ep
		}
	}
	return payloadProcessedEvent{}
}

// requestKey returns the period whose validation request a payload of pv
// belongs to: the pinned request, or the latest period no later than cur for
// which pv is relevant.  ok is false if there is no such period, and the
// payload is held until there is one.
func (store *proposalStore) requestKey(pv proposalValue, cur period) (per period, pinned, ok bool) {
	if store.Pinned == pv {
		return 0, true, true
	}

	for p := range store.Relevant {
		if p <= cur && store.Relevant[p] == pv && (!ok || p > per) {
			per, ok = p, true
		}
	}
	return per, false, ok
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
