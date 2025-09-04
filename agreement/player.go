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
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

// The player implements the top-level state machine functionality of the
// agreement protocol.
type player struct {
	_struct struct{} `codec:","`
	// Round, Period, and Step hold the current round, period, and step of
	// the player state machine.
	Round  round
	Period period
	Step   step

	// LastConcluding holds the largest step reached in the last period.  As
	// described in the spec, it affects the propagation of next-vote
	// messages.
	LastConcluding step

	// Deadline contains the time of the next timeout expected by the player
	// state machine (relevant to the start of the current period).
	Deadline Deadline `codec:"TimersDeadline"`

	// OldDeadline contains the value of Deadline used from a previous version,
	// for backwards compatibility when deserializing player.
	// TODO: remove after consensus upgrade that introduces the Deadline struct.
	OldDeadline time.Duration `codec:"Deadline,omitempty"`

	// Napping is set when the player is expecting a random timeout (i.e.,
	// to determine when the player chooses to send a next-vote).
	Napping bool

	// FastRecoveryDeadline contains the next timeout expected for fast
	// partition recovery.
	FastRecoveryDeadline time.Duration

	// Pending holds the player's proposalTable, which stores proposals that
	// must be verified after some vote has been verified.
	Pending proposalTable

	// the history of arrival times of the lowest credential from previous
	// ronuds, used for calculating the filter timeout dynamically.
	lowestCredentialArrivals credentialArrivalHistory

	// The period 0 dynamic filter timeout calculated for this round, if set,
	// even if dynamic filter timeouts are not enabled. It is used for reporting
	// to telemetry.
	dynamicFilterTimeout time.Duration
}

func (p *player) T() stateMachineTag {
	return playerMachine
}

func (p *player) underlying() actor {
	return p
}

// Precondition: passed-in player is equal to player
// Postcondition: each messageEvent is processed exactly once
func (p *player) handle(r routerHandle, e event) []action {
	var actions []action

	if e.t() == none {
		return nil
	}

	switch e := e.(type) {
	case messageEvent:
		return p.handleMessageEvent(r, e)
	case thresholdEvent:
		return p.handleThresholdEvent(r, e)
	case timeoutEvent:
		if e.T == fastTimeout {
			return p.handleFastTimeout(r, e)
		}

		if !p.Napping {
			r.t.logTimeout(*p)
		}

		var deadlineTimeout time.Duration
		if e.Proto.Version == "" || e.Proto.Err != nil {
			r.t.log.Errorf("failed to read valid protocol version for timeout event (proto %v): %v. "+
				"Falling Back to default deadline timeout.", e.Proto.Version, e.Proto.Err)
			deadlineTimeout = DefaultDeadlineTimeout()
		} else {
			deadlineTimeout = DeadlineTimeout(p.Period, e.Proto.Version)
		}

		switch p.Step {
		case soft:
			// precondition: nap = false
			actions = p.issueSoftVote(r, deadlineTimeout)
			p.Step = cert
			// update tracer state to match player
			r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})
			return actions
		case cert:
			// precondition: nap = false
			p.Step = next
			// update tracer state to match player
			r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})
			return p.issueNextVote(r, deadlineTimeout)
		default:
			if p.Napping {
				return p.issueNextVote(r, deadlineTimeout) // sets p.Napping to false
			}
			// not napping, so we should enter a new step
			p.Step++ // note: this must happen before next timeout setting.
			// TODO add unit test to ensure that deadlines increase monotonically here

			lower, upper := p.Step.nextVoteRanges(deadlineTimeout)
			delta := time.Duration(e.RandomEntropy % uint64(upper-lower))

			p.Napping = true
			p.Deadline = Deadline{Duration: lower + delta, Type: TimeoutDeadline}
			return actions
		}
	case roundInterruptionEvent:
		return p.enterRound(r, e, e.Round)
	case checkpointEvent:
		return p.handleCheckpointEvent(r, e)
	default:
		panic("bad event")
	}
}

func (p *player) handleFastTimeout(r routerHandle, e timeoutEvent) []action {
	if e.Proto.Err != nil {
		r.t.log.Errorf("failed to read protocol version for fastTimeout event (proto %v): %v", e.Proto.Version, e.Proto.Err)
		return nil
	}

	lambda := config.Consensus[e.Proto.Version].FastRecoveryLambda
	k := (p.FastRecoveryDeadline + lambda - 1) / lambda // round up
	lower, upper := k*lambda, (k+1)*lambda
	delta := time.Duration(e.RandomEntropy % uint64(upper-lower))
	if p.FastRecoveryDeadline == 0 {
		// don't vote the first time
		p.FastRecoveryDeadline = lower + delta + lambda // add lambda for extra delay the first time
		return nil
	}
	p.FastRecoveryDeadline = lower + delta
	r.t.logFastTimeout(*p)
	return p.issueFastVote(r)
}

func (p *player) issueSoftVote(r routerHandle, deadlineTimeout time.Duration) (actions []action) {
	defer func() {
		p.Deadline = Deadline{Duration: deadlineTimeout, Type: TimeoutDeadline}
	}()

	e := r.dispatch(*p, proposalFrozenEvent{}, proposalMachinePeriod, p.Round, p.Period, 0)
	a := pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: soft, Proposal: e.(proposalFrozenEvent).Proposal}
	r.t.logProposalFrozen(a.Proposal, a.Round, a.Period)
	r.t.timeR().RecStep(p.Period, soft, a.Proposal)

	res := r.dispatch(*p, nextThresholdStatusRequestEvent{}, voteMachinePeriod, p.Round, p.Period-1, 0)
	nextStatus := res.(nextThresholdStatusEvent) // panic if violate postcondition
	if p.Period > 0 && !nextStatus.Bottom && nextStatus.Proposal != bottom {
		// did not see bottom: vote for our starting value
		// we check if answer.Proposal != bottom because we may have arrived here due to a fast-forward/soft threshold
		// If we arrive due to fast-forward/soft threshold; then answer.Bottom = false and answer.Proposal = bottom
		// and we should soft-vote normally (not based on the starting value)
		a.Proposal = nextStatus.Proposal
		return append(actions, a)
	}

	if a.Proposal == bottom {
		// did not see anything: do not vote
		return nil
	}

	if p.Period > a.Proposal.OriginalPeriod {
		// leader sent reproposal: vote if we saw a quorum for that hash, even if we saw nextStatus.Bottom
		if nextStatus.Proposal != bottom && nextStatus.Proposal == a.Proposal {
			return append(actions, a)
		}
		return nil
	}

	// original proposal: vote for it
	return append(actions, a)
}

// A committableEvent is the trigger for issuing a cert vote.
func (p *player) issueCertVote(r routerHandle, e committableEvent) action {
	r.t.timeR().RecStep(p.Period, cert, e.Proposal)
	return pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: cert, Proposal: e.Proposal}
}

func (p *player) issueNextVote(r routerHandle, deadlineTimeout time.Duration) []action {
	actions := p.partitionPolicy(r)

	a := pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: p.Step, Proposal: bottom}

	answer := stagedValue(*p, r, p.Round, p.Period)
	if answer.Committable {
		a.Proposal = answer.Proposal
	} else {
		res := r.dispatch(*p, nextThresholdStatusRequestEvent{}, voteMachinePeriod, p.Round, p.Period-1, 0)
		nextStatus := res.(nextThresholdStatusEvent) // panic if violate postcondition
		if !nextStatus.Bottom {
			// if we fast-forwarded to this period or entered via a soft/cert threshold,
			// nextStatus.Bottom will be false and we will next vote bottom.
			// As long as a majority of honest users (in the cert threshold case) do not vote bottom (as assumed), we are safe.
			// Note that cert threshold fast-forwarding will never change a next value vote to a next bottom vote -
			// if a player has voted for a value, they have the block, and should have ended the round.
			a.Proposal = nextStatus.Proposal
		}
	}
	actions = append(actions, a)

	r.t.timeR().RecStep(p.Period, p.Step, a.Proposal)

	_, upper := p.Step.nextVoteRanges(deadlineTimeout)
	p.Napping = false
	p.Deadline = Deadline{Duration: upper, Type: TimeoutDeadline}
	return actions
}

func (p *player) issueFastVote(r routerHandle) (actions []action) {
	actions = p.partitionPolicy(r)

	elate := r.dispatch(*p, dumpVotesRequestEvent{}, voteMachineStep, p.Round, p.Period, late).(dumpVotesEvent).Votes
	eredo := r.dispatch(*p, dumpVotesRequestEvent{}, voteMachineStep, p.Round, p.Period, redo).(dumpVotesEvent).Votes
	edown := r.dispatch(*p, dumpVotesRequestEvent{}, voteMachineStep, p.Round, p.Period, down).(dumpVotesEvent).Votes
	votes := append(eredo, edown...)
	votes = append(elate, votes...)
	actions = append(actions, networkAction{T: broadcastVotes, UnauthenticatedVotes: votes})

	a := pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: down, Proposal: bottom}
	answer := stagedValue(*p, r, p.Round, p.Period)
	if answer.Committable {
		a.Step = late
		a.Proposal = answer.Proposal
	} else {
		res := r.dispatch(*p, nextThresholdStatusRequestEvent{}, voteMachinePeriod, p.Round, p.Period-1, 0)
		nextStatus := res.(nextThresholdStatusEvent) // panic if violate postcondition
		if !nextStatus.Bottom {
			a.Step = redo
			// note that this is bottom if we fast-forwarded to this period or entered via a soft/cert threshold.
			a.Proposal = nextStatus.Proposal
		}
	}
	if a.Proposal == bottom {
		// required if we entered the period via a soft threshold
		a.Step = down
	}

	return append(actions, a)
}

func (p *player) handleCheckpointEvent(r routerHandle, e checkpointEvent) []action {
	return []action{
		checkpointAction{ //nolint:gosimple // explicit assignment for clarity
			Round:  e.Round,
			Period: e.Period,
			Step:   e.Step,
			Err:    e.Err,
			done:   e.done,
		}}
}

// updateCredentialArrivalHistory is called at the end of a successful
// uninterrupted round (just after ensureAction is generated) to collect
// credential arrival times to dynamically set the filter timeout.
// It returns the time of the lowest credential's arrival from
// credentialRoundLag rounds ago, if one was collected and added to
// lowestCredentialArrivals, or zero otherwise.
func (p *player) updateCredentialArrivalHistory(r routerHandle, ver protocol.ConsensusVersion) time.Duration {
	if p.Period != 0 {
		// only append to lowestCredentialArrivals if this was a successful round completing in period 0.
		return 0
	}

	if p.Round <= credentialRoundLag {
		// not sufficiently many rounds had passed to collect any measurement
		return 0
	}

	// look up the validatedAt time of the winning proposal-vote from credentialRoundLag ago,
	// by now we should have seen the lowest credential for that round.
	credHistoryRound := p.Round - credentialRoundLag
	re := readLowestEvent{T: readLowestVote, Round: credHistoryRound, Period: 0}
	re = r.dispatch(*p, re, proposalMachineRound, credHistoryRound, 0, 0).(readLowestEvent)
	if !re.HasLowestIncludingLate {
		return 0
	}

	p.lowestCredentialArrivals.store(re.LowestIncludingLate.validatedAt)
	return re.LowestIncludingLate.validatedAt
}

// calculateFilterTimeout chooses the appropriate filter timeout.
func (p *player) calculateFilterTimeout(ver protocol.ConsensusVersion, tracer *tracer) time.Duration {
	proto := config.Consensus[ver]
	if dynamicFilterCredentialArrivalHistory <= 0 || p.Period != 0 {
		// Either dynamic filter timeout is disabled, or we're not in period 0
		// and therefore, can't use dynamic timeout
		return FilterTimeout(p.Period, ver)
	}
	defaultTimeout := FilterTimeout(0, ver)
	if !p.lowestCredentialArrivals.isFull() {
		// not enough samples, use the default
		return defaultTimeout
	}

	dynamicTimeout := p.lowestCredentialArrivals.orderStatistics(dynamicFilterTimeoutCredentialArrivalHistoryIdx) + dynamicFilterTimeoutGraceInterval

	// Make sure the dynamic filter timeout is not too small nor too large
	clampedTimeout := min(max(dynamicTimeout, dynamicFilterTimeoutLowerBound), defaultTimeout)
	tracer.log.Debugf("round %d, period %d: dynamicTimeout = %d, clamped timeout = %d", p.Round, p.Period, dynamicTimeout, clampedTimeout)
	// store dynamicFilterTimeout on the player for debugging & reporting
	p.dynamicFilterTimeout = dynamicTimeout

	if !proto.DynamicFilterTimeout {
		// If the dynamic filter timeout is disabled, return the default filter
		// timeout (after logging what the timeout would have been, if this
		// feature were enabled).
		return defaultTimeout
	}

	return clampedTimeout
}

func (p *player) handleThresholdEvent(r routerHandle, e thresholdEvent) []action {
	r.t.timeR().RecThreshold(e)

	var actions []action
	switch e.t() {
	case certThreshold:
		// for future periods, fast-forwarding below will ensure correct staging
		// for past periods, having a freshest certThreshold will prevent losing the block
		r.dispatch(*p, e, proposalMachine, 0, 0, 0)
		// Now, also check if we have the block.
		res := stagedValue(*p, r, e.Round, e.Period)
		if res.Committable {
			cert := Certificate(e.Bundle)
			a0 := ensureAction{Payload: res.Payload, Certificate: cert}
			a0.voteValidatedAt = p.updateCredentialArrivalHistory(r, e.Proto)
			a0.dynamicFilterTimeout = p.dynamicFilterTimeout
			actions = append(actions, a0)
			as := p.enterRound(r, e, p.Round+1)
			return append(actions, as...)
		}
		// we don't have the block! We need to ensure we will be able to receive the block.
		// In addition, hint to the ledger to fetch by digest.
		actions = append(actions, stageDigestAction{Certificate: Certificate(e.Bundle)})
		if p.Period < e.Period {
			actions = append(actions, p.enterPeriod(r, e, e.Period)...)
		}
		return actions

	case softThreshold:
		// note that it is ok not to stage softThresholds from previous periods; relaying the pinned block
		// handles any edge case (w.r.t. resynchronization, at least)
		if p.Period > e.Period {
			return nil
		}
		if p.Period < e.Period {
			return p.enterPeriod(r, e, e.Period)
		}
		ec := r.dispatch(*p, e, proposalMachine, p.Round, p.Period, 0)
		if ec.t() == proposalCommittable && p.Step <= cert {
			actions = append(actions, p.issueCertVote(r, ec.(committableEvent)))
		}
		return actions

	case nextThreshold:
		// We might receive a next threshold event for the previous period due to fast-forwarding or a soft threshold.
		// If we do, this is okay, but the proposalMachine contract-checker will complain.
		// TODO test this case and update the contract-checker so it does not complain when this is benign
		if p.Period > e.Period {
			return nil
		}
		return p.enterPeriod(r, e, e.Period+1)
	default:
		panic("bad event")
	}
}

func (p *player) enterPeriod(r routerHandle, source thresholdEvent, target period) []action {
	actions := p.partitionPolicy(r)

	// this needs to happen before changing player state so the correct old blockAssemblers can be promoted
	// TODO might be better passing through the old period explicitly in the {soft,next}Threshold event
	e := r.dispatch(*p, source, proposalMachine, p.Round, p.Period, 0)
	r.t.logPeriodConcluded(*p, target, source.Proposal)

	p.LastConcluding = p.Step
	p.Period = target
	p.Step = soft
	p.Napping = false
	p.FastRecoveryDeadline = 0 // set immediately

	if target != 0 {
		// We entered a non-0 period, we should reset the filter timeout
		// calculation mechanism.
		p.lowestCredentialArrivals.reset()
	}
	p.Deadline = Deadline{Duration: p.calculateFilterTimeout(source.Proto, r.t), Type: TimeoutFilter}

	// update tracer state to match player
	r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})

	actions = append(actions, rezeroAction{Round: p.Round})

	if e.t() == proposalCommittable { // implies source.t() == softThreshold
		return append(actions, p.issueCertVote(r, e.(committableEvent)))
	}
	if source.t() == nextThreshold {
		proposal := source.Proposal
		if proposal == bottom {
			a := pseudonodeAction{T: assemble, Round: p.Round, Period: p.Period}
			return append(actions, a)
		}

		a := pseudonodeAction{T: repropose, Round: p.Round, Period: p.Period, Proposal: proposal}
		return append(actions, a)
	}

	return actions
}

func (p *player) enterRound(r routerHandle, source event, target round) []action {
	var actions []action

	newRoundEvent := source
	// passing in a cert threshold to the proposalMachine is now ambiguous,
	// so replace with an explicit new round event.
	// In addition, handle a new source: payloadVerified (which can trigger new round if
	// received after cert threshold)
	if source.t() == certThreshold || source.t() == payloadVerified { // i.e., source.t() != roundInterruption
		r.t.logRoundStart(*p, target)
		newRoundEvent = roundInterruptionEvent{Round: target}
	}
	// this happens here so that the proposalMachine contract does not complain
	e := r.dispatch(*p, newRoundEvent, proposalMachine, target, 0, 0)

	p.LastConcluding = p.Step
	p.Round = target
	p.Period = 0
	p.Step = soft
	p.Napping = false
	p.FastRecoveryDeadline = 0 // set immediately

	switch source := source.(type) {
	case roundInterruptionEvent:
		p.Deadline = Deadline{Duration: p.calculateFilterTimeout(source.Proto.Version, r.t), Type: TimeoutFilter}
	case thresholdEvent:
		p.Deadline = Deadline{Duration: p.calculateFilterTimeout(source.Proto, r.t), Type: TimeoutFilter}
	case filterableMessageEvent:
		p.Deadline = Deadline{Duration: p.calculateFilterTimeout(source.Proto.Version, r.t), Type: TimeoutFilter}
	}

	// update tracer state to match player
	r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})
	r.t.resetTimingWithPipeline(target)

	// do proposal-related actions
	as := pseudonodeAction{T: assemble, Round: p.Round, Period: 0}
	actions = append(actions, rezeroAction{Round: target}, as)

	if e.t() == payloadPipelined {
		e := e.(payloadProcessedEvent)
		msg := message{messageHandle: 0, Tag: protocol.ProposalPayloadTag, UnauthenticatedProposal: e.UnauthenticatedPayload} // TODO do we want to keep around the original handle?
		a := verifyPayloadAction(messageEvent{T: payloadPresent, Input: msg}, p.Round, e.Period, e.Pinned)
		actions = append(actions, a)
	}

	// we might need to handle a pipelined threshold event
	res := r.dispatch(*p, freshestBundleRequestEvent{}, voteMachineRound, p.Round, 0, 0)
	freshestRes := res.(freshestBundleEvent) // panic if violate postcondition
	if freshestRes.Ok {
		a4 := p.handle(r, freshestRes.Event)
		actions = append(actions, a4...)
	}
	return actions
}

// partitionPolicy checks if the player is in a partition, and if it is,
// it returns the list of actions necessary to recover.
//
// partitionPolicy represents an attempt to resynchronize.
//
// These actions include the repropagation of the freshest bundle, if one was seen,
// (necessarily true for p.Period > 0 or the presence of a soft threshold)
// and the repropagation of the block payload this bundle votes for, if one was seen.
func (p *player) partitionPolicy(r routerHandle) (actions []action) {
	if !p.partitioned() {
		return
	}

	res := r.dispatch(*p, freshestBundleRequestEvent{}, voteMachineRound, p.Round, 0, 0)
	bundleResponse := res.(freshestBundleEvent) // panic if violate postcondition
	if bundleResponse.Ok {
		// TODO do we want to authenticate our own bundles?
		b := bundleResponse.Event.Bundle
		r.t.logBundleBroadcast(*p, b)
		a0 := broadcastAction(protocol.VoteBundleTag, b)
		actions = append(actions, a0)
	}

	// On resynchronization, first try relaying the staged proposal from the same period as
	// the freshest bundle. If that does not exist, for instance if we saw two next quorums in a row,
	// then we fall back to relaying the pinned value, for liveness.
	// One specific scenario where this is essential, assuming we handle ensure digest asynchronously:
	// - Let the majority of honest nodes cert vote, and then see a next value quorum, and enter p + 1.
	// - They see another next value quorum, and enter p + 2.
	// - The minority of honest nodes see a certThreshold (but without a block), in period p. Assume that
	//   they are partitioned from the majority of honest nodes, until the majority reach p + 2.
	// - The minority already has the freshest bundle, so will not advance to period p + 2. However, the
	//   majority will also filter out the cert threshold (due to a stale period).
	// - Now we relay the pinned value, and then can wait for catchup.
	// - Another optimization is that we could allow cert bundles from stale periods to bypass the filter.
	//   This may be worth implementing in the future.
	bundleRound := p.Round
	bundlePeriod := p.Period
	switch {
	case bundleResponse.Ok && bundleResponse.Event.Bundle.Proposal != bottom:
		b := bundleResponse.Event.Bundle
		bundleRound = b.Round
		bundlePeriod = b.Period
		fallthrough
	case p.Period == 0:
		resStaged := stagedValue(*p, r, bundleRound, bundlePeriod)
		if resStaged.Committable {
			transmit := compoundMessage{Proposal: resStaged.Payload.u()}
			r.t.logProposalRepropagate(resStaged.Proposal, bundleRound, bundlePeriod)
			a1 := broadcastAction(protocol.ProposalPayloadTag, transmit)
			actions = append(actions, a1)
		} else {
			// even if there is no staged value, there may be a pinned value
			resPinned := pinnedValue(*p, r, bundleRound)
			if resPinned.PayloadOK {
				transmit := compoundMessage{Proposal: resPinned.Payload.u()}
				r.t.logProposalRepropagate(resPinned.Proposal, bundleRound, bundlePeriod)
				a1 := broadcastAction(protocol.ProposalPayloadTag, transmit)
				actions = append(actions, a1)
			}
		}

	}
	return
}

func (p *player) partitioned() bool {
	return p.Step >= partitionStep || p.Period >= 3
}

func (p *player) handleMessageEvent(r routerHandle, e messageEvent) (actions []action) {
	// is it a proposal-vote? (i.e., vote where step = 0)
	proposalVote := false
	switch e.t() {
	case votePresent, voteVerified:
		uv := e.Input.UnauthenticatedVote
		proposalVote = (uv.R.Step == propose)
	}

	// wrap message event with current player round, etc. for freshness computation
	delegatedE := filterableMessageEvent{
		messageEvent: e,
		FreshnessData: freshnessData{
			PlayerRound:          p.Round,
			PlayerPeriod:         p.Period,
			PlayerStep:           p.Step,
			PlayerLastConcluding: p.LastConcluding,
		},
	}

	// if so, process it separately
	if proposalVote {
		doneProcessing := true // TODO check that this is still required
		defer func() {
			tail := e.Tail
			if e.t() == voteVerified {
				tail = p.Pending.pop(e.TaskIndex)
			}

			if tail == nil || !doneProcessing {
				return
			}

			ev := *tail // make sure the event we handle is messageEvent, not *messageEvent
			suffix := p.handle(r, ev)
			actions = append(actions, suffix...)
		}()

		ef := r.dispatch(*p, delegatedE, proposalMachine, 0, 0, 0)
		switch ef.t() {
		case voteMalformed:
			err := ef.(filteredEvent).Err
			return append(actions, disconnectAction(e, err))
		case voteFiltered:
			ver := e.Proto.Version
			proto := config.Consensus[ver]
			if !proto.DynamicFilterTimeout {
				// Dynamic filter timeout feature disabled, so we filter the
				// message as usual (keeping earlier behavior)
				err := ef.(filteredEvent).Err
				return append(actions, ignoreAction(e, err))
			}
			switch ef.(filteredEvent).LateCredentialTrackingNote {
			case VerifiedBetterLateCredentialForTracking:
				// Dynamic filter timeout feature enabled, and current message
				// updated the best credential arrival time
				v := e.Input.Vote
				return append(actions, relayAction(e, protocol.AgreementVoteTag, v.u()))
			case NoLateCredentialTrackingImpact:
				// Dynamic filter timeout feature enabled, but current message
				// may not update the best credential arrival time, so we should
				// ignore it.
				err := ef.(filteredEvent).Err
				return append(actions, ignoreAction(e, err))
			case UnverifiedLateCredentialForTracking:
				// In this case, the vote may impact credential tracking, but needs to
				// be validated. So we do not return here, and continue processing, so that
				// the votePresent check below will make a verifyVoteAction for this vote.
			}
		}

		if e.t() == votePresent {
			doneProcessing = false
			seq := p.Pending.push(e.Tail)
			uv := e.Input.UnauthenticatedVote
			return append(actions, verifyVoteAction(e, uv.R.Round, uv.R.Period, seq))
		}
		v := e.Input.Vote
		a := relayAction(e, protocol.AgreementVoteTag, v.u())
		ep := ef.(proposalAcceptedEvent)
		if ep.PayloadOk {
			transmit := compoundMessage{
				Proposal: ep.Payload.u(),
				Vote:     v.u(),
			}
			a = broadcastAction(protocol.ProposalPayloadTag, transmit)
		}
		return append(actions, a)
	}

	switch e.t() {
	case payloadPresent, payloadVerified:
		ef := r.dispatch(*p, delegatedE, proposalMachine, 0, 0, 0)
		switch ef.t() {
		case payloadMalformed:
			err := makeSerErrf("rejected message since it was invalid: %v", ef.(filteredEvent).Err)
			return append(actions, ignoreAction(e, err))
		case payloadRejected:
			return append(actions, ignoreAction(e, ef.(payloadProcessedEvent).Err))
		case payloadPipelined:
			ep := ef.(payloadProcessedEvent)

			up := e.Input.UnauthenticatedProposal
			uv := ef.(payloadProcessedEvent).Vote.u()

			// relay proposal if it has been pipelined
			ra := relayAction(e, protocol.ProposalPayloadTag, compoundMessage{Proposal: up, Vote: uv})

			if ep.Round == p.Round {
				vpa := verifyPayloadAction(e, ep.Round, ep.Period, ep.Pinned)
				return append(actions, vpa, ra)
			}

			actions = append(actions, ra)
		}

		// relay as the proposer
		if e.Input.messageHandle == nil {
			var uv unauthenticatedVote
			switch ef.t() {
			case payloadPipelined, payloadAccepted:
				uv = ef.(payloadProcessedEvent).Vote.u()
			case proposalCommittable:
				uv = ef.(committableEvent).Vote.u()
			}
			up := e.Input.UnauthenticatedProposal

			a := relayAction(e, protocol.ProposalPayloadTag, compoundMessage{Proposal: up, Vote: uv})
			actions = append(actions, a)
		}

		// If the payload is valid, check it against any received cert threshold.
		// Of course, this should only trigger for payloadVerified case.
		// This allows us to handle late payloads (relative to cert-bundles, i.e., certificates) without resorting to catchup.
		if ef.t() == proposalCommittable || ef.t() == payloadAccepted {
			freshestRes := r.dispatch(*p, freshestBundleRequestEvent{}, voteMachineRound, p.Round, 0, 0).(freshestBundleEvent)
			if freshestRes.Ok && freshestRes.Event.t() == certThreshold && freshestRes.Event.Proposal == e.Input.Proposal.value() {
				cert := Certificate(freshestRes.Event.Bundle)
				a0 := ensureAction{Payload: e.Input.Proposal, Certificate: cert}
				a0.voteValidatedAt = p.updateCredentialArrivalHistory(r, e.Proto.Version)
				a0.dynamicFilterTimeout = p.dynamicFilterTimeout
				actions = append(actions, a0)
				as := p.enterRound(r, delegatedE, cert.Round+1)
				return append(actions, as...)
			}
		}

		if ef.t() == proposalCommittable && p.Step <= cert {
			actions = append(actions, p.issueCertVote(r, ef.(committableEvent)))
		}
		return actions

	case votePresent, voteVerified:
		ef := r.dispatch(*p, delegatedE, voteMachine, 0, 0, 0)
		switch ef.t() {
		case voteMalformed:
			// TODO Add Metrics here to capture telemetryspec.VoteRejectedEvent details
			// 	Reason:           fmt.Sprintf("rejected malformed message: %v", e.Err),
			err := makeSerErrf("rejected message since it was invalid: %v", ef.(filteredEvent).Err)
			return append(actions, disconnectAction(e, err))
		case voteFiltered:
			err := ef.(filteredEvent).Err
			return append(actions, ignoreAction(e, err))
		}
		if e.t() == votePresent {
			uv := e.Input.UnauthenticatedVote
			return append(actions, verifyVoteAction(e, uv.R.Round, uv.R.Period, 0))
		} // else e.t() == voteVerified
		v := e.Input.Vote
		actions = append(actions, relayAction(e, protocol.AgreementVoteTag, v.u()))
		a1 := p.handle(r, ef)
		return append(actions, a1...)

	case bundlePresent, bundleVerified:
		ef := r.dispatch(*p, delegatedE, voteMachine, 0, 0, 0)
		switch ef.t() {
		case bundleMalformed:
			err := makeSerErrf("rejected message since it was invalid: %v", ef.(filteredEvent).Err)
			return append(actions, disconnectAction(e, err))
		case bundleFiltered:
			err := ef.(filteredEvent).Err
			return append(actions, ignoreAction(e, err))
		}
		if e.t() == bundlePresent {
			ub := e.Input.UnauthenticatedBundle
			return append(actions, verifyBundleAction(e, ub.Round, ub.Period, ub.Step))
		}
		a0 := relayAction(e, protocol.VoteBundleTag, ef.(thresholdEvent).Bundle)
		a1 := p.handle(r, ef)
		return append(append(actions, a0), a1...)
	}

	panic("bad event")
}
