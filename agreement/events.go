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
	"github.com/algorand/go-algorand/protocol"
)

// An event represents the communication of an event to a state machine.
//
// The eventType of the event corresponds to its semantics.  Metadata associated
// with an event is returned in the struct that implements the event interface.
type event interface {
	// t returns the eventType associated with the event.
	t() eventType

	// String returns a string description of an event.
	String() string

	// ComparableStr returns a comparable string description of an event
	// for testing purposes.
	ComparableStr() string
}

// A ConsensusVersionView is a view of the consensus version as read from a
// LedgerReader, associated with some round.
type ConsensusVersionView struct {
	Err     serializableError
	Version protocol.ConsensusVersion
}

// An externalEvent represents an event delivered to the top-level state machine.
//
// External events are associated with a round and a view of consensus version
// on that round.
type externalEvent interface {
	event

	// ConsensusRound is the round related to this event.
	ConsensusRound() round

	// AttachConsensusVersion returns a copy of this externalEvent with a
	// ConsensusVersion attached.
	AttachConsensusVersion(v ConsensusVersionView) externalEvent
}

// An eventType identifies the particular type of event emitted.
//
// The eventType is distinct from the Go event struct which implements the event
// interface.  The semantics of an event depends on the eventType and not on the
// type of the implementing struct.
//
//go:generate stringer -type=eventType
//msgp:ignore eventType
type eventType int

const (
	// none is returned by state machines which have no event to return
	// otherwise.
	none eventType = iota

	// Some events originate from input sources to the agreement service.
	// These events are serialized via the demultiplexer.

	// votePresent, payloadPresent, and bundlePresent are emitted by the
	// network as input to the player state machine as messages are
	// received by the network.
	//
	// These events contain the unverfied version of the message object
	// itself as well as the MessageHandle tag.
	votePresent
	payloadPresent
	bundlePresent

	// voteVerified, payloadVerified, and bundleVerified are emitted by the
	// cryptoVerifier as input to the player state machine as cryptographic
	// verification completes for messages.
	//
	// These events contain the original unverified version of the message
	// object and the MessageHandle tag associated with the message when
	// first received.
	//
	// If verification has succeeded, these events also contain the verified
	// version of the message object, and their Err field is set to nil.  If
	// verification has failed, these events instead set the Err field with
	// the reason that verification failed.
	voteVerified
	payloadVerified
	bundleVerified

	// roundInterruption is emitted by the Ledger as input to the player
	// state machine when an external source observes that the player's
	// current round has completed concurrent with the player's operation.
	// roundInterruption is also emitted (internally, by the player itself) after
	// calling ensureBlock.
	roundInterruption

	// timeout is emitted by the Clock as input to the player state machine
	// as the system observes that a timeout has been reached.
	//
	// The duration of the timeout is the one specified in player.Deadline.
	// This duration is expressed as an offset from the start of the current
	// period.
	//
	// fastTimeout is like timeout but for fast partition recovery.
	timeout
	fastTimeout

	// Other events are delivered from one state machine to another to
	// communicate some message or as a reply to some message.  These events
	// are internally dispatched via the router.

	// softThreshold, certThreshold, and nextThreshold are emitted by vote
	// state machines as they observe that a threshold of votes have been
	// met for a given step.
	//
	// These events may tell the player state machine to change their round,
	// their period, or possibly to send a cert vote.  These events are also
	// delivered to the proposal state machines to ensure that the correct
	// block is staged and relayed.
	softThreshold
	certThreshold
	nextThreshold

	// proposalCommittable is returned by the proposal state machines when a
	// proposal-value is observed to be committable (e.g., it is possible
	// that a certificate has formed for that proposal-value.
	proposalCommittable

	// proposalCommittable is returned by the proposal state machines when a
	// proposal-value is accepted.
	proposalAccepted

	// voteFiltered and voteMalformed are returned by the voteMachine and
	// the proposalMachine when a vote is invalid because it is corrupt
	// (voteMalformed) or irrelevant (voteFiltered).
	voteFiltered
	voteMalformed

	// bundleFiltered and bundleMalformed are returned by the voteMachine
	// when a bundle is invalid because it is corrupt (bundleMalformed) or
	// irrelevant (bundleFiltered).
	bundleFiltered
	bundleMalformed

	// payloadRejected and payloadMalformed are returned by the
	// proposalMachine when a proposal payload is invalid because it is
	// corrupt (payloadMalformed) or irrelevant (payloadRejected).
	payloadRejected
	payloadMalformed

	// payloadPipelined and payloadAccepted are returned by a proposal state
	// machine when either an unauthenticated (payloadPipelined) or an
	// authenticated (payloadAccepted) proposal payload is accepted and
	// stored.
	payloadPipelined
	payloadAccepted

	// proposalFrozen is sent between the player and proposal state machines
	// to specify that the proposal-vote with the lowest credential should
	// be fixed.
	proposalFrozen

	// voteAccepted is delivered from the voteMachine to its children after
	// a relevant vote has been validated.
	voteAccepted

	// newRound and newPeriod are delivered from the proposalMachine to
	// their children when a new round or period is observed.
	newRound
	newPeriod

	// readStaging is sent to the proposalPeriodMachine to read the staging
	// value for that period, if it exists.  It is returned by this machine
	// with the response.
	readStaging

	// readPinned is sent to the proposalStore to read the pinned value, if it exists.
	readPinned

	/*
	 * The following are event types that replace queries, and may warrant
	 * a revision to make them more state-machine-esque.
	 */

	// voteFilterRequest is an internal event emitted by vote aggregator and
	// the proposal manager to the vote step machines and the proposal period
	// machines respectively to check for duplicate votes. They enable the emission
	// of voteFilteredStep events.
	voteFilterRequest
	voteFilteredStep

	// nextThresholdStatusRequest is an internal event handled by voteMachinePeriod
	// that generates a corresponding nextThresholdStatus tracking whether the period
	// has seen none, a bot threshold, a value threshold, or both thresholds.
	nextThresholdStatusRequest
	nextThresholdStatus

	// freshestBundleRequest is an internal event handled by voteMachineRound that
	// generates a corresponding freshestBundle event.
	freshestBundleRequest
	freshestBundle

	// dumpVotesRequest is an internal event handled by voteTracker that generates
	// a corresponding dumpVotes event.
	dumpVotesRequest
	dumpVotes

	// For testing purposes only
	wrappedAction

	// checkpointReached indicates that we've completly persisted the agreement state to disk.
	// it's invoked by the end of the persistence loop on either success or failuire.
	checkpointReached
)

type emptyEvent struct{}

func (e emptyEvent) t() eventType {
	return none
}

func (e emptyEvent) String() string {
	return e.t().String()
}

func (e emptyEvent) ComparableStr() string {
	return e.String()
}

func (e emptyEvent) ConsensusRound() round {
	return roundZero
}

func (e emptyEvent) AttachConsensusVersion(v ConsensusVersionView) externalEvent {
	return e
}

type messageEvent struct {
	// {vote,bundle,payload}{Present,Verified}
	T eventType

	// Input represents the message itself.
	Input message

	// Err is set if cryptographic verification was attempted and failed for
	// Input.
	Err serializableError
	// TaskIndex is optionally set to track a message as it is processed
	// through cryptographic verification.
	TaskIndex int

	// Tail is an optionally-set field which specifies an unauthenticated
	// proposal which should be processed after Input is processed.  Tail is
	// used to schedule processing proposal payloads after a matching
	// proposal-vote.
	Tail *messageEvent
	// Tail *unauthenticatedProposal

	// whether the corresponding request was cancelled
	Cancelled bool

	Proto ConsensusVersionView
}

func (e messageEvent) t() eventType {
	return e.T
}

func (e messageEvent) String() string {
	return fmt.Sprintf("{T:%s Err:%v}", e.t().String(), e.Err)
}

func (e messageEvent) ComparableStr() string {
	return e.T.String()
}

func (e messageEvent) ConsensusRound() round {
	switch e.T {
	case votePresent, voteVerified:
		return e.Input.UnauthenticatedVote.R.roundBranch()
	case payloadPresent, payloadVerified:
		return e.Input.UnauthenticatedProposal.roundBranch()
	case bundlePresent, bundleVerified:
		return e.Input.UnauthenticatedBundle.roundBranch()
	default:
		return roundZero
	}
}

func (e messageEvent) AttachConsensusVersion(v ConsensusVersionView) externalEvent {
	e.Proto = v
	return e
}

// freshnessData is bundled with filterableMessageEvent
// to allow for delegated freshness computation
type freshnessData struct {
	PlayerRound          round
	PlayerPeriod         period
	PlayerStep           step
	PlayerLastConcluding step
}

type filterableMessageEvent struct {
	messageEvent

	// bundle-in player data for freshness computation
	// we may want to rethink the SM structure here to avoid passing around state
	FreshnessData freshnessData
}

type roundInterruptionEvent struct {
	// Round holds the round the state machine should enter after processing
	// this event.
	Round round

	Proto ConsensusVersionView
}

func (e roundInterruptionEvent) t() eventType {
	return roundInterruption
}

func (e roundInterruptionEvent) String() string {
	return e.t().String()
}

func (e roundInterruptionEvent) ComparableStr() string {
	return e.String()
}

func (e roundInterruptionEvent) ConsensusRound() round {
	return e.Round
}

func (e roundInterruptionEvent) AttachConsensusVersion(v ConsensusVersionView) externalEvent {
	e.Proto = v
	return e
}

type timeoutEvent struct {
	// {timeout,fastTimeout}
	T eventType

	RandomEntropy uint64

	Round round
	Proto ConsensusVersionView
}

func (e timeoutEvent) t() eventType {
	return e.T
}

func (e timeoutEvent) String() string {
	return e.t().String()
}

func (e timeoutEvent) ComparableStr() string {
	return e.t().String()
}

func (e timeoutEvent) ConsensusRound() round {
	return e.Round
}

func (e timeoutEvent) AttachConsensusVersion(v ConsensusVersionView) externalEvent {
	e.Proto = v
	return e
}

type newRoundEvent struct{}

func (e newRoundEvent) t() eventType {
	return newRound
}

func (e newRoundEvent) String() string {
	return e.t().String()
}

func (e newRoundEvent) ComparableStr() string {
	return e.String()
}

type newPeriodEvent struct {
	// Period holds the latest period relevant to the proposalRoundMachine.
	Period period
	// Proposal holds the proposal-value that the new period may want to
	// agree on.  It is used to update the pinned value.
	Proposal proposalValue
}

func (e newPeriodEvent) t() eventType {
	return newPeriod
}

func (e newPeriodEvent) String() string {
	return e.t().String()
}

func (e newPeriodEvent) ComparableStr() string {
	return fmt.Sprintf("%s: %d\t%.5s", e.t().String(), e.Period, e.Proposal.BlockDigest.String())
}

type voteAcceptedEvent struct {
	// Vote holds the vote accepted by the voteMachine.
	Vote vote

	// Proto is the consensus version corresponding to Vote.R.Round
	Proto protocol.ConsensusVersion
}

func (e voteAcceptedEvent) t() eventType {
	return voteAccepted
}

func (e voteAcceptedEvent) String() string {
	return fmt.Sprintf("%s: %d\t%.10s\t%.5s", e.t().String(), e.Vote.R.Step, e.Vote.R.Sender.String(), e.Vote.R.Proposal.BlockDigest.String())
}

func (e voteAcceptedEvent) ComparableStr() string {
	return e.String()
}

type proposalAcceptedEvent struct {
	// Round and Period are the round in which the proposal was accepted.
	Round  round
	Period period

	// Proposal is the proposal-value which was accepted.
	Proposal proposalValue

	// PayloadOk is true if a proposal payload which corresponds to the
	// proposal-value has already been received.  Payload holds the proposal
	// payload if this is the case.
	Payload   proposal
	PayloadOk bool
}

func (e proposalAcceptedEvent) t() eventType {
	return proposalAccepted
}

func (e proposalAcceptedEvent) String() string {
	return fmt.Sprintf("%v: %.5v", e.t().String(), e.Proposal.BlockDigest.String())
}

func (e proposalAcceptedEvent) ComparableStr() string {
	return e.String()
}

type proposalFrozenEvent struct {
	// Proposal is set to be the proposal-value which was frozen.
	Proposal proposalValue
}

func (e proposalFrozenEvent) t() eventType {
	return proposalFrozen
}

func (e proposalFrozenEvent) String() string {
	return e.t().String()
}

func (e proposalFrozenEvent) ComparableStr() string {
	return e.String()
}

type committableEvent struct {
	// Proposal is set to be the proposal-value which is committable.
	Proposal proposalValue

	// the proposal-vote that authenticated the payload (if one exists)
	Vote vote
}

func (e committableEvent) t() eventType {
	return proposalCommittable
}

func (e committableEvent) String() string {
	return e.t().String()
}

func (e committableEvent) ComparableStr() string {
	return e.String()
}

type payloadProcessedEvent struct {
	// payload{Rejected,Pipelined,Accepted}
	T eventType

	// Round is the round for which a payload has been pipelined or
	// accepted.
	Round round
	// Period is the period that is interested in this payload.
	// For reproposed payloads this may be different from the
	// original period in which the block was proposed.
	Period period
	// Pinned is set if this is a pinned payload.  If Pinned is set,
	// Period will be 0.
	Pinned bool

	// Proposal is the proposal-value that corresponds to the payload.
	Proposal proposalValue

	// UnauthenticatedPayload is the proposal payload which was pipelined by
	// proposal machine.
	UnauthenticatedPayload unauthenticatedProposal

	// Vote holds some proposal-vote that authenticated the payload, if one
	// exists.
	Vote vote

	// Err is set to be the reason the proposal payload was rejected in
	// payloadRejected.
	Err serializableError
}

func (e payloadProcessedEvent) t() eventType {
	return e.T
}

func (e payloadProcessedEvent) String() string {
	if e.t() == payloadRejected {
		return fmt.Sprintf("%v: %v; %.5v", e.t().String(), e.Err, e.Proposal.BlockDigest.String())
	}
	return fmt.Sprintf("%v: %.5v", e.t().String(), e.Proposal.BlockDigest.String())
}

func (e payloadProcessedEvent) ComparableStr() string {
	return fmt.Sprintf("%v: %.5v", e.t().String(), e.Proposal.BlockDigest.String())
}

type filteredEvent struct {
	// {proposal,vote,bundle}{Filtered,Malformed}
	T eventType

	// Err is the reason cryptographic verification failed and is set for
	// events {proposal,vote,bundle}Malformed.
	Err serializableError
}

func (e filteredEvent) t() eventType {
	return e.T
}

func (e filteredEvent) String() string {
	return fmt.Sprintf("%v: %v", e.t().String(), e.Err)
}

func (e filteredEvent) ComparableStr() string {
	return e.t().String()
}

type stagingValueEvent struct {
	// Round and Period are the round and period of the staging value.
	Round  round
	Period period

	// Proposal holds the staging value itself.
	Proposal proposalValue
	// Payload holds the payload, if one exists (which is the case if Committable is set).
	Payload proposal
	// Committable is set if and only if the staging value is committable.
	Committable bool
}

func (e stagingValueEvent) t() eventType {
	return readStaging
}

func (e stagingValueEvent) String() string {
	return fmt.Sprintf("%v: %.5v", e.t().String(), e.Proposal.BlockDigest.String())
}

func (e stagingValueEvent) ComparableStr() string {
	return e.String()
}

type pinnedValueEvent struct {
	// Round is the round for which to query the current pinned value
	Round round

	// Proposal holds the pinned value itself.
	Proposal proposalValue
	// Payload holds the payload, if one exists (which is the case if PayloadOK is set).
	Payload proposal
	// PayloadOK is set if and only if a payload was received for the pinned value.
	PayloadOK bool
}

func (e pinnedValueEvent) t() eventType {
	return readPinned
}

func (e pinnedValueEvent) String() string {
	return fmt.Sprintf("%v: %.5v", e.t().String(), e.Proposal.BlockDigest.String())
}

func (e pinnedValueEvent) ComparableStr() string {
	return e.String()
}

type thresholdEvent struct {
	// {{soft,cert,next}Threshold, none}
	T eventType

	// Round, Period, and Step describe the round, period, and step where
	// the threshold was reached.
	Round  round
	Period period
	Step   step

	// Proposal is the proposal-value for which the threshold was reached.
	Proposal proposalValue

	// Bundle holds a quorum of votes which form the threshold.
	Bundle unauthenticatedBundle

	Proto protocol.ConsensusVersion
}

func (e thresholdEvent) t() eventType {
	return e.T
}

func (e thresholdEvent) String() string {
	switch e.t() {
	case none:
		return e.t().String()
	default:
		return fmt.Sprintf("%v: %.5s", e.t().String(), e.Proposal.BlockDigest.String())
	}
}

func (e thresholdEvent) ComparableStr() string {
	return e.String()
}

// fresherThan produces a partial ordering on threshold events from the same
// round.
//
// The ordering is given as follows:
//
//  - certThreshold events are fresher than all other non-certThreshold events.
//  - Events from a later period are fresher than events from an older period.
//  - nextThreshold events are fresher than softThreshold events from the same
//    period.
//  - nextThreshold events for the bottom proposal-value are fresher than
//    nextThreshold events for some other value.
//
// Precondition: e.Round == o.Round if e.T != none and o.T != none
func (e thresholdEvent) fresherThan(o thresholdEvent) bool {
	if e.T == none && o.T == none {
		return true
	}

	if e.T == none {
		return false
	}

	if o.T == none {
		return true
	}

	if e.Round != o.Round {
		logging.Base().Panicf("round mismatch: %v != %v", e.Round, o.Round)
	}

	switch o.T {
	case softThreshold:
	case certThreshold:
	case nextThreshold:
	default:
		logging.Base().Panicf("bad event: %v", e.T)
	}
	switch e.T {
	case softThreshold:
	case certThreshold:
	case nextThreshold:
	default:
		logging.Base().Panicf("bad event: %v", e.T)
	}

	if o.T == certThreshold {
		return false
	}
	switch e.T {
	case softThreshold:
		return e.Period > o.Period
	case certThreshold:
		return true
	case nextThreshold:
		if e.Period > o.Period {
			return true
		}
		if e.Period < o.Period {
			return false
		}

		if o.T == softThreshold {
			return true
		}

		return e.Proposal == bottom && o.Proposal != bottom
	}
	logging.Base().Panicf("bad case: %v", e.T)
	return false
}

// zeroEvent creates a zeroed event of a given type
func zeroEvent(t eventType) event {
	switch t {
	case none:
		return emptyEvent{}
	case votePresent, voteVerified, payloadPresent, payloadVerified, bundlePresent, bundleVerified:
		return messageEvent{}
	case roundInterruption:
		return roundInterruptionEvent{}
	case timeout, fastTimeout:
		return timeoutEvent{}
	case newRound:
		return newRoundEvent{}
	case newPeriod:
		return newPeriodEvent{}
	case voteAccepted:
		return voteAcceptedEvent{}
	case proposalAccepted:
		return proposalAcceptedEvent{}
	case proposalFrozen:
		return proposalFrozenEvent{}
	case proposalCommittable:
		return committableEvent{}
	case payloadRejected, payloadPipelined, payloadAccepted:
		return payloadProcessedEvent{}
	case voteFiltered, bundleFiltered:
		return filteredEvent{}
	case softThreshold, certThreshold, nextThreshold:
		return thresholdEvent{}
	case checkpointReached:
		return checkpointEvent{}
	default:
		err := fmt.Errorf("bad event type: %v", t)
		panic(err)
	}
}

/* Former Query Events */

type voteFilterRequestEvent struct {
	RawVote rawVote
}

func (e voteFilterRequestEvent) t() eventType {
	return voteFilterRequest
}

func (e voteFilterRequestEvent) String() string {
	return fmt.Sprintf("%s: %d\t%.10s\t%.5s", e.t().String(), e.RawVote.Step, e.RawVote.Sender.String(), e.RawVote.Proposal.BlockDigest.String())
}

func (e voteFilterRequestEvent) ComparableStr() string {
	return e.String()
}

type filteredStepEvent struct {
	// voteFilteredStep
	T eventType
}

func (e filteredStepEvent) t() eventType {
	return e.T
}

func (e filteredStepEvent) String() string {
	return e.T.String()
}

func (e filteredStepEvent) ComparableStr() string {
	return e.String()
}

type nextThresholdStatusRequestEvent struct {
	// should be dispatched to the round, period in question, so no need to store that
}

func (e nextThresholdStatusRequestEvent) t() eventType {
	return nextThresholdStatusRequest
}

func (e nextThresholdStatusRequestEvent) String() string {
	return e.t().String()
}

func (e nextThresholdStatusRequestEvent) ComparableStr() string {
	return e.String()
}

type nextThresholdStatusEvent struct {
	// the result of a nextThresholdStatusRequest. Contains two bits of information,
	// capturing four cases:
	// Bottom = false, Proposal = unset/bottom --> received no next value thresholds
	// Bottom = true, Proposal = unset/bottom --> received only a next-vote bottom threshold
	// Bottom = false, Proposal = val --> received a next value threshold
	// Bottom = true, Proposal = val --> received both thresholds.
	// In particular, the first case could occur despite already been in the subsequent period
	// IF we fast forwarded from a soft-vote bundle from the subsequent period.

	Bottom   bool          // true if saw a threshold for bottom
	Proposal proposalValue // set to not bottom if saw threshold for some proposal
}

func (e nextThresholdStatusEvent) t() eventType {
	return nextThresholdStatus
}

func (e nextThresholdStatusEvent) String() string {
	return e.t().String()
}

func (e nextThresholdStatusEvent) ComparableStr() string {
	return e.String()
}

type freshestBundleRequestEvent struct{}

func (e freshestBundleRequestEvent) t() eventType {
	return freshestBundleRequest
}

func (e freshestBundleRequestEvent) String() string {
	return e.t().String()
}

func (e freshestBundleRequestEvent) ComparableStr() string {
	return e.String()
}

type freshestBundleEvent struct {
	// Ok is set if any thresholdEvent was seen
	Ok bool
	// Event holds the freshest thresholdEvent seen by a round machine
	Event thresholdEvent
}

func (e freshestBundleEvent) t() eventType {
	return freshestBundle
}

func (e freshestBundleEvent) String() string {
	return fmt.Sprintf("%s: (%s)", e.t().String(), e.Event.String())
}

func (e freshestBundleEvent) ComparableStr() string {
	return e.String()
}

type dumpVotesRequestEvent struct{}

func (e dumpVotesRequestEvent) t() eventType {
	return dumpVotesRequest
}

func (e dumpVotesRequestEvent) String() string {
	return e.t().String()
}

func (e dumpVotesRequestEvent) ComparableStr() string {
	return e.String()
}

type dumpVotesEvent struct {
	Votes []unauthenticatedVote
}

func (e dumpVotesEvent) t() eventType {
	return dumpVotes
}

func (e dumpVotesEvent) String() string {
	return e.t().String()
}

func (e dumpVotesEvent) ComparableStr() string {
	return e.String()
}

type checkpointEvent struct {
	Round  round
	Period period
	Step   step
	Err    serializableError // the error that was generated while storing the state to disk; nil on success.
	done   chan error        // an output channel to let the pseudonode that we're done processing. We don't want to serialize that, since it's not needed in recovery/autopsy.
}

func (e checkpointEvent) t() eventType {
	return checkpointReached
}

func (e checkpointEvent) String() string {
	return e.t().String()
}

func (e checkpointEvent) ComparableStr() string {
	return e.String()
}

func (e checkpointEvent) ConsensusRound() round {
	return roundZero
}

func (e checkpointEvent) AttachConsensusVersion(v ConsensusVersionView) externalEvent {
	return e
}
