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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
)

func makeRandomProposalPayload(r round) *proposal {
	f := testBlockFactory{Owner: 1}
	ve, _ := f.AssembleBlock(r, time.Time{})

	var payload unauthenticatedProposal
	payload.Block = ve.Block()
	payload.SeedProof = crypto.VRFProof{}

	return &proposal{unauthenticatedProposal: payload, ve: ve}
}

var errTestVerifyFailed = makeSerErrStr("test error")

type playerPermutation int

const (
	playerSameRound = iota
	playerNextRound
	playerPrevRoundPendingPayloadPresent
	playerSameRoundProcessedProposalVote
	playerSameRoundReachedSoftThreshold
	playerSameRoundReachedCertThreshold
	playerSameRoundProcessedProposal
)

func getPlayerPermutation(t *testing.T, n int) (plyr *player, pMachine ioAutomata, helper *voteMakerHelper) {
	const r = round(209)
	const p = period(0)
	var payload = makeRandomProposalPayload(r)
	var pV = payload.value()
	switch n {
	case playerSameRound: // same round and period as proposal
		return setupP(t, r, p, soft)
	case playerNextRound: // one round ahead of proposal
		return setupP(t, r+1, p, soft)
	case playerPrevRoundPendingPayloadPresent:
		plyr, pMachine, helper = setupP(t, r-1, p, soft)
		plyr.Pending.push(&messageEvent{
			T: payloadPresent,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedProposal: payload.u(),
			},
		})
	case playerSameRoundProcessedProposalVote: // already processed proposal vote
		plyr, pMachine, helper = setupP(t, r, p, soft)
		pM := pMachine.(*ioAutomataConcretePlayer)
		pM.update(*plyr, r, true)
		pM.Children[r].ProposalStore.Assemblers = make(map[proposalValue]blockAssembler)
		pM.Children[r].ProposalStore.Assemblers[pV] = blockAssembler{}
		pM.Children[r].update(*plyr, p, true)
		pM.Children[r].Children[p].ProposalTracker.Duplicate = make(map[basics.Address]bool)
		helper.addresses[0] = basics.Address(randomBlockHash())
		pM.Children[r].Children[p].ProposalTracker.Duplicate[helper.addresses[0]] = true
		pM.Children[r].Children[p].ProposalTrackerContract.SawOneVote = true
		pM.Children[r].Children[p].update(0)
	case playerSameRoundReachedSoftThreshold: // already reached soft threshold
		plyr, pMachine, helper = setupP(t, r, p, soft)
		pM := pMachine.(*ioAutomataConcretePlayer)
		pM.update(*plyr, r, true)
		pM.Children[r].ProposalStore.Assemblers = make(map[proposalValue]blockAssembler)
		pM.Children[r].ProposalStore.Assemblers[pV] = blockAssembler{}
		pM.Children[r].update(*plyr, p, true)
		pM.Children[r].Children[p].ProposalTracker.Duplicate = make(map[basics.Address]bool)
		helper.addresses[0] = basics.Address(randomBlockHash())
		pM.Children[r].Children[p].ProposalTracker.Duplicate[helper.addresses[0]] = true
		pM.Children[r].Children[p].ProposalTracker.Staging = pV
		pM.Children[r].Children[p].ProposalTrackerContract.SawOneVote = true
		pM.Children[r].Children[p].update(0)
	case playerSameRoundReachedCertThreshold: // already reached cert threshold
		plyr, pMachine, helper = setupP(t, r, p, soft)
		pM := pMachine.(*ioAutomataConcretePlayer)
		pM.update(*plyr, r, true)
		pM.Children[r].ProposalStore.Assemblers = make(map[proposalValue]blockAssembler)
		pM.Children[r].ProposalStore.Assemblers[pV] = blockAssembler{}
		pM.Children[r].VoteTrackerRound.Freshest = thresholdEvent{T: certThreshold, Proposal: pV, Round: r, Period: p, Bundle: unauthenticatedBundle{Round: r}}
		pM.Children[r].VoteTrackerRound.Ok = true
		pM.Children[r].update(*plyr, p, true)
		pM.Children[r].Children[p].ProposalTracker.Duplicate = make(map[basics.Address]bool)
		helper.addresses[0] = basics.Address(randomBlockHash())
		pM.Children[r].Children[p].ProposalTracker.Duplicate[helper.addresses[0]] = true
		pM.Children[r].Children[p].ProposalTracker.Staging = pV
		pM.Children[r].Children[p].ProposalTrackerContract.SawOneVote = true
		pM.Children[r].Children[p].update(0)
	case playerSameRoundProcessedProposal: // already processed proposal
		plyr, pMachine, helper = setupP(t, r, p, soft)
		pM := pMachine.(*ioAutomataConcretePlayer)
		pM.update(*plyr, r, true)
		pM.Children[r].ProposalStore.Assemblers = make(map[proposalValue]blockAssembler)
		pM.Children[r].ProposalStore.Assemblers[pV] = blockAssembler{Assembled: true, Payload: *payload}
		pM.Children[r].update(*plyr, p, true)
		pM.Children[r].Children[p].ProposalTracker.Duplicate = make(map[basics.Address]bool)
		helper.addresses[0] = basics.Address(randomBlockHash())
		pM.Children[r].Children[p].ProposalTracker.Duplicate[helper.addresses[0]] = true
		pM.Children[r].Children[p].ProposalTrackerContract.SawOneVote = true
		pM.Children[r].Children[p].update(0)
	default:
		require.Fail(t, "player permutation %v does not exist", n)
	}
	return
}

type messageEventPermutation int

const (
	softVoteVerifiedEventSamePeriod = iota
	softVotePresentEventSamePeriod
	proposeVoteVerifiedEventNextPeriod
	proposeVoteVerifiedEventSamePeriod
	proposeVotePresentEventSamePeriod
	payloadPresentEvent
	payloadVerifiedEvent
	payloadVerifiedEventNoMessageHandle
	bundleVerifiedEventSamePeriod
	bundlePresentEventSamePeriod
	softVoteVerifiedErrorEventSamePeriod
	proposeVoteVerifiedErrorEventSamePeriod
	bundleVerifiedErrorEvent
	payloadVerifiedErrorEvent
)

func getMessageEventPermutation(t *testing.T, n int, helper *voteMakerHelper) (e messageEvent) {
	const r = round(209)
	const p = period(0)
	var payload = makeRandomProposalPayload(r)
	var pV = payload.value()
	switch n {
	case softVoteVerifiedEventSamePeriod:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:       "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case softVotePresentEventSamePeriod:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
		e = messageEvent{
			T: votePresent,
			Input: message{
				MessageHandle:       "uniquemessage",
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case proposeVoteVerifiedEventNextPeriod:
		vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:       "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case proposeVoteVerifiedEventSamePeriod:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:       "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			TaskIndex: 1,
			Proto:     ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case proposeVotePresentEventSamePeriod:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
		e = messageEvent{
			T: votePresent,
			Input: message{
				MessageHandle:       "uniquemessage",
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case payloadPresentEvent:
		e = messageEvent{
			T: payloadPresent,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedProposal: payload.u(),
			},
		}
	case payloadVerifiedEvent:
		e = messageEvent{
			T: payloadVerified,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedProposal: payload.u(),
				Proposal:                *payload,
			},
		}
	case payloadVerifiedEventNoMessageHandle:
		e = messageEvent{
			T: payloadVerified,
			Input: message{
				UnauthenticatedProposal: payload.u(),
				Proposal:                *payload,
			},
		}
	case bundleVerifiedEventSamePeriod:
		votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
		for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
			votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
		}
		bun := unauthenticatedBundle{
			Round:    r,
			Period:   p,
			Proposal: pV,
		}
		e = messageEvent{
			T: bundleVerified,
			Input: message{
				Bundle: bundle{
					U:     bun,
					Votes: votes,
				},
				UnauthenticatedBundle: bun,
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case bundlePresentEventSamePeriod:
		votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
		for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
			votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
		}
		bun := unauthenticatedBundle{
			Round:    r,
			Period:   p,
			Proposal: pV,
		}
		e = messageEvent{
			T: bundlePresent,
			Input: message{
				UnauthenticatedBundle: bun,
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case softVoteVerifiedErrorEventSamePeriod:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:       "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Err:   errTestVerifyFailed,
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case proposeVoteVerifiedErrorEventSamePeriod:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:       "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Err:   errTestVerifyFailed,
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case bundleVerifiedErrorEvent:
		e = messageEvent{
			T: bundleVerified,
			Input: message{
				Bundle:                bundle{},
				UnauthenticatedBundle: unauthenticatedBundle{},
				MessageHandle:         "uniquemalformedBundle",
			},
			Err: errTestVerifyFailed,
		}
	case payloadVerifiedErrorEvent:
		e = messageEvent{
			T: payloadVerified,
			Input: message{
				UnauthenticatedProposal: payload.u(),
				Proposal:                *payload,
			},
			Err: errTestVerifyFailed,
		}
	default:
		require.Fail(t, "messageEvent permutation %v does not exist", n)
	}
	return
}

func expectIgnore(t *testing.T, trace ioTrace, errMsg string, playerN int, eventN int) {
	require.Truef(t, trace.ContainsFn(func(b event) bool {
		if b.t() != wrappedAction {
			return false
		}
		wrapper := b.(wrappedActionEvent)
		if wrapper.action.t() != ignore {
			return false
		}
		act := wrapper.action.(networkAction)
		if act.T == ignore && act.Err != nil {
			return true
		}
		return false
	}), errMsg, playerN, eventN)
}

func expectDisconnect(t *testing.T, trace ioTrace, errMsg string, playerN int, eventN int) {
	require.Truef(t, trace.ContainsFn(func(b event) bool {
		if b.t() != wrappedAction {
			return false
		}
		wrapper := b.(wrappedActionEvent)
		if wrapper.action.t() != disconnect {
			return false
		}
		act := wrapper.action.(networkAction)
		if act.T == disconnect && act.Err != nil {
			return true
		}
		return false
	}), errMsg, playerN, eventN)
}

func requireActionCount(t *testing.T, trace ioTrace, expectedCount, playerN, eventN int) {
	require.Equalf(t, trace.countAction(), expectedCount, "Player should not emit extra actions, player: %v, event: %v", playerN, eventN)
}

func requireTraceContains(t *testing.T, trace ioTrace, expected event, playerN, eventN int) {
	require.Truef(t, trace.Contains(expected), "Player should emit action, player: %v, event: %v", playerN, eventN)
}

func verifyPermutationExpectedActions(t *testing.T, playerN int, eventN int, helper *voteMakerHelper, trace ioTrace) {
	const r = round(209)
	const p = period(0)
	var payload = makeRandomProposalPayload(r)
	var pV = payload.value()
	switch playerN {
	case playerSameRound:
		switch eventN {
		case softVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case softVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventNextPeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case payloadPresentEvent, payloadVerifiedEvent, payloadVerifiedEventNoMessageHandle:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposal with no vvote, player: %v, event: %v", playerN, eventN)
		case bundleVerifiedEventSamePeriod:
			requireActionCount(t, trace, 2, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ra := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			requireTraceContains(t, trace, ev(ra), playerN, eventN)
			sa := stageDigestAction{Certificate: Certificate(bun)}
			requireTraceContains(t, trace, ev(sa), playerN, eventN)
		case bundlePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
		case softVoteVerifiedErrorEventSamePeriod, proposeVoteVerifiedErrorEventSamePeriod, bundleVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case payloadVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case playerNextRound:
		switch eventN {
		case softVoteVerifiedEventSamePeriod, softVotePresentEventSamePeriod, proposeVoteVerifiedEventNextPeriod, proposeVoteVerifiedEventSamePeriod, proposeVotePresentEventSamePeriod, payloadPresentEvent, payloadVerifiedEvent, payloadVerifiedEventNoMessageHandle, bundleVerifiedEventSamePeriod, bundlePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore msg from past rounds, player: %v, event: %v", playerN, eventN)
		case softVoteVerifiedErrorEventSamePeriod, proposeVoteVerifiedErrorEventSamePeriod, bundleVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case payloadVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case playerPrevRoundPendingPayloadPresent:
		switch eventN {
		case softVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case softVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventNextPeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore future msg from bad period, player: %v, event: %v", playerN, eventN)
		case proposeVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 2, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
		case proposeVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case payloadPresentEvent, payloadVerifiedEvent, payloadVerifiedEventNoMessageHandle:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposal with no vvote, player: %v, event: %v", playerN, eventN)
		case bundleVerifiedEventSamePeriod, bundlePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore bundle from different round, player: %v, event: %v", playerN, eventN)
		case softVoteVerifiedErrorEventSamePeriod, proposeVoteVerifiedErrorEventSamePeriod, bundleVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case payloadVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case playerSameRoundProcessedProposalVote:
		switch eventN {
		case softVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case softVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventNextPeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventSamePeriod, proposeVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case payloadPresentEvent:
			requireActionCount(t, trace, 2, playerN, eventN)
			ca := cryptoAction{T: verifyPayload, M: message{UnauthenticatedProposal: payload.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
		case payloadVerifiedEvent:
			requireActionCount(t, trace, 0, playerN, eventN)
		case payloadVerifiedEventNoMessageHandle:
			requireActionCount(t, trace, 1, playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
		case bundleVerifiedEventSamePeriod:
			requireActionCount(t, trace, 2, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ra := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			requireTraceContains(t, trace, ev(ra), playerN, eventN)
			sa := stageDigestAction{Certificate: Certificate(bun)}
			requireTraceContains(t, trace, ev(sa), playerN, eventN)
		case bundlePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
		case softVoteVerifiedErrorEventSamePeriod, proposeVoteVerifiedErrorEventSamePeriod, bundleVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case payloadVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)

		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case playerSameRoundReachedSoftThreshold:
		switch eventN {
		case softVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case softVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventNextPeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventSamePeriod, proposeVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case payloadPresentEvent:
			requireActionCount(t, trace, 2, playerN, eventN)
			ca := cryptoAction{T: verifyPayload, M: message{UnauthenticatedProposal: payload.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
		case payloadVerifiedEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			pa := pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: pV}
			requireTraceContains(t, trace, ev(pa), playerN, eventN)
		case payloadVerifiedEventNoMessageHandle:
			requireActionCount(t, trace, 2, playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
			pa := pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: pV}
			requireTraceContains(t, trace, ev(pa), playerN, eventN)
		case bundleVerifiedEventSamePeriod:
			requireActionCount(t, trace, 2, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ra := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			requireTraceContains(t, trace, ev(ra), playerN, eventN)
			sa := stageDigestAction{Certificate: Certificate(bun)}
			requireTraceContains(t, trace, ev(sa), playerN, eventN)
		case bundlePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
		case softVoteVerifiedErrorEventSamePeriod, proposeVoteVerifiedErrorEventSamePeriod, bundleVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case payloadVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)

		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case playerSameRoundReachedCertThreshold:
		switch eventN {
		case softVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case softVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventNextPeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventSamePeriod, proposeVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case payloadPresentEvent:
			requireActionCount(t, trace, 2, playerN, eventN)
			ca := cryptoAction{T: verifyPayload, M: message{UnauthenticatedProposal: payload.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
		case payloadVerifiedEvent:
			requireActionCount(t, trace, 3, playerN, eventN)
			ea := ensureAction{Certificate: Certificate(unauthenticatedBundle{Round: r}), Payload: *payload}
			requireTraceContains(t, trace, ev(ea), playerN, eventN)
			ra := rezeroAction{Round: r + 1}
			requireTraceContains(t, trace, ev(ra), playerN, eventN)
			pa := pseudonodeAction{T: assemble, Round: r + 1, Period: 0, Step: 0}
			requireTraceContains(t, trace, ev(pa), playerN, eventN)
		case payloadVerifiedEventNoMessageHandle:
			requireActionCount(t, trace, 4, playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
			ea := ensureAction{Certificate: Certificate(unauthenticatedBundle{Round: r}), Payload: *payload}
			requireTraceContains(t, trace, ev(ea), playerN, eventN)
			ra := rezeroAction{Round: r + 1}
			requireTraceContains(t, trace, ev(ra), playerN, eventN)
			pa := pseudonodeAction{T: assemble, Round: r + 1, Period: 0, Step: 0}
			requireTraceContains(t, trace, ev(pa), playerN, eventN)
		case bundleVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore, already hit thresh, player: %v, event: %v", playerN, eventN)
		case bundlePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
		case softVoteVerifiedErrorEventSamePeriod, proposeVoteVerifiedErrorEventSamePeriod, bundleVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case payloadVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)

		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case playerSameRoundProcessedProposal:
		switch eventN {
		case softVoteVerifiedEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case softVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventNextPeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: broadcast, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u(), Vote: vvote.u()}}
			requireTraceContains(t, trace, ev(a), playerN, eventN)
		case proposeVoteVerifiedEventSamePeriod, proposeVotePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case payloadPresentEvent, payloadVerifiedEvent, payloadVerifiedEventNoMessageHandle:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposal already assembled: %v, event: %v", playerN, eventN)
		case bundleVerifiedEventSamePeriod:
			requireActionCount(t, trace, 4, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			na := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			requireTraceContains(t, trace, ev(na), playerN, eventN)
			ea := ensureAction{Certificate: Certificate(bun), Payload: *payload}
			requireTraceContains(t, trace, ev(ea), playerN, eventN)
			ra := rezeroAction{Round: r + 1}
			requireTraceContains(t, trace, ev(ra), playerN, eventN)
			pa := pseudonodeAction{T: assemble, Round: r + 1, Period: 0, Step: 0}
			requireTraceContains(t, trace, ev(pa), playerN, eventN)
		case bundlePresentEventSamePeriod:
			requireActionCount(t, trace, 1, playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{Round: r, Period: p, Proposal: pV}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			requireTraceContains(t, trace, ev(ca), playerN, eventN)
		case softVoteVerifiedErrorEventSamePeriod, proposeVoteVerifiedErrorEventSamePeriod, bundleVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case payloadVerifiedErrorEvent:
			requireActionCount(t, trace, 1, playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)

		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	default:
		require.Fail(t, "player permutation %v does not exist", playerN)
	}
	return
}

// Generates a set of player states, router states, and messageEvents and tests all permutations of them
func TestPlayerPermutation(t *testing.T) {
   testPartitioning.PartitionTest(t)

	for i := 0; i < 7; i++ {
		for j := 0; j < 14; j++ {
			_, pMachine, helper := getPlayerPermutation(t, i)
			inMsg := getMessageEventPermutation(t, j, helper)
			err, panicErr := pMachine.transition(inMsg)
			fmt.Println(pMachine.getTrace().events)
			fmt.Println("")
			require.NoErrorf(t, err, "player: %v, event: %v", i, j)
			require.NoErrorf(t, panicErr, "player: %v, event: %v", i, j)

			verifyPermutationExpectedActions(t, i, j, helper, pMachine.getTrace())
		}
	}
}
