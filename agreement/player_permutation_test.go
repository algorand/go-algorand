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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const r = round(209)
const p = period(0)

func makeRandomProposalPayload(r round) *proposal {
	f := testBlockFactory{Owner: 1}
	ve, _ := f.AssembleBlock(r, time.Now().Add(time.Minute))

	var payload unauthenticatedProposal
	payload.Block = ve.Block()
	payload.SeedProof = randomVRFProof()

	return &proposal{unauthenticatedProposal: payload, ve: ve}
}

var payload = makeRandomProposalPayload(r)
var pV = payload.value()

var verifyError = makeSerErrStr("test error")

func getPlayerPermutation(t *testing.T, n int) (plyr *player, pMachine ioAutomata, helper *voteMakerHelper) {
	switch n {
	case 0: // same round and period as proposal
		return setupP(t, r, p, soft)
	case 1: // one round ahead of proposal
		return setupP(t, r+1, p, soft)
	case 2:
		plyr, pMachine, helper = setupP(t, r-1, p, soft)
		plyr.Pending.push(&messageEvent{
			T:     payloadPresent,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedProposal: payload.u(),
			},
		})
	case 3: // already processed proposal vote
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
	case 4: // already reached soft threshold
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
	case 5: // already reached cert threshold
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
	case 6: // already processed proposal
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

func getMessageEventPermutation(t *testing.T, n int, helper *voteMakerHelper) (e messageEvent) {
	switch n {
	case 0:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:           "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 1:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
		e = messageEvent{
			T: votePresent,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 2:
		vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:           "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 3:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:           "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			TaskIndex: 1,
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 4:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
		e = messageEvent{
			T: votePresent,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedVote: vvote.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 5:
		e = messageEvent{
			T:     payloadPresent,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedProposal: payload.u(),
			},
		}
	case 6:
		e = messageEvent{
			T:     payloadVerified,
			Input: message{
				MessageHandle:           "uniquemessage",
				UnauthenticatedProposal: payload.u(),
				Proposal:                *payload,
			},
		}
	case 7:
		e = messageEvent{
			T:     payloadVerified,
			Input: message{
				UnauthenticatedProposal: payload.u(),
				Proposal:                *payload,
			},
		}
	case 8:
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
	case 9:
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
			T:     bundlePresent,
			Input: message{
				UnauthenticatedBundle: bun,
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 10:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:           "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Err: verifyError,
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 11:
		vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
		e = messageEvent{
			T: voteVerified,
			Input: message{
				MessageHandle:           "uniquemessage",
				Vote:                vvote,
				UnauthenticatedVote: vvote.u(),
			},
			Err: verifyError,
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
	case 12:
		e = messageEvent{
			T:     bundleVerified,
			Input: message{
				Bundle:                bundle{},
				UnauthenticatedBundle: unauthenticatedBundle{},
				MessageHandle:         "uniquemalformedBundle",
			},
			Err:   verifyError,
		}
	case 13:
		e = messageEvent{
			T:     payloadVerified,
			Input: message{
				UnauthenticatedProposal: payload.u(),
				Proposal:                *payload,
			},
			Err: verifyError,
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

func verifyPermutationExpectedActions(t *testing.T, playerN int, eventN int, helper *voteMakerHelper, trace ioTrace) {
	switch playerN {
	case 0:
		switch eventN {
		case 0:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 1:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 2:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 3:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 4:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 5, 6, 7:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposal with no vvote, player: %v, event: %v", playerN, eventN)
		case 8:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ra := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			require.Truef(t, trace.Contains(ev(ra)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			sa := stageDigestAction{Certificate: Certificate(bun)}
			require.Truef(t, trace.Contains(ev(sa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 9:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			//ea := ensureAction{Certificate: Certificate(bun), Payload: *payload}
			//require.Truef(t, trace.Contains(ev(ea)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 10, 11, 12:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case 13:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case 1:
		switch eventN {
		case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore msg from past rounds, player: %v, event: %v", playerN, eventN)
		case 10, 11, 12:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case 13:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case 2:
		switch eventN {
		case 0:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 1:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 2:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore future msg from bad period, player: %v, event: %v", playerN, eventN)
		case 3:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 4:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, propose, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 5, 6, 7:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposal with no vvote, player: %v, event: %v", playerN, eventN)
		case 8, 9:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore bundle from different round, player: %v, event: %v", playerN, eventN)
		case 10, 11, 12:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case 13:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case 3:
		switch eventN {
		case 0:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 1:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 2:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 3, 4:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case 5:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			ca := cryptoAction{T: verifyPayload, M: message{UnauthenticatedProposal: payload.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 6:
			require.Equalf(t, trace.countAction(), 0, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
		case 7:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 8:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ra := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			require.Truef(t, trace.Contains(ev(ra)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			sa := stageDigestAction{Certificate: Certificate(bun)}
			require.Truef(t, trace.Contains(ev(sa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 9:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 10, 11, 12:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case 13:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case 4:
		switch eventN {
		case 0:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 1:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 2:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 3, 4:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case 5:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			ca := cryptoAction{T: verifyPayload, M: message{UnauthenticatedProposal: payload.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 6:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			pa := pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: pV}
			require.Truef(t, trace.Contains(ev(pa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 7:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			pa := pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: pV}
			require.Truef(t, trace.Contains(ev(pa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 8:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ra := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			require.Truef(t, trace.Contains(ev(ra)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			sa := stageDigestAction{Certificate: Certificate(bun)}
			require.Truef(t, trace.Contains(ev(sa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 9:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 10, 11, 12:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case 13:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case 5:
		switch eventN {
		case 0:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 1:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 2:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 3, 4:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case 5:
			require.Equalf(t, trace.countAction(), 2, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			ca := cryptoAction{T: verifyPayload, M: message{UnauthenticatedProposal: payload.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 6:
			require.Equalf(t, trace.countAction(), 3, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			ea := ensureAction{Certificate: Certificate(unauthenticatedBundle{Round: r}), Payload: *payload}
			require.Truef(t, trace.Contains(ev(ea)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			ra := rezeroAction{Round: r+1}
			require.Truef(t, trace.Contains(ev(ra)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			pa := pseudonodeAction{T: assemble, Round: r+1, Period: 0, Step: 0}
			require.Truef(t, trace.Contains(ev(pa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 7:
			require.Equalf(t, trace.countAction(), 4, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			na := networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			ea := ensureAction{Certificate: Certificate(unauthenticatedBundle{Round: r}), Payload: *payload}
			require.Truef(t, trace.Contains(ev(ea)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			ra := rezeroAction{Round: r+1}
			require.Truef(t, trace.Contains(ev(ra)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			pa := pseudonodeAction{T: assemble, Round: r+1, Period: 0, Step: 0}
			require.Truef(t, trace.Contains(ev(pa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 8:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore, already hit thresh, player: %v, event: %v", playerN, eventN)
		case 9:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 10, 11, 12:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case 13:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore malformed proposal, player: %v, event: %v", playerN, eventN)
		default:
			require.Fail(t, "event permutation %v does not exist", eventN)
		}
	case 6:
		switch eventN {
		case 0:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vvote.u()}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 1:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p, soft, pV)
			a := cryptoAction{T: verifyVote, M: message{UnauthenticatedVote: vvote.u()}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 2:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			vvote := helper.MakeVerifiedVote(t, 0, r, p+1, propose, pV)
			a := networkAction{T: broadcast, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u(), Vote: vvote.u()}}
			require.Truef(t, trace.Contains(ev(a)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 3, 4:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposalvvote already received: %v, event: %v", playerN, eventN)
		case 5, 6, 7:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectIgnore(t, trace, "Player should ignore proposal already assembled: %v, event: %v", playerN, eventN)
		case 8:
			require.Equalf(t, trace.countAction(), 4, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			na := networkAction{T: relay, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun}
			require.Truef(t, trace.Contains(ev(na)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			ea := ensureAction{Certificate: Certificate(bun), Payload: *payload}
			require.Truef(t, trace.Contains(ev(ea)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			ra := rezeroAction{Round: r+1}
			require.Truef(t, trace.Contains(ev(ra)), "Player should emit action, player: %v, event: %v", playerN, eventN)
			pa := pseudonodeAction{T: assemble, Round: r+1, Period: 0, Step: 0}
			require.Truef(t, trace.Contains(ev(pa)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 9:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
			for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
				votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, pV)
			}
			bun := unauthenticatedBundle{
				Round:    r,
				Period:   p,
				Proposal: pV,
			}
			ca := cryptoAction{T: verifyBundle, M: message{Bundle: bundle{U: bun, Votes: votes}, UnauthenticatedBundle: bun}, TaskIndex: 0}
			require.Truef(t, trace.Contains(ev(ca)), "Player should emit action, player: %v, event: %v", playerN, eventN)
		case 10, 11, 12:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
			expectDisconnect(t, trace, "Player should disconnect malformed vote/bundle, player: %v, event: %v", playerN, eventN)
		case 13:
			require.Equalf(t, trace.countAction(), 1, "Plyaer should not emit extra actions, player: %v, event: %v", playerN, eventN)
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
