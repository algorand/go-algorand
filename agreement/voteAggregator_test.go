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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testpartitioning"
)

var voteAggregatorTracer tracer

func init() {
	voteAggregatorTracer.log = serviceLogger{logging.Base()}
}

func TestVoteAggregatorVotes(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	player := player{Round: round, Period: period}

	var l listener = checkedListener{listener: new(voteAggregator), listenerContract: voteAggregatorContract{}}

	var router router
	rr := routerFixture
	rr.voteRoot = l
	router = &rr

	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()

	for s := 1; s <= 5; s++ {
		for i := range addresses {
			address := addresses[i]
			step := step(s)
			rv := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
			uv, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
			assert.NoError(t, err)

			vote, err := uv.verify(ledger)
			if err != nil {
				continue
			}

			msg := message{
				Tag:                 protocol.AgreementVoteTag,
				Vote:                vote,
				UnauthenticatedVote: vote.u(),
			}
			eM := messageEvent{T: voteVerified, Input: msg, Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion}}
			e := filterableMessageEvent{messageEvent: eM, FreshnessData: freshnessData{
				PlayerRound:          round,
				PlayerPeriod:         period,
				PlayerStep:           step,
				PlayerLastConcluding: 0,
			}}

			router.dispatch(&voteAggregatorTracer, player, e, playerMachine, voteMachine, round, period, step)
		}
	}
}

func TestVoteAggregatorBundles(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	player := player{Round: round, Period: period}

	var l listener = checkedListener{listener: new(voteAggregator), listenerContract: voteAggregatorContract{}}

	var router router
	rr := routerFixture
	rr.voteRoot = l
	router = &rr

	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()

	var bundles []bundle
	for s := 1; s <= 5; s++ {
		var votes []vote
		for i := range addresses {
			address := addresses[i]
			step := step(s)
			rv := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
			uv, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
			assert.NoError(t, err)

			vote, err := uv.verify(ledger)
			if err != nil {
				continue
			}

			votes = append(votes, vote)
		}

		ub := makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, nil)
		bundle, err := ub.verify(context.Background(), ledger, avv)
		if err != nil {
			panic(err)
		}
		bundles = append(bundles, bundle)
	}

	for _, bundle := range bundles {
		msg := message{
			Tag:                   protocol.VoteBundleTag,
			Bundle:                bundle,
			UnauthenticatedBundle: bundle.u(),
		}
		eM := messageEvent{T: voteVerified, Input: msg, Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion}}
		e := filterableMessageEvent{messageEvent: eM, FreshnessData: freshnessData{
			PlayerRound:          round,
			PlayerPeriod:         period,
			PlayerStep:           0,
			PlayerLastConcluding: 0,
		}}

		router.dispatch(&voteAggregatorTracer, player, e, playerMachine, voteMachine, bundle.U.Round, bundle.U.Period, bundle.U.Step)
	}
}

/* These tests generally look at the composition of voteAggregator and lower vote machines.
 * If we want to test vote aggregator in isolation, some refactoring will have to be done.
 */

func TestVoteAggregatorFiltersVotePresentStale(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(1),
			PlayerPeriod:         period(0),
			PlayerStep:           cert,
			PlayerLastConcluding: 0,
		},
	}
	// generate stale vote, make sure it is rejected
	pV := helper.MakeRandomProposalValue()
	uv := helper.MakeUnauthenticatedVote(t, 0, round(100), period(1), soft, *pV)
	inMsg := msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})
	// fresh vote should not be rejected
	uv = helper.MakeUnauthenticatedVote(t, 1, round(1), period(1), next, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})
	// vote from next round not rejected
	uv = helper.MakeUnauthenticatedVote(t, 1, round(2), period(0), soft, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// duplicate vote rejected
	v := helper.MakeVerifiedVote(t, 1, round(2), period(0), soft, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: voteVerified, // have the vote machine log the vote
		Input: message{
			Vote: v,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})
	uv = helper.MakeUnauthenticatedVote(t, 1, round(2), period(0), soft, *pV)
	inMsg = msgTemplate
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VotePresent not correctly filtered")
}

func TestVoteAggregatorFiltersVoteVerifiedStale(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(1),
			PlayerPeriod:         period(0),
			PlayerStep:           cert,
			PlayerLastConcluding: 0,
		},
	}
	// generate stale vote, make sure it is rejected
	pV := helper.MakeRandomProposalValue()
	uv := helper.MakeVerifiedVote(t, 0, round(100), period(1), soft, *pV)
	inMsg := msgTemplate // copy
	// Err is all nil, should be fine
	inMsg.messageEvent = messageEvent{
		T: voteVerified,
		Input: message{
			Vote: uv,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})
	// fresh vote should not be rejected
	uv = helper.MakeVerifiedVote(t, 1, round(1), period(1), next, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: voteVerified,
		Input: message{
			Vote: uv,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})
	// vote from next round not rejected
	uv = helper.MakeVerifiedVote(t, 1, round(2), period(0), soft, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: voteVerified,
		Input: message{
			Vote: uv,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})
	// malformed vote rejected
	uv = helper.MakeVerifiedVote(t, 1, round(2), period(0), soft, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: voteVerified,
		Input: message{
			Vote: uv,
		},
		Err:   makeSerErrStr("Test Error"),
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteMalformed})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteVerified not correctly filtered")
}

func TestVoteAggregatorFiltersVoteVerifiedThreshold(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(1),
			PlayerPeriod:         period(0),
			PlayerStep:           cert,
			PlayerLastConcluding: 0,
		},
	}
	// generate threshold, make sure we see it
	// (this is based on the composition of machines...)
	pV := helper.MakeRandomProposalValue()
	v := helper.MakeVerifiedVote(t, 0, round(1), period(1), soft, *pV)
	v.Cred = committee.Credential{Weight: soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])}
	inMsg := msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: voteVerified,
		Input: message{
			Vote: v,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, thresholdEvent{T: softThreshold, Proposal: *pV})

	// same threshold for next round should not be emitted
	v = helper.MakeVerifiedVote(t, 0, round(2), period(0), soft, *pV)
	v.Cred = committee.Credential{Weight: soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: voteVerified,
		Input: message{
			Vote: v,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Unexpected threshold event")
}

func TestVoteAggregatorFiltersBundlePresent(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(1001),
			PlayerPeriod:         period(2),
			PlayerStep:           soft,
			PlayerLastConcluding: 0,
		},
	}
	// generate acceptable bundles
	bun := unauthenticatedBundle{
		Round:  round(1001),
		Period: period(2),
	}
	inMsg := msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundlePresent,
		Input: message{
			UnauthenticatedBundle: bun,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// another acceptable bundle from future period
	bun = unauthenticatedBundle{
		Round:  round(1001),
		Period: period(200),
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundlePresent,
		Input: message{
			UnauthenticatedBundle: bun,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// generate bad bundle with r_bundle < r
	bun = unauthenticatedBundle{
		Round:  round(1000),
		Period: period(0),
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundlePresent,
		Input: message{
			UnauthenticatedBundle: bun,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: bundleFiltered})

	// generate bad bundle with r_bundle > r
	bun = unauthenticatedBundle{
		Round:  round(1002),
		Period: period(0),
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundlePresent,
		Input: message{
			UnauthenticatedBundle: bun,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: bundleFiltered})

	// generate bad bundle with p_k + 1 < p
	bun = unauthenticatedBundle{
		Round:  round(1001),
		Period: period(0),
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundlePresent,
		Input: message{
			UnauthenticatedBundle: bun,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: bundleFiltered})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Unexpected bundle filtering")
}

func TestVoteAggregatorFiltersBundleVerifiedThresholdStale(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(2099),
			PlayerPeriod:         period(201),
			PlayerStep:           soft,
			PlayerLastConcluding: 0,
		},
	}
	// generate malformed bundle
	bun := unauthenticatedBundle{
		Round:  round(2099),
		Period: period(201),
	}
	inMsg := msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U: bun,
			},
		},
		Err:   makeSerErrStr("Fake error"),
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: bundleMalformed})

	// generate empty bundle
	bun = unauthenticatedBundle{
		Round:  round(2099),
		Period: period(201),
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U: bun,
			},
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: bundleFiltered})

	// generate acceptable bundles
	// note, as long as err != nil the bundles should be taken
	// to be valid...
	pV := helper.MakeRandomProposalValue()
	r := round(2099)
	p := period(201)
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, *pV)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U:     bun,
				Votes: votes,
			},
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, thresholdEvent{T: certThreshold, Proposal: *pV})

	// another broken bundle from future period with soft vote
	pV = helper.MakeRandomProposalValue()
	r = round(2099)
	p = period(2000)
	votes = make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U:     bun,
				Votes: votes,
			},
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion}}
	// this won't make it through the stack, a soft bundle is not fresher than a cert
	b.AddInOutPair(inMsg, filteredEvent{T: bundleFiltered})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Unexpected verified bundle filtering")
}

func TestVoteAggregatorFiltersBundleVerifiedRelayStale(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(2099),
			PlayerPeriod:         period(201),
			PlayerStep:           soft,
			PlayerLastConcluding: 0,
		},
	}

	// generate acceptable bundles
	// note, as long as err != nil the bundles should be taken
	// to be valid...
	pV := helper.MakeRandomProposalValue()
	r := round(2099)
	p := period(201)
	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pV,
	}
	inMsg := msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U:     bun,
				Votes: votes,
			},
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	b.AddInOutPair(inMsg, thresholdEvent{T: softThreshold, Proposal: *pV})

	// an unacceptable bundle from old period
	pV = helper.MakeRandomProposalValue()
	r = round(2099)
	p = period(198)
	votes = make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U:     bun,
				Votes: votes,
			},
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	// this won't make it through the stack, a soft bundle is not fresher than a cert
	b.AddInOutPair(inMsg, filteredEvent{T: bundleFiltered})

	// an acceptable bundle from same period, with equivocations
	pV = helper.MakeRandomProposalValue()
	r = round(2099)
	p = period(201)
	votes = make([]vote, 1)
	votes[0] = helper.MakeVerifiedVote(t, 0, r, p, cert, *pV)

	equivocationVotes := make([]equivocationVote, 1)
	equivocationVotes[0] = helper.MakeEquivocationVote(t, 1, r, p, cert, cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])-1)
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U:                 bun,
				Votes:             votes,
				EquivocationVotes: equivocationVotes,
			},
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	// this won't make it through the stack, a soft bundle is not fresher than a cert
	b.AddInOutPair(inMsg, thresholdEvent{T: certThreshold, Proposal: *pV})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Unexpected verified bundle filtering")
}

func TestVoteAggregatorFiltersVotePresentPeriod(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	lastConcludingStep := next
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(10),
			PlayerPeriod:         period(10),
			PlayerStep:           next + 5,
			PlayerLastConcluding: lastConcludingStep,
		},
	}
	// generate old next vote in same period, make sure it is rejected
	pV := helper.MakeRandomProposalValue()
	uv := helper.MakeUnauthenticatedVote(t, 0, round(10), period(10), next+3, *pV)
	inMsg := msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// super far away vote, even in same period, should be rejected
	uv = helper.MakeUnauthenticatedVote(t, 1, round(10), period(10), next+7, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// me.next+1 should not be rejected
	uv = helper.MakeUnauthenticatedVote(t, 1, round(10), period(10), next+6, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// relevant next vote from previous period should not be rejected
	uv = helper.MakeUnauthenticatedVote(t, 1, round(10), period(9), lastConcludingStep, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// a vote from subsequent round > period 0.next should be filtered
	// they generally "don't matter"
	uv = helper.MakeUnauthenticatedVote(t, 1, round(11), period(1), soft, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VotePresent not correctly filtered")
}

func TestVoteAggregatorFiltersVoteNextRound(t *testing.T) {
	testpartitioning.PartitionTest(t)

	// Set up a composed test machine
	rRouter := new(rootRouter)
	rRouter.update(player{}, 0, false)
	voteM := &ioAutomataConcrete{
		listener:  rRouter.voteRoot,
		routerCtx: rRouter,
	}
	helper := voteMakerHelper{}
	helper.Setup()
	b := testCaseBuilder{}

	// define a current player state for freshness testing
	lastConcludingStep := next
	msgTemplate := filterableMessageEvent{
		FreshnessData: freshnessData{
			PlayerRound:          round(10),
			PlayerPeriod:         period(10),
			PlayerStep:           next + 5,
			PlayerLastConcluding: lastConcludingStep,
		},
	}
	// generate old next vote in next round, period 0, step 1; make sure it is accepted
	pV := helper.MakeRandomProposalValue()
	uv := helper.MakeUnauthenticatedVote(t, 0, round(11), period(0), soft, *pV)
	inMsg := msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, emptyEvent{})

	// next round, period 0, step > next should be rejected
	uv = helper.MakeUnauthenticatedVote(t, 1, round(11), period(0), next+1, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// next round, period 1 should be rejected
	uv = helper.MakeUnauthenticatedVote(t, 1, round(11), period(1), soft, *pV)
	inMsg = msgTemplate // copy
	inMsg.messageEvent = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: uv,
		},
	}
	b.AddInOutPair(inMsg, filteredEvent{T: voteFiltered})

	// finalize
	res, err := b.Build().Validate(voteM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Votes from next round not correctly filtered")
}

func TestVoteAggregatorOldVote(t *testing.T) {
	testpartitioning.PartitionTest(t)

	cparams := config.Consensus[protocol.ConsensusCurrentVersion]
	maxNumBlocks := 2 * cparams.SeedRefreshInterval * cparams.SeedLookback
	ledger := makeTestLedgerMaxBlocks(readOnlyGenesis100, maxNumBlocks)
	addresses, vrfSecrets, otSecrets := readOnlyAddrs100, readOnlyVRF100, readOnlyOT100
	round := ledger.NextRound()
	period := period(0)

	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()

	var uvs []unauthenticatedVote
	for i := range addresses {
		address := addresses[i]
		step := step(1)
		rv := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
		uv, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
		assert.NoError(t, err)
		uvs = append(uvs, uv)
	}

	for r := 1; r < 1000; r++ {
		ledger.EnsureBlock(makeRandomBlock(ledger.NextRound()), Certificate{})
	}

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()

	results := make(chan asyncVerifyVoteResponse, len(uvs))

	for i, uv := range uvs {
		avv.verifyVote(context.Background(), ledger, uv, i, message{}, results)
		result := <-results
		require.True(t, result.cancelled)
	}
}
