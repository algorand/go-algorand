// Copyright (C) 2019-2024 Algorand, Inc.
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
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var playerTracer tracer

func init() {
	playerTracer.log = serviceLogger{logging.Base()}
}

func makeTimeoutEvent() timeoutEvent {
	return timeoutEvent{T: timeout, RandomEntropy: crypto.RandUint64(), Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion}}
}

func generateProposalEvents(t *testing.T, player player, accs testAccountData, f testBlockFactory, ledger Ledger) (voteBatch []event, payloadBatch []event, lowestProposal proposalValue) {
	payloads, votes := makeProposalsTesting(accs, player.Round, player.Period, f, ledger)
	if len(votes) == 0 {
		return
	}

	for i := range votes {
		vote := votes[i]
		msg := message{Tag: protocol.AgreementVoteTag, Vote: vote, UnauthenticatedVote: vote.u()}
		e := messageEvent{T: voteVerified, Input: msg, Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion}}
		voteBatch = append(voteBatch, e)

		payload := payloads[i]
		msg = message{Tag: protocol.ProposalPayloadTag, Proposal: payload, UnauthenticatedProposal: payload.u()}
		e = messageEvent{T: payloadVerified, Input: msg, Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion}}
		payloadBatch = append(payloadBatch, e)
	}

	lowestCredential := votes[0].Cred
	lowestProposal = votes[0].R.Proposal
	for _, vote := range votes {
		if vote.Cred.Less(lowestCredential) {
			lowestCredential = vote.Cred
			lowestProposal = vote.R.Proposal
		}
	}

	return
}

func generateVoteEvents(t *testing.T, player player, step step, accs testAccountData, proposal proposalValue, ledger Ledger) (batch []event) {
	votes := makeVotesTesting(accs, player.Round, player.Period, step, proposal, ledger)
	for i := range votes {
		vote := votes[i]
		msg := message{Tag: protocol.AgreementVoteTag, Vote: vote, UnauthenticatedVote: vote.u()}
		e := messageEvent{T: voteVerified, Input: msg, Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion}}
		batch = append(batch, e)
	}
	return batch
}

func simulateProposalVotes(t *testing.T, router *rootRouter, player *player, batch []event) {
	for _, e := range batch {
		*player, _ = router.submitTop(&playerTracer, *player, e)
	}
}

func (prop proposalValue) matches(dig, encdig crypto.Digest) error {
	if prop.BlockDigest != dig {
		return fmt.Errorf("proposal block digest mismatches payload: %v != %v", prop.BlockDigest, dig)
	}
	if prop.EncodingDigest != encdig {
		return fmt.Errorf("proposal encoding digest mismatches payload: %v != %v", prop.EncodingDigest, encdig)
	}
	return nil
}

func simulateProposalPayloads(t *testing.T, router *rootRouter, player *player, expected proposalValue, batch []event) {
	for _, e := range batch {
		var res []action
		*player, res = router.submitTop(&playerTracer, *player, e)
		for _, a := range res {
			if a.t() != relay {
				continue
			}
			received := e.(messageEvent).Input.Proposal
			err := expected.matches(received.Digest(), crypto.HashObj(received))
			if expected != bottom && err != nil {
				panic("wrong payload relayed")
			}
		}
	}
}

func simulateProposals(t *testing.T, router *rootRouter, player *player, voteBatch []event, payloadBatch []event) {
	for i, e := range voteBatch {
		var res []action
		*player, res = router.submitTop(&playerTracer, *player, e)

		earlier := res
		*player, res = router.submitTop(&playerTracer, *player, payloadBatch[i])
		if len(res) != len(earlier) {
			panic("proposal action mismatch")
		}
		for i := range res {
			if res[i].t() != earlier[i].t() {
				panic("proposal action mismatch")
			}
		}
	}
}

func simulateTimeoutExpectSoft(t *testing.T, router *rootRouter, player *player, expected proposalValue) {
	var res []action
	e := makeTimeoutEvent()
	*player, res = router.submitTop(&playerTracer, *player, e)
	if len(res) != 1 {
		panic("wrong number of actions")
	}

	a1x := res[0]
	if a1x.t() != attest {
		panic("action 1 is not attest")
	}

	a1 := a1x.(pseudonodeAction)
	if a1.Proposal != expected {
		panic("bad soft vote")
	}
	if a1.Step != soft {
		panic("bad soft step")
	}

	if player.Napping {
		panic("player is napping")
	}
}

// TODO this should check that player.Deadline is set correctly
func simulateTimeoutExpectAlarm(t *testing.T, router *rootRouter, player *player) {
	var res []action
	e := makeTimeoutEvent()
	*player, res = router.submitTop(&playerTracer, *player, e)

	for _, a := range res {
		if a.t() == noop {
			continue
		}
		panic("got some non-noop action")
	}
	if player.Napping {
		panic("player is napping")
	}
}

func simulateTimeoutExpectNext(t *testing.T, router *rootRouter, player *player, expected proposalValue, step step) {
	var res []action
	e := makeTimeoutEvent()
	*player, res = router.submitTop(&playerTracer, *player, e)

	if len(res) != 1 {
		panic("wrong number of actions")
	}

	a1x := res[0]
	if a1x.t() != attest {
		panic("action 1 is not attest")
	}

	a1 := a1x.(pseudonodeAction)
	if a1.Proposal != expected {
		panic("bad next vote")
	}
	if a1.Step != step {
		panic("bad next step")
	}

	if player.Napping {
		panic("player is napping")
	}
}

func simulateTimeoutExpectNextPartitioned(t *testing.T, router *rootRouter, player *player, expected proposalValue, step step) {
	var res []action
	e := makeTimeoutEvent()
	*player, res = router.submitTop(&playerTracer, *player, e)

	if len(res) != 2 && len(res) != 3 {
		panic("wrong number of actions not in [2, 3]")
	}

	a0x, a1x := res[0], res[1]
	if len(res) == 3 {
		a1x = res[2]

		abx := res[1]
		if abx.t() != broadcast {
			panic("action 1.5 is not broadcast")
		}

		ab := abx.(networkAction)
		if ab.Tag != protocol.ProposalPayloadTag {
			panic("action 1 has no proposal payload tag")
		}
		// TODO check payload matches bundle value
	}

	if a0x.t() != broadcast {
		panic("action 1 is not broadcast")
	}
	if a1x.t() != attest {
		panic("action 2 is not attest")
	}

	a0 := a0x.(networkAction)
	if a0.Tag != protocol.VoteBundleTag {
		panic("action 1 has no vote bundle tag")
	}
	ub := a0.UnauthenticatedBundle
	if ub.Proposal != expected {
		panic("bad bundle proposal")
	}

	a1 := a1x.(pseudonodeAction)
	if a1.Proposal != expected {
		panic("bad next vote")
	}
	if a1.Step != step {
		panic("bad next step")
	}

	if player.Napping {
		panic("player is napping")
	}
}

func simulateTimeoutExpectNextNap(t *testing.T, router *rootRouter, player *player, expected proposalValue, step step) {
	var res []action
	e := makeTimeoutEvent()
	*player, res = router.submitTop(&playerTracer, *player, e)
	if len(res) != 0 {
		panic("some event emitted")
	}
	if !player.Napping {
		panic("player is not napping")
	}
}

func simulateSoftExpectAttest(t *testing.T, router *rootRouter, player *player, expected proposalValue, batch []event) {
	var softActions []action
	for _, e := range batch {
		var res []action
		*player, res = router.submitTop(&playerTracer, *player, e)
		softActions = append(softActions, res...)
	}

	attestsSent := 0
	for _, a := range softActions {
		if a.t() == attest {
			a := a.(pseudonodeAction)
			attestsSent++
			if a.Proposal != expected {
				panic("bad cert vote")
			}
			if a.Step != cert {
				panic("not cert step")
			}
		}
	}
	if attestsSent == 0 {
		panic("no attestations sent")
	}
	if attestsSent > 1 {
		panic("sent too many attestations")
	}
}

func simulateSoftExpectNoAttest(t *testing.T, router *rootRouter, player *player, batch []event) {
	var softActions []action
	for _, e := range batch {
		var res []action
		*player, res = router.submitTop(&playerTracer, *player, e)
		softActions = append(softActions, res...)
	}

	for _, a := range softActions {
		if a.t() == attest {
			panic("attestation sent")
		}
	}
}

func simulateCertExpectEnsureAssemble(t *testing.T, router *rootRouter, player *player, expected proposalValue, batch []event) (act ensureAction) {
	var certActions []action
	for _, e := range batch {
		var res []action
		*player, res = router.submitTop(&playerTracer, *player, e)
		certActions = append(certActions, res...)
	}

	ensuresSent := 0
	assemblesSent := 0
	assembleAfter := false
	for _, a := range certActions {
		if a.t() == ensure {
			act = a.(ensureAction)
			ensuresSent++
			if act.Certificate.Proposal != expected {
				panic("bad ensure certificate")
			}
			if act.Payload.Digest() != expected.BlockDigest {
				panic("bad ensure digest")
			}
		} else if a.t() == assemble {
			assemblesSent++
			if ensuresSent == 1 {
				assembleAfter = true
			}
		}
	}
	if ensuresSent == 0 {
		panic("no ensures sent")
	}
	if ensuresSent > 1 {
		panic("sent too many ensures")
	}
	if assemblesSent == 0 {
		panic("no assembles sent")
	}
	if assemblesSent > 1 {
		panic("sent too many assembles")
	}
	if !assembleAfter {
		panic("assemble not after ensure")
	}

	return act
}

func simulateNextExpectRecover(t *testing.T, router *rootRouter, player *player, expected proposalValue, batch []event) {
	var certActions []action
	for _, e := range batch {
		var res []action
		*player, res = router.submitTop(&playerTracer, *player, e)
		certActions = append(certActions, res...)
	}

	assemblesSent := 0
	for _, a := range certActions {
		if a.t() == assemble {
			assemblesSent++
		}
	}
	if assemblesSent == 0 {
		panic("no assembles sent")
	}
	if assemblesSent > 1 {
		panic("sent too many assembles")
	}
}

func simulateSingleSynchronousRound(t *testing.T, router *rootRouter, player *player, accs testAccountData, f testBlockFactory, ledger Ledger) {
	proposalVoteEventBatch, proposalPayloadEventBatch, lowestProposal := generateProposalEvents(t, *player, accs, f, ledger)
	softEventBatch := generateVoteEvents(t, *player, soft, accs, lowestProposal, ledger)
	certEventBatch := generateVoteEvents(t, *player, cert, accs, lowestProposal, ledger)

	simulateProposals(t, router, player, proposalVoteEventBatch, proposalPayloadEventBatch)
	simulateTimeoutExpectSoft(t, router, player, lowestProposal)
	simulateSoftExpectAttest(t, router, player, lowestProposal, softEventBatch)

	act := simulateCertExpectEnsureAssemble(t, router, player, lowestProposal, certEventBatch)
	ledger.EnsureBlock(act.Payload.Block, act.Certificate)
}

func simulateSynchronousRoundRecovery(t *testing.T, router *rootRouter, player *player, accs testAccountData, f testBlockFactory, ledger Ledger) {
	nextEventBatch := generateVoteEvents(t, *player, next, accs, bottom, ledger)

	simulateNextExpectRecover(t, router, player, bottom, nextEventBatch)

	proposalVoteEventBatch, proposalPayloadEventBatch, lowestProposal := generateProposalEvents(t, *player, accs, f, ledger)
	softEventBatch := generateVoteEvents(t, *player, soft, accs, lowestProposal, ledger)
	certEventBatch := generateVoteEvents(t, *player, cert, accs, lowestProposal, ledger)

	simulateProposals(t, router, player, proposalVoteEventBatch, proposalPayloadEventBatch)
	simulateTimeoutExpectSoft(t, router, player, lowestProposal)
	simulateSoftExpectAttest(t, router, player, lowestProposal, softEventBatch)

	act := simulateCertExpectEnsureAssemble(t, router, player, lowestProposal, certEventBatch)
	ledger.EnsureBlock(act.Payload.Block, act.Certificate)
}

func testPlayerSetup() (player, rootRouter, testAccountData, testBlockFactory, Ledger) {
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture10()
	accs := testAccountData{addresses: addresses, vrfs: vrfSecrets, ots: otSecrets}
	round := ledger.NextRound()
	period := period(0)
	historyBuffer := makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)
	player := player{Round: round, Period: period, Step: soft, lowestCredentialArrivals: historyBuffer}

	var p actor = ioLoggedActor{checkedActor{actor: &player, actorContract: playerContract{}}, playerTracer}
	router := routerFixture
	router.root = p
	f := testBlockFactory{Owner: 1} // TODO this should change with given address

	return player, router, accs, f, ledger
}

func TestPlayerSynchronous(t *testing.T) {
	partitiontest.PartitionTest(t)

	player, router, accs, f, ledger := testPlayerSetup()

	for i := 0; i < 20; i++ {
		simulateSingleSynchronousRound(t, &router, &player, accs, f, ledger)
	}
}

func TestPlayerOffsetStart(t *testing.T) {
	partitiontest.PartitionTest(t)

	player, router, accs, f, ledger := testPlayerSetup()

	simulateTimeoutExpectAlarm(t, &router, &player)
	simulateTimeoutExpectNext(t, &router, &player, bottom, next)

	for i := step(1); i < 10; i++ {
		simulateTimeoutExpectNextNap(t, &router, &player, bottom, next+i)
		simulateTimeoutExpectNext(t, &router, &player, bottom, next+i)
	}

	simulateSynchronousRoundRecovery(t, &router, &player, accs, f, ledger)

	for i := 0; i < 5; i++ {
		simulateSingleSynchronousRound(t, &router, &player, accs, f, ledger)
	}
}

func TestPlayerLateBlockProposalPeriod0(t *testing.T) {
	partitiontest.PartitionTest(t)

	player, router, accs, f, ledger := testPlayerSetup()

	proposalVoteEventBatch, proposalPayloadEventBatch, lowestProposal := generateProposalEvents(t, player, accs, f, ledger)
	softEventBatch := generateVoteEvents(t, player, soft, accs, lowestProposal, ledger)
	certEventBatch := generateVoteEvents(t, player, cert, accs, lowestProposal, ledger)

	simulateProposalVotes(t, &router, &player, proposalVoteEventBatch)
	simulateTimeoutExpectSoft(t, &router, &player, lowestProposal)
	simulateSoftExpectNoAttest(t, &router, &player, softEventBatch)
	simulateTimeoutExpectNext(t, &router, &player, bottom, next)

	simulateProposalPayloads(t, &router, &player, lowestProposal, proposalPayloadEventBatch)

	for i := step(1); i < 10; i++ {
		simulateTimeoutExpectNextNap(t, &router, &player, lowestProposal, next+i)
		if !player.partitioned() {
			simulateTimeoutExpectNext(t, &router, &player, lowestProposal, next+i)
		} else {
			simulateTimeoutExpectNextPartitioned(t, &router, &player, lowestProposal, next+i)
		}
	}

	act := simulateCertExpectEnsureAssemble(t, &router, &player, lowestProposal, certEventBatch)
	ledger.EnsureBlock(act.Payload.Block, act.Certificate)

	for i := 0; i < 5; i++ {
		simulateSingleSynchronousRound(t, &router, &player, accs, f, ledger)
	}
}

/*
 * Automata-style trace based integration tests.
 * ---------------------------------------------
 * There is significant overlap with the tests above, but that's ok.
 * TODO use bundle creation logic in common_test.go
 */

/* White box tests that make sure player enters the right state */

func setupP(t *testing.T, r round, p period, s step) (plyr *player, pMachine ioAutomata, helper *voteMakerHelper) {
	// Set up a composed test machine starting at specified rps
	history := makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)
	rRouter := makeRootRouter(player{Round: r, Period: p, Step: s, Deadline: Deadline{Duration: FilterTimeout(p, protocol.ConsensusCurrentVersion), Type: TimeoutFilter}, lowestCredentialArrivals: history})
	concreteMachine := ioAutomataConcretePlayer{rootRouter: &rRouter}
	plyr = concreteMachine.underlying()
	plyr.lowestCredentialArrivals = makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)
	pMachine = &concreteMachine
	helper = &voteMakerHelper{}
	helper.Setup()
	// return plyr so we can inspect its state in white box manner
	return
}

// ISV = Issue Soft Vote
func TestPlayerISVDoesNotSoftVoteBottom(t *testing.T) {
	partitiontest.PartitionTest(t)

	// every soft vote is associated with a proposalValue != bottom.
	const r = round(209)
	const p = period(1)
	_, pM, helper := setupP(t, r, p, soft)

	pV := &bottom

	vv := helper.MakeVerifiedVote(t, 0, r, p, soft, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	softVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: soft, Proposal: *pV})
	require.Falsef(t, pM.getTrace().Contains(softVoteEvent), "Player should not issue soft vote")
}

func TestPlayerISVVoteForStartingValue(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if we see a next value quorum, and no next bottom quorum, vote for that value regardless
	// every soft vote is associated with a proposalValue != bottom.
	const r = round(209)
	const p = period(11)
	_, pM, helper := setupP(t, r, p, soft)

	pV := helper.MakeRandomProposalValue()
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Step:     next,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, trigger soft vote timeout
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	softVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: soft, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(softVoteEvent), "Player should issue soft vote")
}

func TestPlayerISVVoteNoVoteSansProposal(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if we see no proposal, even if we see a next-value bottom quorum, do not issue a soft vote

	const r = round(209)
	const p = period(11)
	_, pM, helper := setupP(t, r, p, soft)

	pV := &bottom
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Step:     next,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, trigger soft vote timeout
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Falsef(t, pM.getTrace().ContainsFn(func(b event) bool {
		switch b.t() {
		case wrappedAction:
			e := b.(wrappedActionEvent)
			if e.action.t() == attest {
				return true
			}
		}
		return false
	}), "Player should not issue any vote, especially soft vote")
}

func TestPlayerISVVoteForReProposal(t *testing.T) {
	partitiontest.PartitionTest(t)

	// even if we saw bottom, if we see reproposal, and a next value quorum, vote for it
	// why do reproposals need to be associated with next value quorums? (instead of just a next
	// bottom quorum) - seems to be important for seed biasing
	const r = round(209)
	const p = period(11)
	_, pM, helper := setupP(t, r, p, soft)

	pV := &bottom
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Step:     next,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now feed value quorum
	pV = helper.MakeRandomProposalValue()
	votes = make([]vote, int((next + 1).threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int((next + 1).threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next+1, *pV)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Step:     (next + 1),
		Proposal: *pV,
	}

	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now feed reproposal

	vv := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, trigger soft vote timeout
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	softVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: soft, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(softVoteEvent), "Player should issue soft vote")
}

func TestPlayerISVNoVoteForUnsupportedReProposal(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if there's no next value quorum, don't support the reproposal
	const r = round(209)
	const p = period(11)
	_, pM, helper := setupP(t, r, p, soft)

	// feed bottom quorum, this is how the machine got into this period
	pV := &bottom
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Step:     next,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now feed reproposal
	vv := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, trigger soft vote timeout
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	softVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: soft, Proposal: *pV})
	require.Falsef(t, pM.getTrace().Contains(softVoteEvent), "Player should not issue soft vote without corresponding next threshold")
}

// ICV = Issue Cert Vote
func TestPlayerICVOnSoftThresholdSamePeriod(t *testing.T) {
	partitiontest.PartitionTest(t)

	// basic cert vote check.
	// This also tests cert vote even if freeze timer has not yet fired
	const r = round(12)
	const p = period(1)
	_, pM, helper := setupP(t, r, p, soft)

	payload, pV := helper.MakeRandomProposalPayload(t, r)

	// now, dispatch a commitable proposal
	//First, send a proposal vote
	//Second, dispatch a payload
	proposalVote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                proposalVote,
			UnauthenticatedVote: proposalVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     soft,
		Proposal: *pV,
	}

	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, check cert vote generated
	certVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(certVoteEvent), "Player should issue cert vote")
	// the semantics of p.Step may be revised; we can cert vote at any time, regardless
	// of step. p.Step is set to cert only after issuing a soft vote. (So it seems that we can,
	// in fact, issue a cert vote, and then a soft vote in the same period).
	//require.Truef(t, pWhite.Step == cert, "Player should move into cert step") // white box
}

func TestPlayerICVOnSoftThresholdPrePayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Check cert voting when soft bundle is received
	// before a proposal payload. Should still generate cert vote.

	// This also tests cert vote even if freeze timer has not yet fired
	const r = round(12)
	const p = period(1)
	_, pM, helper := setupP(t, r, p, soft)

	// feed soft quorum for pV
	payload, pV := helper.MakeRandomProposalPayload(t, r)
	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     soft,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, dispatch a commitable proposal
	//First, send a proposal vote
	//Second, dispatch a payload
	proposalVote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                proposalVote,
			UnauthenticatedVote: proposalVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, check cert vote generated
	certVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(certVoteEvent), "Player should issue cert vote")
}

func TestPlayerICVOnSoftThresholdThenPayloadNoProposalVote(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if there's no proposal vote, a soft threshold should still trigger a cert vote
	const r = round(12)
	const p = period(1)
	_, pM, helper := setupP(t, r, p, soft)

	// feed soft quorum for pV
	payload, pV := helper.MakeRandomProposalPayload(t, r)
	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     soft,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, dispatch a payload with no proposal
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, check cert vote generated
	certVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(certVoteEvent), "Player should issue cert vote")
}

func TestPlayerICVNoVoteForUncommittableProposal(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(12)
	const p = period(1)
	pWhite, pM, helper := setupP(t, r, p, soft)

	// feed soft quorum for pV
	pV := helper.MakeRandomProposalValue()

	// now, dispatch an uncommitable proposal
	// First, send a proposal vote, without corresponding payload.
	proposalVote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                proposalVote,
			UnauthenticatedVote: proposalVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     soft,
		Proposal: *pV,
	}

	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, check cert vote generated
	certVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: cert, Proposal: *pV})
	require.Falsef(t, pM.getTrace().Contains(certVoteEvent), "Player should not issue cert vote")
	require.Truef(t, pWhite.Step == soft, "Player should not move out of soft step") // white box
}

func TestPlayerICVPanicOnSoftBottomThreshold(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(209)
	const p = period(1)
	_, pM, helper := setupP(t, r, p, 0)
	// make sure a next vote bottom for a future period fast forwards us to that period
	pV := &bottom
	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.Errorf(t, panicErr, "player should never see softThreshold = bottom")
}

// FF = Fast Forwarding
func TestPlayerFFSoftThreshold(t *testing.T) {
	partitiontest.PartitionTest(t)

	// future periods
	const r = round(201221)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	// now, dispatch a commitable proposal
	//First, send a proposal vote
	//Second, dispatch a payload
	pV := helper.MakeRandomProposalValue()
	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+100, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p + 100,
		Step:     soft,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Equalf(t, p+100, pWhite.Period, "player did not fast forward to new period")
}

func TestPlayerFFSoftThresholdWithPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	// future periods
	// must also cert vote
	const r = round(201221)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	// now, dispatch a commitable proposal
	//First, send a proposal vote. Note that proposal votes for periods
	// far in the future will be filtered, along with corresponding payload (if new)
	//Second, dispatch a payload.
	payload, pV := helper.MakeRandomProposalPayload(t, r)
	proposalVote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                proposalVote,
			UnauthenticatedVote: proposalVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// note that payloads are generally round/period agnostic, and cached only if
	// there is a corresponding (filterable) proposalVote or relevant proposal.
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+100, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p + 100,
		Step:     soft,
		Proposal: *pV,
	}

	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, check cert vote generated
	certVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p + 100, Step: cert, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(certVoteEvent), "Player should issue cert vote")
	require.Equalf(t, p+100, pWhite.Period, "player did not fast forward to new period")
}

func TestPlayerFFSoftThresholdLatePayloadCert(t *testing.T) {
	partitiontest.PartitionTest(t)

	// should cert vote after fast forwarding due to soft bundle, if we see late payload
	const r = round(201221)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	payload, pV := helper.MakeRandomProposalPayload(t, r)

	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+100, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p + 100,
		Step:     soft,
		Proposal: *pV,
	}

	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, dispatch a commitable proposal
	//First, send a proposal vote. Note that proposal votes for periods
	// far in the future will be filtered, along with corresponding payload (if new)
	//Second, dispatch a payload.
	proposalVote := helper.MakeVerifiedVote(t, 0, r, p+100, propose, *pV)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote: proposalVote,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// note that payloads are generally round/period agnostic, and cached only if
	// there is a corresponding (filterable) proposalVote or relevant proposal.
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, check cert vote generated
	certVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p + 100, Step: cert, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(certVoteEvent), "Player should issue cert vote")
	require.Equalf(t, p+100, pWhite.Period, "player did not fast forward to new period")
}

func TestPlayerFFNextThresholdBottom(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Set up a composed test machine starting at period 0
	const r = round(209)
	pWhite, pM, helper := setupP(t, r, period(0), soft)

	// make sure a next vote bottom for a future period fast forwards us to that period
	pV := &bottom
	futureP := period(10)
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, futureP, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   futureP,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Equalf(t, futureP+1, pWhite.Period, "player did not fast forward to new period")
}

func TestPlayerFFNextThresholdValue(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Set up a composed test machine starting at period 0
	const r = round(209)
	pWhite, pM, helper := setupP(t, r, period(0), soft)

	// make sure a next vote bottom for a future period fast forwards us to that period
	pV := helper.MakeRandomProposalValue()
	futureP := period(10)
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, futureP, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   futureP,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Equalf(t, futureP+1, pWhite.Period, "player did not fast forward to new period")
}

func TestPlayerDoesNotFastForwardOldThresholdEvents(t *testing.T) {
	partitiontest.PartitionTest(t)

	// thresholds/bundles with p_k < p are useless and should not cause any logic
	// (though, in the process of generating the threshold, it should update cached next bundle)
	const r = round(209)
	const p = period(11)
	pWhite, pM, helper := setupP(t, r, p-1, soft)

	pV := helper.MakeRandomProposalValue()
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, p, pWhite.Period, "player did not fast forward to new period")

	// update old cached next bundle
	pV = &bottom
	votes = make([]vote, int((next + 1).threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int((next + 1).threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, (next + 1), *pV)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// allow soft voting for new proposal based on bottom
	pV = helper.MakeRandomProposalValue()
	pV.OriginalPeriod = p // we need to set this to trigger soft vote; else, its a reproposal
	vv := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, trigger soft vote timeout
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	softVoteEvent := ev(pseudonodeAction{T: attest, Round: r, Period: p, Step: soft, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(softVoteEvent), "Player should issue soft vote")
}

// Proposals
// Contract: player should not propose unless it sees valid proof of proposal safety
func TestPlayerProposesBottomBundle(t *testing.T) {
	partitiontest.PartitionTest(t)

	// sanity check that player actually proposes something
	// player should create a new proposal
	const r = round(209)
	const p = period(11)
	pWhite, pM, helper := setupP(t, r, p-1, soft)

	// gen bottom bundle to fast forward into period 11
	pV := &bottom
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, p, pWhite.Period, "player did not fast forward to new period")
	assembleEvent := ev(pseudonodeAction{T: assemble, Round: r, Period: p})
	require.Truef(t, pM.getTrace().Contains(assembleEvent), "Player should try to assemble new proposal")
}

func TestPlayerProposesNewRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	// player should create a new proposal on new round
	const r = round(209)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// send a payload
	// store an arbitrary proposal/payload
	vVote := helper.MakeVerifiedVote(t, 0, r-1, p, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *pP,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// gen cert to move into the next round
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r-1, p, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r - 1,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r, pWhite.Round, "player did not enter new round")
	require.Equalf(t, period(0), pWhite.Period, "player did not enter period 0 in new round")
	assembleEvent := ev(pseudonodeAction{T: assemble, Round: r, Period: 0})
	require.Truef(t, pM.getTrace().Contains(assembleEvent), "Player should try to assemble new proposal")
}

func TestPlayerCertificateThenPayloadEntersNewRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	// player should create a new proposal on new round
	const r = round(209)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// gen cert; this should not advance into next round
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r-1, p, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r - 1,
		Period:   p,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r-1, pWhite.Round, "player entered new round but shouldn't have without payload")
	assembleEvent := ev(pseudonodeAction{T: assemble, Round: r, Period: 0})
	require.Falsef(t, pM.getTrace().Contains(assembleEvent), "Player should not try to assemble new proposal without new round")

	// send a payload corresponding with previous cert. now we should enter new round
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *pP,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r, pWhite.Round, "player did not enter new round")
	require.Equalf(t, period(0), pWhite.Period, "player did not enter period 0 in new round")
	require.Truef(t, pM.getTrace().Contains(assembleEvent), "Player should try to assemble new proposal")
}

func TestPlayerReproposesNextValueBundleWithoutPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Even having not seen the payload, player should still repropose
	const r = round(209)
	const p = period(11)
	pWhite, pM, helper := setupP(t, r, p-1, soft)
	pV := helper.MakeRandomProposalValue()

	// gen next value bundle to fast forward into period 11
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check player fast-forwarded, rezeros, reproposed, relays next-value bundle
	require.Equalf(t, p, pWhite.Period, "player did not fast forward to new period")
	zeroEvent := ev(rezeroAction{Round: r})
	require.Truef(t, pM.getTrace().Contains(zeroEvent), "Player should reset clock")
	reproposeEvent := ev(pseudonodeAction{T: repropose, Round: r, Period: p, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(reproposeEvent), "Player should repropose from next-value quorum")
	relayEvent := ev(networkAction{T: broadcast, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun})
	require.Truef(t, pM.getTrace().Contains(relayEvent), "Player should relay freshest bundle = next value bundle")
}

func TestPlayerReproposesNextValueBundleRelaysPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	// player should forward the proposal payload, forwad freshest bundle, and broadcast a reproposal vote.
	// which comes from the previous period. (has period set to p - 1)
	const r = round(209)
	const p = period(11)
	pWhite, pM, helper := setupP(t, r, p-1, soft)
	payload, pV := helper.MakeRandomProposalPayload(t, r)

	// submit a proposal/payload
	vv := helper.MakeVerifiedVote(t, 0, r, p-1, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// gen next value bundle to fast forward into period 11
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check player fast-forwarded, rezeros, reproposed, relays next-value bundle
	require.Equalf(t, p, pWhite.Period, "player did not fast forward to new period")
	zeroEvent := ev(rezeroAction{Round: r})
	require.Truef(t, pM.getTrace().Contains(zeroEvent), "Player should reset clock")
	reproposeEvent := ev(pseudonodeAction{T: repropose, Round: r, Period: p, Proposal: *pV})
	require.Truef(t, pM.getTrace().Contains(reproposeEvent), "Player should repropose from next-value quorum")
	relayEvent := ev(networkAction{T: broadcast, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun})
	require.Truef(t, pM.getTrace().Contains(relayEvent), "Player should relay freshest bundle = next value bundle")

	// simulate the pseudonode
	vote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg = messageEvent{
		T: votePresent,
		Input: message{
			UnauthenticatedVote: vote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// simulate the cryptoverifier
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vote,
			UnauthenticatedVote: vote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check payload is relayed
	relayPayloadEvent := ev(networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u(), Vote: vote.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay payload on reproposal")
}

// Commitment
func TestPlayerCommitsCertThreshold(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(20239)
	const p = period(1001)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// send a payload
	// store an arbitrary proposal/payload
	vVote := helper.MakeVerifiedVote(t, 0, r-1, p, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *pP,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// gen cert to move into the next round
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r-1, p, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r - 1,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r, pWhite.Round, "player did not enter new round")
	require.Equalf(t, period(0), pWhite.Period, "player did not enter period 0 in new round")
	commitEvent := ev(ensureAction{Certificate: Certificate(bun), Payload: *pP})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should try to ensure block/digest on ledger")
}

// Recovery = Re
const testPartitionPeriod = 3

var testPartitionStep = partitionStep

func TestPlayerRePropagatesFreshestBundle(t *testing.T) {
	partitiontest.PartitionTest(t)

	// let's just fire a bunch of timeouts
	const r = round(20239)
	const p = period(2)
	pWhite, pM, helper := setupP(t, r, p, soft)

	// gen next bundle to move into the next round
	pV := helper.MakeRandomProposalValue()
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, p, pWhite.Period, "player did not enter new period")

	// now, trigger soft vote timeout
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, trigger cert vote timeout; now step = next
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	for i := 3; i < int(testPartitionStep); i++ {
		err, panicErr = pM.transition(makeTimeoutEvent())
		require.NoError(t, err)
		require.NoError(t, panicErr)
		// actually send the next next vote
		err, panicErr = pM.transition(makeTimeoutEvent())
		require.NoError(t, err)
		require.NoError(t, panicErr)
	}

	// check if partitioned (this is hardcoded in implementation?)
	require.Truef(t, pWhite.partitioned(), "player should detect partition but isn't")

	resynchEvent := ev(networkAction{T: broadcast, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun})
	require.Truef(t, pM.getTrace().Contains(resynchEvent), "Player should try to repropagate freshest bundle")
}

func TestPlayerPropagatesProposalPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if a player receives a payload from the network, it should relay it.
	const r = round(209)
	_, pM, helper := setupP(t, r, 0, soft)
	payload, pV := helper.MakeRandomProposalPayload(t, r)

	// store an arbitrary proposal/payload
	vVote := helper.MakeVerifiedVote(t, 0, r, 0, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	m := message{
		messageHandle:           "msghandle",
		UnauthenticatedProposal: payload.u(),
	}
	inMsg = messageEvent{
		T:     payloadPresent,
		Input: m,
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	relayPayloadEvent := ev(networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay payload on reception")
}

func TestPlayerPropagatesOwnProposalPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if a player receives a PayloadVerified event with its own payload, it should relay it.
	const r = round(209)
	_, pM, helper := setupP(t, r, 0, soft)
	payload, pV := helper.MakeRandomProposalPayload(t, r)

	// store an arbitrary proposal/payload
	vVote := helper.MakeVerifiedVote(t, 0, r, 0, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	m := message{
		UnauthenticatedProposal: payload.u(),
		Proposal:                *payload,
	}
	inMsg = messageEvent{
		T:     payloadVerified,
		Input: m,
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	relayPayloadEvent := ev(networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay own payload")
}

func TestPlayerPropagatesProposalPayloadFutureRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if a player receives a proposal payload for a future round, it should still
	// propagate it at some point.
	const r = round(209)
	_, pM, helper := setupP(t, r, 0, soft)
	payload, pV := helper.MakeRandomProposalPayload(t, r+1)

	// store an arbitrary proposal/payload
	vVote := helper.MakeVerifiedVote(t, 0, r+1, 0, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	m := message{
		messageHandle:           "msghandle",
		UnauthenticatedProposal: payload.u(),
	}
	inMsg = messageEvent{
		T:     payloadPresent,
		Input: m,
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// advance to the next round
	msg := roundInterruptionEvent{
		Round: r + 1,
	}
	err, panicErr = pM.transition(msg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	relayPayloadEvent := ev(networkAction{T: relay, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay payload on new round")
}

func TestPlayerRePropagatesProposalPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if player broadcasts a non-bottom freshest bundle during recovery/resynch, broadcast the
	// associated proposal payload. note this is distinct from relaying the payload
	// on seeing a reproposal/proposal vote.
	const r = round(209)
	const p = period(11)
	require.Truef(t, p >= testPartitionPeriod, "test case must force player into partitioned period")
	pWhite, pM, helper := setupP(t, r, p-1, soft)
	payload, pV := helper.MakeRandomProposalPayload(t, r)

	// store an arbitrary proposal/payload
	vVote := helper.MakeVerifiedVote(t, 0, r, p-1, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *payload,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// let's stage the value in period 10, so that we relay the block at the end of period 10
	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, soft, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// gen next value bundle to fast forward into period 11
	votes = make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// check player is partitioned and is attempting to resynch other processes
	require.Truef(t, pWhite.partitioned(), "player should detect partition but isn't")
	relayEvent := ev(networkAction{T: broadcast, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun})
	require.Truef(t, pM.getTrace().Contains(relayEvent), "Player should relay freshest bundle = next value bundle")

	// check payload is relayed due to staging, even if it is not pinned
	relayPayloadEvent := ev(networkAction{T: broadcast, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay payload on resynch")

	// now, let's say someone saw the next value bundle, and they reproposed
	vVote = helper.MakeVerifiedVote(t, 100, r, p, propose, *pV)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// we should attach a relay payload to this proposal
	relayPayloadEvent = ev(networkAction{T: broadcast, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u(), Vote: vVote.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay payload on resynch")

	// now, trigger soft vote timeout
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// now, trigger cert vote timeout; now step = next
	pM.resetTrace()
	err, panicErr = pM.transition(makeTimeoutEvent())
	require.NoError(t, err)
	require.NoError(t, panicErr)
	// check that this next vote contains old pV
	relayPayloadEvent = ev(networkAction{T: broadcast, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay payload on resynch")

	// now, stage a new payload for this same period p.
	payloadNext, pVNext := helper.MakeRandomProposalPayload(t, r)
	votes = make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, soft, *pVNext)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pVNext,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	// Also deliver the payload this period.
	vVote = helper.MakeVerifiedVote(t, 0, r, p, propose, *pVNext)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *payloadNext,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// make sure we relay the new payload (staged has precedence over pinned)
	// now, trigger second next step
	pM.resetTrace()
	err, panicErr = pM.transition(makeTimeoutEvent()) // inject randomness
	require.NoError(t, err)
	require.NoError(t, panicErr)
	err, panicErr = pM.transition(makeTimeoutEvent()) // actually send next + 1 vote
	require.NoError(t, err)
	require.NoError(t, panicErr)
	relayPayloadEvent = ev(networkAction{T: broadcast, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payloadNext.u()}})
	require.Truef(t, pM.getTrace().Contains(relayPayloadEvent), "Player should relay staged payload over pinned payload on resynch")
}

func TestPlayerPropagatesProposalVote(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(209)
	_, pM, helper := setupP(t, r, 0, soft)
	_, pV := helper.MakeRandomProposalPayload(t, r)

	vVote := helper.MakeVerifiedVote(t, 0, r, 0, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	relayVoteEvent := ev(networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vVote.u()})
	require.Truef(t, pM.getTrace().Contains(relayVoteEvent), "Player should relay proposal vote")
}

func TestPlayerPropagatesSoftVote(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(209)
	_, pM, helper := setupP(t, r, 0, soft)
	_, pV := helper.MakeRandomProposalPayload(t, r)

	vVote := helper.MakeVerifiedVote(t, 0, r, 0, soft, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	relayVoteEvent := ev(networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vVote.u()})
	require.Truef(t, pM.getTrace().Contains(relayVoteEvent), "Player should relay soft vote")
}

func TestPlayerPropagatesCertVote(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(209)
	_, pM, helper := setupP(t, r, 0, cert)
	_, pV := helper.MakeRandomProposalPayload(t, r)

	vVote := helper.MakeVerifiedVote(t, 0, r, 0, cert, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	relayVoteEvent := ev(networkAction{T: relay, Tag: protocol.AgreementVoteTag, UnauthenticatedVote: vVote.u()})
	require.Truef(t, pM.getTrace().Contains(relayVoteEvent), "Player should relay cert vote")
}

// Malformed Messages
// check both proposals, proposal payloads, and votes, bundles
func TestPlayerDisconnectsFromMalformedProposalVote(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	_, pM, helper := setupP(t, r, p, cert)

	verifyError := makeSerErrStr("test error")

	// check disconnect on malformed proposal votes
	proposalVote := helper.MakeVerifiedVote(t, 0, r, p, propose, bottom)
	m := message{
		Vote:                proposalVote,
		UnauthenticatedVote: proposalVote.u(),
	}
	inMsg := messageEvent{
		T:     voteVerified,
		Input: m,
		Err:   verifyError,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Truef(t, pM.getTrace().ContainsFn(func(b event) bool {
		if b.t() != wrappedAction {
			return false
		}
		wrapper := b.(wrappedActionEvent)
		if wrapper.action.t() != disconnect {
			return false
		}
		act := wrapper.action.(networkAction)
		if act.T == disconnect && act.h == m.messageHandle && act.Err != nil {
			return true
		}
		return false
	}), "Player should disconnect due to malformed proposal")
}

func TestPlayerIgnoresMalformedPayload(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	_, pM, _ := setupP(t, r, p, cert)

	verifyError := makeSerErrStr("test error")

	// check ignore on malformed payloads
	m := message{
		messageHandle:           "uniquemessage",
		Proposal:                proposal{},
		UnauthenticatedProposal: unauthenticatedProposal{},
	}
	inMsg := messageEvent{
		T:     payloadVerified,
		Input: m,
		Err:   verifyError,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Truef(t, pM.getTrace().ContainsFn(func(b event) bool {
		if b.t() != wrappedAction {
			return false
		}
		wrapper := b.(wrappedActionEvent)
		if wrapper.action.t() != ignore {
			return false
		}
		act := wrapper.action.(networkAction)
		if act.T == ignore && act.h == m.messageHandle && act.Err != nil {
			return true
		}
		return false
	}), "Player should ignore malformed payload")
}

func TestPlayerDisconnectsFromMalformedVotes(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	_, pM, helper := setupP(t, r, p, cert)

	verifyError := makeSerErrStr("test error")

	// check disconnect on malformed votes
	vv := helper.MakeVerifiedVote(t, 0, r, p, soft, bottom)
	m := message{
		Vote:                vv,
		UnauthenticatedVote: vv.u(),
		messageHandle:       "uniquemalformedvote",
	}
	inMsg := messageEvent{
		T:     voteVerified,
		Input: m,
		Err:   verifyError,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Truef(t, pM.getTrace().ContainsFn(func(b event) bool {
		if b.t() != wrappedAction {
			return false
		}
		wrapper := b.(wrappedActionEvent)
		if wrapper.action.t() != disconnect {
			return false
		}
		act := wrapper.action.(networkAction)
		if act.T == disconnect && act.h == m.messageHandle && act.Err != nil {
			return true
		}
		return false
	}), "Player should disconnect due to malformed vote")
}

func TestPlayerDisconnectsFromMalformedBundles(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	_, pM, _ := setupP(t, r, p, cert)

	verifyError := makeSerErrStr("test error")

	// check disconnect on malformed bundles
	m := message{
		Bundle:                bundle{},
		UnauthenticatedBundle: unauthenticatedBundle{},
		messageHandle:         "uniquemalformedBundle",
	}
	inMsg := messageEvent{
		Err:   verifyError,
		T:     bundleVerified,
		Input: m,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Truef(t, pM.getTrace().ContainsFn(func(b event) bool {
		if b.t() != wrappedAction {
			return false
		}
		wrapper := b.(wrappedActionEvent)
		if wrapper.action.t() != disconnect {
			return false
		}
		act := wrapper.action.(networkAction)
		if act.T == disconnect && act.h == m.messageHandle && act.Err != nil {
			return true
		}
		return false
	}), "Player should disconnect due to malformed bundle")
}

// Helper Sanity Checks
func TestPlayerRequestsVoteVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	_, pM, helper := setupP(t, r, p, cert)
	pV := helper.MakeRandomProposalValue()
	vote := helper.MakeVerifiedVote(t, 0, r, p, soft, *pV)
	m := message{
		UnauthenticatedVote: vote.u(),
	}
	inMsg := messageEvent{
		T:     votePresent,
		Input: m,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	verifyEvent := ev(cryptoAction{T: verifyVote, M: m, Round: r, Period: p, TaskIndex: 0})
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")
}

func TestPlayerRequestsProposalVoteVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(1)
	const p = period(0)
	_, pM, helper := setupP(t, r, p, cert)
	pV := helper.MakeRandomProposalValue()
	vote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	m := message{
		UnauthenticatedVote: vote.u(),
	}
	inMsg := messageEvent{
		T:     votePresent,
		Input: m,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	verifyEvent := ev(cryptoAction{T: verifyVote, M: m, Round: r, Period: p, TaskIndex: 1})
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")
}

func TestPlayerRequestsBundleVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	_, pM, _ := setupP(t, r, p, cert)
	bun := unauthenticatedBundle{
		Round:  r,
		Period: p,
	}
	m := message{
		UnauthenticatedBundle: bun,
	}
	inMsg := messageEvent{
		T:     bundlePresent,
		Input: m,
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	verifyEvent := ev(cryptoAction{T: verifyBundle, M: m, Round: r, Period: p, TaskIndex: 0})
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify bundle")
}

// Payload Pipelining
func TestPlayerRequestsPayloadVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	_, pM, helper := setupP(t, r, p, cert)
	payload, pV := helper.MakeRandomProposalPayload(t, r)

	// submit a proposal/initial payload
	vv := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	m := message{
		UnauthenticatedProposal: payload.u(),
	}
	inMsg = messageEvent{
		T:     payloadPresent,
		Input: m,
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// make sure payload verify request
	verifyEvent := ev(cryptoAction{T: verifyPayload, M: m, Round: r, Period: p, TaskIndex: 0})
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify payload")

}

func TestPlayerRequestsPipelinedPayloadVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(201221)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)
	// also make sure we ask for payload verification when entering a new round
	payloadTwo, pVTwo := helper.MakeRandomProposalPayload(t, r+1)
	vv := helper.MakeVerifiedVote(t, 0, r+1, 0, propose, *pVTwo)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	m := message{
		UnauthenticatedProposal: payloadTwo.u(),
		messageHandle:           "r2",
	}
	inMsg = messageEvent{
		T:     payloadPresent,
		Input: m,
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	// make sure no payload verify request, because its for the next round
	require.Falsef(t, pM.getTrace().ContainsString(verifyPayload.String()), "Player should not verify payload from r + 1")

	// now enter next round
	pP, pV := helper.MakeRandomProposalPayload(t, r)
	// send a payload
	// store an arbitrary proposal/payload
	vVote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg = messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *pP,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r+1, pWhite.Round, "player did not enter new round")
	require.Equalf(t, period(0), pWhite.Period, "player did not enter period 0 in new round")
	commitEvent := ev(ensureAction{Certificate: Certificate(bun), Payload: *pP})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should try to ensure block/digest on ledger")

	// make sure we sent out pipelined payload verify requests
	verifyEvent := ev(cryptoAction{T: verifyPayload, Round: r + 1, TaskIndex: 0})
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify pipelined payload first seen in previous round")
}

// Round pipelining
func TestPlayerHandlesPipelinedThresholds(t *testing.T) {
	partitiontest.PartitionTest(t)

	// make sure we stage a pipelined soft threshold after entering new round
	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	// pipeline a soft threshold for the next round
	payload, pV := helper.MakeRandomProposalPayload(t, r+1)
	votes := make([]vote, int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r+1, p, soft, *pV)
	}
	// note: we can't just send a bundle - it will get rejected due to freshness rules
	//bun := unauthenticatedBundle{
	//	Round:    r + 1,
	//	Period:   p,
	//	Proposal: *pV,
	//}
	//inMsg := messageEvent{
	//	T: bundleVerified,
	//	Input: message{
	//		Bundle: bundle{
	//			U:     bun,
	//			Votes: votes,
	//		},
	//		UnauthenticatedBundle: bun,
	//	},
	//}
	//err, panicErr := pM.transition(inMsg)
	//require.NoError(t, err)
	//require.NoError(t, panicErr)
	for _, v := range votes {
		inMsg := messageEvent{
			T: voteVerified,
			Input: message{
				Vote:                v,
				UnauthenticatedVote: v.u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
		err, panicErr := pM.transition(inMsg)
		require.NoError(t, err)
		require.NoError(t, panicErr)
	}

	// now, enter next round
	pPTwo, pVTwo := helper.MakeRandomProposalPayload(t, r)
	// store pPTwo
	vVote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pVTwo)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vVote,
			UnauthenticatedVote: vVote.u(),
		},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *pPTwo,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	votes = make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, *pVTwo)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Proposal: *pVTwo,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Equalf(t, r+1, pWhite.Round, "player did not enter new round")

	// now make sure we stage our soft threshold now
	// we verify this indirectly by attempting to send a payload and making sure it gets verified
	m := message{
		UnauthenticatedProposal: payload.u(),
	}
	inMsg = messageEvent{
		T:     payloadPresent,
		Input: m,
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	verifyEvent := ev(cryptoAction{T: verifyPayload, Round: r + 1})
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify pipelined payload first seen in previous round")
}

func TestPlayerRegression_EnsuresCertThreshFromOldPeriod_8ba23942(t *testing.T) {
	partitiontest.PartitionTest(t)

	// should not ignore cert thresholds from previous period in same round, if it
	// was saved as freshest threshold
	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	// send a next threshold to send player into period 1
	pP, pV := helper.MakeRandomProposalPayload(t, r)
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     next,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Equalf(t, p+1, pWhite.Period, "player did not fast forward to new period")

	// gen cert threshold in period 0, should move into next round
	// store an arbitrary payload. It should be accepted since the next quorum pinned pV.
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *pP,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	votes = make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, *pV) // period 0
		msg := messageEvent{
			T: voteVerified,
			Input: message{
				Vote:                votes[i],
				UnauthenticatedVote: votes[i].u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
		err, panicErr = pM.transition(msg)
		require.NoError(t, err)
		require.NoError(t, panicErr)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     cert,
		Proposal: *pV,
	}
	require.Equalf(t, r+1, pWhite.Round, "player did not enter new round")
	require.Equalf(t, period(0), pWhite.Period, "player did not enter period 0 in new round")
	commitEvent := ev(ensureAction{Certificate: Certificate(bun), Payload: *pP})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should try to ensure block on ledger")
}

func TestPlayer_RejectsCertThresholdFromPreviousRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	_, pV := helper.MakeRandomProposalPayload(t, r)
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r-1, p+1, cert, *pV)
		msg := messageEvent{
			T: voteVerified,
			Input: message{
				Vote:                votes[i],
				UnauthenticatedVote: votes[i].u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
		err, panicErr := pM.transition(msg)
		require.NoError(t, err)
		require.NoError(t, panicErr)
	}
	bun := unauthenticatedBundle{
		Round:    r - 1,
		Period:   p + 1,
		Step:     cert,
		Proposal: *pV,
	}
	require.Equalf(t, r, pWhite.Round, "player entered new round... bad!")
	require.Equalf(t, p, pWhite.Period, "player changed periods... bad!")
	commitEvent := ev(stageDigestAction{Certificate: Certificate(bun)})
	require.Falsef(t, pM.getTrace().Contains(commitEvent), "Player should not try to stage anything")
}

func TestPlayer_CommitsCertThresholdWithoutPreStaging(t *testing.T) {
	partitiontest.PartitionTest(t)

	// if player has pinned a block, then sees a cert threshold, it should commit
	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	// send a next threshold to send player into period 1
	pP, pV := helper.MakeRandomProposalPayload(t, r)
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     next,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Equalf(t, p+1, pWhite.Period, "player did not fast forward to new period")

	// store an arbitrary payload. It should be accepted since the next quorum pinned pV.
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal: *pP,
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// generate a cert threshold for period 1. This should ensureBlock since we have the payload.
	votes = make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+1, cert, *pV) // period 0
		msg := messageEvent{
			T: voteVerified,
			Input: message{
				Vote:                votes[i],
				UnauthenticatedVote: votes[i].u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
		err, panicErr = pM.transition(msg)
		require.NoError(t, err)
		require.NoError(t, panicErr)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p + 1,
		Step:     cert,
		Proposal: *pV,
	}
	require.Equalf(t, r+1, pWhite.Round, "player did not enter new round")
	require.Equalf(t, period(0), pWhite.Period, "player did not enter period 0 in new round")
	commitEvent := ev(ensureAction{Certificate: Certificate(bun), Payload: *pP})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should try to ensure block on ledger")
}

func TestPlayer_CertThresholdDoesNotBlock(t *testing.T) {
	partitiontest.PartitionTest(t)

	// check that ledger gets a hint to stage digest
	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	_, pV := helper.MakeRandomProposalPayload(t, r)
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p, cert, *pV)
		msg := messageEvent{
			T: voteVerified,
			Input: message{
				Vote:                votes[i],
				UnauthenticatedVote: votes[i].u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
		err, panicErr := pM.transition(msg)
		require.NoError(t, err)
		require.NoError(t, panicErr)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p,
		Step:     cert,
		Proposal: *pV,
	}
	require.Equalf(t, r, pWhite.Round, "player entered new round... bad!")
	require.Equalf(t, p, pWhite.Period, "player changed periods... bad!")
	commitEvent := ev(stageDigestAction{Certificate: Certificate(bun)})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should have staged something but didn't")
}

func TestPlayer_CertThresholdDoesNotBlockFuturePeriod(t *testing.T) {
	partitiontest.PartitionTest(t)

	// check that ledger gets a hint to stage digest
	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	_, pV := helper.MakeRandomProposalPayload(t, r)
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+1, cert, *pV)
		msg := messageEvent{
			T: voteVerified,
			Input: message{
				Vote:                votes[i],
				UnauthenticatedVote: votes[i].u(),
			},
			Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
		}
		err, panicErr := pM.transition(msg)
		require.NoError(t, err)
		require.NoError(t, panicErr)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p + 1,
		Step:     cert,
		Proposal: *pV,
	}
	require.Equalf(t, r, pWhite.Round, "player entered new round... bad!")
	require.Equalf(t, p+1, pWhite.Period, "player should have changed periods but didn't")
	commitEvent := ev(stageDigestAction{Certificate: Certificate(bun)})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should have staged something but didn't")
}

func TestPlayer_CertThresholdFastForwards(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	_, pV := helper.MakeRandomProposalPayload(t, r)
	// send a bundle - individual votes will get filtered.
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+2, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p + 2,
		Step:     cert,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r, pWhite.Round, "player entered new round... bad!")
	require.Equalf(t, p+2, pWhite.Period, "player should have changed periods but didn't")
	commitEvent := ev(stageDigestAction{Certificate: Certificate(bun)})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should have staged something but didn't")
}

func TestPlayer_CertThresholdCommitsFuturePeriodIfAlreadyHasBlock(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	payload, pV := helper.MakeRandomProposalPayload(t, r)
	// give player a proposal/payload.
	proposalVote := helper.MakeVerifiedVote(t, 0, r, p, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                proposalVote,
			UnauthenticatedVote: proposalVote.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// send a bundle - individual votes will get filtered.
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+2, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p + 2,
		Step:     cert,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r+1, pWhite.Round, "player did not enter new round... bad!")
	require.Equalf(t, period(0), pWhite.Period, "player should have entered period 0 of new round but didn't")
	commitEvent := ev(ensureAction{Certificate: Certificate(bun), Payload: *payload})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should have committed a block but didn't")
}

func TestPlayer_PayloadAfterCertThresholdCommits(t *testing.T) {
	partitiontest.PartitionTest(t)

	const r = round(20)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r, p, cert)

	pP, pV := helper.MakeRandomProposalPayload(t, r)
	// send a bundle - individual votes will get filtered.
	votes := make([]vote, int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p+2, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p + 2,
		Step:     cert,
		Proposal: *pV,
	}
	inMsg := messageEvent{
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
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r, pWhite.Round, "player entered new round... bad!")
	require.Equalf(t, p+2, pWhite.Period, "player should have changed periods but didn't")
	commitEvent := ev(stageDigestAction{Certificate: Certificate(bun)})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should have staged something but didn't")
	pM.resetTrace()

	// now, deliver payload, commit.
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *pP,
			UnauthenticatedProposal: pP.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	require.Equalf(t, r+1, pWhite.Round, "player did not enter new round... bad!")
	require.Equalf(t, period(0), pWhite.Period, "player should have entered period 0 but didn't")
	commitEvent = ev(ensureAction{Certificate: Certificate(bun), Payload: *pP})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should have committed but didn't")
}

func TestPlayerAlwaysResynchsPinnedValue(t *testing.T) {
	partitiontest.PartitionTest(t)

	// a white box test that checks the pinned value is relayed even it is not staged in the period corresponding to the freshest bundle
	const r = round(209)
	const p = period(12)
	pWhite, pM, helper := setupP(t, r, p-2, soft)
	payload, pV := helper.MakeRandomProposalPayload(t, r)

	// store a payload for period 10
	vv := helper.MakeVerifiedVote(t, 0, r, p-2, propose, *pV)
	inMsg := messageEvent{
		T: voteVerified,
		Input: message{
			Vote:                vv,
			UnauthenticatedVote: vv.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	inMsg = messageEvent{
		T: payloadVerified,
		Input: message{
			Proposal:                *payload,
			UnauthenticatedProposal: payload.u(),
		},
		Proto: ConsensusVersionView{Version: protocol.ConsensusCurrentVersion},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// gen next value bundle to fast forward into period 11
	votes := make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-2, next, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r,
		Period:   p - 2,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// Generate one more to fast-forward into period 12; note that period 11 has no staged value.
	votes = make([]vote, int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])))
	for i := 0; i < int(next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r, p-1, next, *pV)
	}
	bun = unauthenticatedBundle{
		Round:    r,
		Period:   p - 1,
		Proposal: *pV,
	}
	inMsg = messageEvent{
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
	pM.resetTrace() // clean up the history
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// Now, player should be in period 12, and should have tried to resychronize the pinned payload
	trace := pM.getTrace()
	require.Equalf(t, p, pWhite.Period, "player did not fast forward to new period")
	zeroEvent := ev(rezeroAction{Round: r})
	require.Truef(t, trace.Contains(zeroEvent), "Player should reset clock")

	resynchEvent := ev(networkAction{T: broadcast, Tag: protocol.VoteBundleTag, UnauthenticatedBundle: bun})
	require.Truef(t, trace.Contains(resynchEvent), "Player should relay freshest bundle = next value bundle")

	rePayloadEvent := ev(networkAction{T: broadcast, Tag: protocol.ProposalPayloadTag, CompoundMessage: compoundMessage{Proposal: payload.u()}})
	require.Truef(t, trace.Contains(rePayloadEvent), "Player should relay payload even if not staged in previous period")
}

// test that ReceivedAt and ValidateAt timing information are retained in proposalStore
// when the payloadPresent, payloadVerified, and voteVerified events are processed, and that all timings
// are available when the ensureAction is called for the block.
func TestPlayerRetainsReceivedValidatedAtOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(131)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// send voteVerified message for round r-credentialRoundLag-1, then for r-1
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 502*time.Millisecond, nil)
	// send payloadPresent message for r-1
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	// advance player to R and check timings ensured for R-1 are correct
	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)
}

// test that ReceivedAt and ValidateAt timing information are retained in proposalStore
// when the payloadPresent, payloadVerified, and voteVerified events are processed, and that all timings
// are available when the ensureAction is called for the block.
func TestPlayerRetainsReceivedValidatedAtCredentialHistory(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-credentialRoundLag-1, p, soft)

	// send voteVerified and payloadPresent messages with timings, and advance through rounds r-credentialRoundLag-1 up to r-1
	voteVerifiedTiming := 501 * time.Millisecond
	payloadPresentTiming := 1001 * time.Millisecond
	payloadVerifiedTiming := 2001 * time.Millisecond
	for rnd := r - credentialRoundLag - 1; rnd < r-1; rnd++ {
		pP, pV := helper.MakeRandomProposalPayload(t, rnd)
		sendVoteVerified(t, helper, pWhite, pM, 0, rnd, rnd, p, pV, voteVerifiedTiming, nil)
		sendPayloadPresent(t, pWhite, pM, rnd, pP, payloadPresentTiming, nil)
		moveToRound(t, pWhite, pM, helper, rnd+1, p, pP, pV, payloadVerifiedTiming, version)

		voteVerifiedTiming += time.Millisecond
		payloadPresentTiming += time.Millisecond
		payloadVerifiedTiming += time.Millisecond
	}

	// send in voteVerified and payloadPresent for r-1
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 600*time.Millisecond, nil)
	sendPayloadPresent(t, pWhite, pM, r-1, pP, 1500*time.Millisecond, nil)
	// advance player to R and check timings ensured for R-1 are correct
	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2500*time.Millisecond, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, 1500*time.Millisecond, 2500*time.Millisecond)

	// player is looking up arrival times from r-roundLag ago so only the 501ms vote will be in lowestCredentialArrivals
	assertSingleCredentialArrival(t, pWhite, 501*time.Millisecond)
}

// test that ReceivedAt and ValidateAt timing information are retained in
// proposalStore when the payloadPresent, payloadVerified, and voteVerified
// events are processed in the *preceding round*, and that all timings are
// available when the ensureAction is called for the block.
func TestPlayerRetainsEarlyReceivedValidatedAtOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)

	// send voteVerified message
	pP, pV := helper.MakeRandomProposalPayload(t, r-credentialRoundLag-1)
	sendVoteVerified(t, helper, pWhite, pM, 0, r-credentialRoundLag-2, r-credentialRoundLag-1, p, pV, 401*time.Millisecond, nil)

	// send voteVerified message
	pP, pV = helper.MakeRandomProposalPayload(t, r-1)
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	// advance player to R and check timings ensured for R-1 are correct
	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)

	// assert lowest vote validateAt time was recorded into payloadArrivals
	assertSingleCredentialArrival(t, pWhite, pipelinedMessageTimestamp)
}

func testClockForRound(t *testing.T, pWhite *player, fixedDur time.Duration, currentRound round, historicalClocks map[round]roundStartTimer) func(round) roundStartTimer {
	return func(eventRound round) roundStartTimer {
		//require.Equal(t, pWhite.Round, currentRound) // TODO make tests more realistic
		return clockForRound(currentRound, constantRoundStartTimer(fixedDur), historicalClocks)(eventRound)
	}
}

// test that ReceivedAt and ValidateAt timing information are retained in
// proposalStore when the payloadPresent, payloadVerified, and voteVerified
// events are processed credentialRoundLag after the round they belong to, and
// that all timings are available when the ensureAction is called for the block.
func TestPlayerRetainsLateReceivedValidatedAtOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)

	historicalClocks := map[round]roundStartTimer{
		r - credentialRoundLag - 1: constantRoundStartTimer(900 * time.Millisecond),
	}

	// send voteVerified message
	pP, pV := helper.MakeRandomProposalPayload(t, r-credentialRoundLag-1)
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-credentialRoundLag-1, p, pV, 401*time.Millisecond, historicalClocks)

	// send voteVerified message
	pP, pV = helper.MakeRandomProposalPayload(t, r-1)
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	// advance player to R and check timings ensured for R-1 are correct
	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)

	// assert lowest vote validateAt time was recorded into payloadArrivals
	assertSingleCredentialArrival(t, pWhite, 900*time.Millisecond)
}

// test that ReceivedAt and ValidateAt timing information are retained in proposalStore
// when the payloadPresent, payloadVerified, and voteVerified events are processed, and that all timings
// are available when the ensureAction is called for the block. The history should be kept for the last
// DynamicFilterCredentialArrivalHistory rounds.
func TestPlayerRetainsReceivedValidatedAtForHistoryWindow(t *testing.T) {
	partitiontest.PartitionTest(t)
	testPlayerRetainsReceivedValidatedAtForHistoryWindow(t, false)
}

func TestPlayerRetainsReceivedValidatedAtForHistoryWindowLateBetter(t *testing.T) {
	partitiontest.PartitionTest(t)
	testPlayerRetainsReceivedValidatedAtForHistoryWindow(t, true)
}

func testPlayerRetainsReceivedValidatedAtForHistoryWindow(t *testing.T, addBetterLate bool) {
	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)

	require.NotZero(t, dynamicFilterCredentialArrivalHistory)

	for i := 0; i < dynamicFilterCredentialArrivalHistory+int(credentialRoundLag); i++ {
		// send voteVerified message
		pP, pV := helper.MakeRandomProposalPayload(t, r+round(i)-1)
		vVote := helper.MakeVerifiedVote(t, 0, r+round(i)-1, p, propose, *pV)
		var betterLateVote vote
		if addBetterLate {
			// set up better late proposal-vote from someone else, so it won't be a errProposalTrackerSenderDup
			vVote2 := helper.MakeVerifiedVote(t, 1, r+round(i)-1, p, propose, *pV)
			vVote.Cred.VrfOut = crypto.Digest{1}
			vVote2.Cred.VrfOut = crypto.Digest{2}
			if vVote2.Cred.Less(vVote.Cred) {
				betterLateVote = vVote2
			} else {
				betterLateVote = vVote
				vVote = vVote2
			}
			require.True(t, betterLateVote.Cred.Less(vVote.Cred))
			require.False(t, vVote.Cred.Less(betterLateVote.Cred))
		}
		inMsg := messageEvent{T: voteVerified, Input: message{Vote: vVote, UnauthenticatedVote: vVote.u()}}
		timestamp := 500 + i
		inMsg = inMsg.AttachValidatedAt(testClockForRound(t, pWhite, time.Duration(timestamp)*time.Millisecond, r+round(i)-1, nil))
		err, panicErr := pM.transition(inMsg)
		require.NoError(t, err)
		require.NoError(t, panicErr)

		// send payloadPresent message
		sendPayloadPresent(t, pWhite, pM, r+round(i)-1, pP, time.Second, nil)
		moveToRound(t, pWhite, pM, helper, r+round(i), p, pP, pV, 2*time.Second, version)

		// send better late voteVerified message
		if addBetterLate {
			inMsg = messageEvent{T: voteVerified, Input: message{Vote: betterLateVote, UnauthenticatedVote: betterLateVote.u()}}
			timestamp := 600 + i
			inMsg = inMsg.AttachValidatedAt(testClockForRound(t, pWhite, time.Duration(timestamp)*time.Millisecond, r+round(i)-1, nil))
			err, panicErr = pM.transition(inMsg)
			require.NoError(t, err)
			require.NoError(t, panicErr)
		}
	}

	// assert lowest vote validateAt time was recorded into payloadArrivals
	require.True(t, pWhite.lowestCredentialArrivals.isFull())
	for i := 0; i < dynamicFilterCredentialArrivalHistory; i++ {
		// only the last historyLen samples are kept, so the first one is discarded
		timestamp := 500 + i
		if addBetterLate {
			timestamp = 600 + i
		}
		require.Equal(t, time.Duration(timestamp)*time.Millisecond, pWhite.lowestCredentialArrivals.history[i])
	}
}

// test that ReceivedAt and ValidateAt timing information are retained in proposalStore
// when the payloadPresent (as part of the CompoundMessage encoding used by PP messages),
// payloadVerified, and voteVerified events are processed, and that all timings
// are available when the ensureAction is called for the block.
func TestPlayerRetainsReceivedValidatedAtPPOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version, _, configCleanup := overrideConfigWithDynamicFilterParam(true)
	defer configCleanup()
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// Move to round r, no credentials arrived.
	// send voteVerified message
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)
	require.False(t, pWhite.lowestCredentialArrivals.isFull())
	require.Equal(t, pWhite.lowestCredentialArrivals.writePtr, 0)

	// XXX this behavior only happens if dynamic timeout enabled; test the other way

	historicalClocks := map[round]roundStartTimer{
		r - credentialRoundLag: constantRoundStartTimer(900 * time.Millisecond),
	}
	// create a PP message for the round we're going to take the sample from when round r-1 ends
	pP, pV = helper.MakeRandomProposalPayload(t, r-credentialRoundLag)
	vVote := sendCompoundMessage(t, helper, pWhite, pM, r, r-credentialRoundLag, p, pP, pV, time.Second, nil, version)

	verifyEvent := ev(verifyVoteAction(messageEvent{Input: message{UnauthenticatedVote: vVote.u()}}, r-credentialRoundLag, p, 1))
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")
	sendVoteVerifiedForVote(t, vVote, pWhite, pM, r, 502*time.Millisecond, historicalClocks, 1)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r, pP, time.Second, nil)

	// move to round r+1, triggering history update
	pP, pV = helper.MakeRandomProposalPayload(t, r)
	sendVoteVerified(t, helper, pWhite, pM, 0, r, r, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r, pP, time.Second, nil)

	moveToRound(t, pWhite, pM, helper, r+1, p, pP, pV, 2*time.Second, version)

	// assert lowest vote validateAt time was recorded into payloadArrivals
	assertSingleCredentialArrival(t, pWhite, 900*time.Millisecond)
}

// test that ReceivedAt and ValidateAt timing information are retained in
// proposalStore when the payloadPresent (as part of the CompoundMessage
// encoding used by PP messages), payloadVerified, and voteVerified events are
// processed one round early, and that all timings are available when the
// ensureAction is called for the block.
func TestPlayerRetainsEarlyReceivedValidatedAtPPOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version, _, configCleanup := overrideConfigWithDynamicFilterParam(true)
	defer configCleanup()

	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// Move to round r, no credentials arrived.
	// send voteVerified message
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)
	require.False(t, pWhite.lowestCredentialArrivals.isFull())
	require.Equal(t, pWhite.lowestCredentialArrivals.writePtr, 0)

	// create a PP message for the round we're going to take the sample from when round r-1 ends
	// Now we're going to pretend we got the message one round early.
	pP, pV = helper.MakeRandomProposalPayload(t, r-credentialRoundLag)
	vVote := sendCompoundMessage(t, helper, pWhite, pM, r-credentialRoundLag-1, r-credentialRoundLag, p, pP, pV, time.Second, nil, version)

	// make sure vote verify requests
	verifyEvent := ev(verifyVoteAction(messageEvent{Input: message{UnauthenticatedVote: vVote.u()}}, r-credentialRoundLag, p, 1))
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")

	sendVoteVerifiedForVote(t, vVote, pWhite, pM, r-credentialRoundLag, 502*time.Millisecond, nil, 1)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-credentialRoundLag, pP, time.Second, nil)

	// move to round r+1, triggering history update
	pP, pV = helper.MakeRandomProposalPayload(t, r)
	sendVoteVerified(t, helper, pWhite, pM, 0, r, r, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r, pP, time.Second, nil)
	moveToRound(t, pWhite, pM, helper, r+1, p, pP, pV, 2*time.Second, version)

	// assert lowest vote validateAt time was recorded into payloadArrivals
	assertSingleCredentialArrival(t, pWhite, 502*time.Millisecond)
}

// test that ReceivedAt and ValidateAt timing information are retained in
// proposalStore when the payloadPresent (as part of the CompoundMessage
// encoding used by PP messages), payloadVerified, and voteVerified events are
// processed credentialRoundLag after the round they belong to, and that all
// timings are available when the ensureAction is called for the block.
func TestPlayerRetainsLateReceivedValidatedAtPPOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version, _, configCleanup := overrideConfigWithDynamicFilterParam(true)
	defer configCleanup()
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// Move to round r, no credentials arrived.
	// send voteVerified message
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	// Go from round r-1 to r
	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)
	require.False(t, pWhite.lowestCredentialArrivals.isFull())
	require.Equal(t, pWhite.lowestCredentialArrivals.writePtr, 0)

	historicalClocks := map[round]roundStartTimer{
		r - credentialRoundLag: constantRoundStartTimer(900 * time.Millisecond),
	}
	// create a PP message for the round we're going to take the sample from when round r-1 ends
	// Now we're going to pretend we got the message credentialRoundLag too late.
	pP, pV = helper.MakeRandomProposalPayload(t, r-credentialRoundLag)
	vVote := sendCompoundMessage(t, helper, pWhite, pM, r, r-credentialRoundLag, p, pP, pV, time.Second, historicalClocks, version)

	verifyEvent := ev(verifyVoteAction(messageEvent{Input: message{UnauthenticatedVote: vVote.u()}}, r-credentialRoundLag, p, 1))
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")

	sendVoteVerifiedForVote(t, vVote, pWhite, pM, r, 502*time.Millisecond, historicalClocks, 1)

	// move to round r+1, triggering history update
	pP, pV = helper.MakeRandomProposalPayload(t, r)
	sendVoteVerified(t, helper, pWhite, pM, 0, r, r, p, pV, 503*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r, pP, time.Second, nil)
	moveToRound(t, pWhite, pM, helper, r+1, p, pP, pV, 2*time.Second, version)

	// assert lowest vote validateAt time was recorded into payloadArrivals
	assertSingleCredentialArrival(t, pWhite, 900*time.Millisecond)
}

// test that ReceivedAt and ValidateAt timing information are retained in
// proposalStore when the payloadPresent (as part of the CompoundMessage
// encoding used by PP messages), payloadVerified, and voteVerified events are
// processed, and that all timings are available when the ensureAction is called
// for the block. The history should be kept for the last
// DynamicFilterCredentialArrivalHistory rounds.
func TestPlayerRetainsReceivedValidatedAtPPForHistoryWindow(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)

	require.NotZero(t, dynamicFilterCredentialArrivalHistory)

	for i := 0; i < dynamicFilterCredentialArrivalHistory+int(credentialRoundLag); i++ {
		// create a PP message for an arbitrary proposal/payload similar to setupCompoundMessage
		pP, pV := helper.MakeRandomProposalPayload(t, r+round(i)-1)
		vVote := sendCompoundMessage(t, helper, pWhite, pM, r+round(i)-1, r+round(i)-1, p, pP, pV, time.Second, nil, version)

		// make sure vote verify requests
		taskIndex := uint64(i + 1)
		verifyEvent := ev(verifyVoteAction(messageEvent{Input: message{UnauthenticatedVote: vVote.u()}}, r+round(i)-1, p, taskIndex))
		require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")

		// send voteVerified
		timestamp := 500 + i
		sendVoteVerifiedForVote(t, vVote, pWhite, pM, r+round(i)-1, time.Duration(timestamp)*time.Millisecond, nil, taskIndex)
		sendPayloadPresent(t, pWhite, pM, r+round(i)-1, pP, time.Duration(timestamp)*time.Millisecond+time.Second, nil)
		moveToRound(t, pWhite, pM, helper, r+round(i), p, pP, pV, 2*time.Second+time.Duration(timestamp)*time.Millisecond, version)
	}

	// assert lowest vote validateAt time was recorded into payloadArrivals
	require.True(t, pWhite.lowestCredentialArrivals.isFull())
	for i := 0; i < dynamicFilterCredentialArrivalHistory; i++ {
		// only the last historyLen samples are kept, so the first one is discarded
		timestamp := 500 + i
		require.Equal(t, time.Duration(timestamp)*time.Millisecond, pWhite.lowestCredentialArrivals.history[i])
	}
}

// test that ReceivedAt and ValidateAt timing information are retained in proposalStore
// when the voteVerified event comes in first (as part of the AV message before PP),
// then the payloadPresent (as part of the CompoundMessage encoding used by PP messages)
// and payloadVerified events are processed, and that all timings
// are available when the ensureAction is called for the block.
func TestPlayerRetainsReceivedValidatedAtAVPPOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create a protocol version where dynamic lambda is enabled
	version, _, configCleanup := overrideConfigWithDynamicFilterParam(true)
	defer configCleanup()
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// Move to round r, no credentials arrived.
	// send voteVerified message
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)
	require.False(t, pWhite.lowestCredentialArrivals.isFull())
	require.Equal(t, pWhite.lowestCredentialArrivals.writePtr, 0)

	// send votePresent message (mimicking the first AV message validating)
	pP, pV = helper.MakeRandomProposalPayload(t, r-credentialRoundLag)
	vVote := sendVotePresent(t, helper, pWhite, pM, 0, r-credentialRoundLag, p, pV, version)

	// make sure vote verify requests
	unverifiedVoteMsg := message{UnauthenticatedVote: vVote.u()}
	verifyEvent := ev(verifyVoteAction(messageEvent{Input: unverifiedVoteMsg}, r-credentialRoundLag, p, 1))
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")

	// send voteVerified
	sendVoteVerifiedForVote(t, vVote, pWhite, pM, r-credentialRoundLag, 502*time.Millisecond, nil, 1)

	// create a PP message for an arbitrary proposal/payload similar to setupCompoundMessage
	sendCompoundMessageForVote(t, vVote, pWhite, pM, r-credentialRoundLag, pP, time.Second, nil, version)

	// move to round r+1, triggering history update
	pP, pV = helper.MakeRandomProposalPayload(t, r)
	sendVoteVerified(t, helper, pWhite, pM, 0, r, r, p, pV, time.Second, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r, pP, time.Second, nil)
	moveToRound(t, pWhite, pM, helper, r+1, p, pP, pV, 2*time.Second, version)

	// assert lowest vote validateAt time was recorded into payloadArrivals
	assertSingleCredentialArrival(t, pWhite, 502*time.Millisecond)
}

// test that ReceivedAt and ValidateAt timing information are retained in
// proposalStore when the voteVerified event comes in first (as part of the AV
// message before PP), then the payloadPresent (as part of the CompoundMessage
// encoding used by PP messages) and payloadVerified events are processed one
// round early, and that all timings are available when the ensureAction is
// called for the block.
func TestPlayerRetainsEarlyReceivedValidatedAtAVPPOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// Move to round r, no credentials arrived.
	// send voteVerified message
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)
	require.False(t, pWhite.lowestCredentialArrivals.isFull())
	require.Equal(t, pWhite.lowestCredentialArrivals.writePtr, 0)

	// create a protocol version where dynamic filter is enabled
	version, _, configCleanup := overrideConfigWithDynamicFilterParam(true)
	defer configCleanup()

	// send votePresent message (mimicking the first AV message validating)
	pP, pV = helper.MakeRandomProposalPayload(t, r-credentialRoundLag)
	vVote := sendVotePresent(t, helper, pWhite, pM, 0, r-credentialRoundLag, p, pV, version)

	// make sure vote verify requests
	verifyEvent := ev(verifyVoteAction(messageEvent{Input: message{UnauthenticatedVote: vVote.u()}}, r-credentialRoundLag, p, 1))
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")

	// send voteVerified, pretend we're one round too early
	sendVoteVerifiedForVote(t, vVote, pWhite, pM, r-credentialRoundLag-1, 502*time.Millisecond, nil, 1)

	// create a PP message for an arbitrary proposal/payload similar to setupCompoundMessage
	sendCompoundMessageForVote(t, vVote, pWhite, pM, r-credentialRoundLag, pP, time.Second, nil, version)

	// move to round r+1, triggering history update
	pP, pV = helper.MakeRandomProposalPayload(t, r)
	sendVoteVerified(t, helper, pWhite, pM, 0, r, r, p, pV, time.Second, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r, pP, time.Second, nil)
	moveToRound(t, pWhite, pM, helper, r+1, p, pP, pV, 2*time.Second, version)

	// assert lowest vote validateAt time was recorded into payloadArrivals
	assertSingleCredentialArrival(t, pWhite, pipelinedMessageTimestamp)
}

// test that ReceivedAt and ValidateAt timing information are retained in
// proposalStore when the voteVerified event comes in first (as part of the AV
// message before PP), then the payloadPresent (as part of the CompoundMessage
// encoding used by PP messages) and payloadVerified events are processed
// credentialRoundLag after the round they belong to, and that all timings are
// available when the ensureAction is called for the block.
func TestPlayerRetainsLateReceivedValidatedAtAVPPOneSample(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)
	pP, pV := helper.MakeRandomProposalPayload(t, r-1)

	// Move to round r, no credentials arrived.
	// send voteVerified message
	sendVoteVerified(t, helper, pWhite, pM, 0, r-1, r-1, p, pV, 501*time.Millisecond, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r-1, pP, time.Second, nil)

	moveToRound(t, pWhite, pM, helper, r, p, pP, pV, 2*time.Second, version)
	assertPayloadTimings(t, pWhite, pM, r-1, pV, time.Second, 2*time.Second)
	require.False(t, pWhite.lowestCredentialArrivals.isFull())
	require.Equal(t, pWhite.lowestCredentialArrivals.writePtr, 0)

	// create a protocol version where dynamic filter is enabled
	version, _, configCleanup := overrideConfigWithDynamicFilterParam(true)
	defer configCleanup()

	// send votePresent message (mimicking the first AV message validating)
	pP, pV = helper.MakeRandomProposalPayload(t, r-credentialRoundLag)
	vVote := sendVotePresent(t, helper, pWhite, pM, 0, r-credentialRoundLag, p, pV, version)

	// make sure vote verify requests
	verifyEvent := ev(verifyVoteAction(messageEvent{Input: message{UnauthenticatedVote: vVote.u()}}, r-credentialRoundLag, p, 1))
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")

	historicalClocks := map[round]roundStartTimer{
		r - credentialRoundLag: constantRoundStartTimer(900 * time.Millisecond),
	}
	// send voteVerified, pretend we're credentialRoundLag after the message was sent
	sendVoteVerifiedForVote(t, vVote, pWhite, pM, r, 502*time.Millisecond, historicalClocks, 1)

	// create a PP message for an arbitrary proposal/payload similar to setupCompoundMessage
	sendCompoundMessageForVote(t, vVote, pWhite, pM, r-credentialRoundLag, pP, time.Second, nil, version)

	// move to round r+1, triggering history update
	pP, pV = helper.MakeRandomProposalPayload(t, r)
	sendVoteVerified(t, helper, pWhite, pM, 0, r, r, p, pV, time.Second, nil)

	// send payloadPresent message
	sendPayloadPresent(t, pWhite, pM, r, pP, time.Second, nil)
	moveToRound(t, pWhite, pM, helper, r+1, p, pP, pV, 2*time.Second, version)

	// assert lowest vote validateAt time was recorded into lowestCredentialArrivals
	assertSingleCredentialArrival(t, pWhite, 900*time.Millisecond)
}

func TestPlayerRetainsReceivedValidatedAtAVPPHistoryWindow(t *testing.T) {
	partitiontest.PartitionTest(t)

	version := protocol.ConsensusCurrentVersion
	const r = round(20239)
	const p = period(0)
	pWhite, pM, helper := setupP(t, r-1, p, soft)

	require.NotZero(t, dynamicFilterCredentialArrivalHistory)

	for i := 0; i < dynamicFilterCredentialArrivalHistory+int(credentialRoundLag); i++ {
		pP, pV := helper.MakeRandomProposalPayload(t, r+round(i)-1)

		// send votePresent message (mimicking the first AV message validating)
		vVote := sendVotePresent(t, helper, pWhite, pM, 0, r+round(i)-1, p, pV, version)

		// make sure vote verify requests
		taskIndex := uint64(i + 1)
		verifyEvent := ev(verifyVoteAction(messageEvent{Input: message{UnauthenticatedVote: vVote.u()}}, r+round(i)-1, p, taskIndex))
		require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify vote")

		// send voteVerified
		timestamp := 500 + i
		sendVoteVerifiedForVote(t, vVote, pWhite, pM, r+round(i)-1, time.Duration(timestamp)*time.Millisecond, nil, taskIndex)

		// create a PP message for an arbitrary proposal/payload similar to setupCompoundMessage
		sendCompoundMessageForVote(t, vVote, pWhite, pM, r+round(i)-1, pP, time.Second, nil, version)

		moveToRound(t, pWhite, pM, helper, r+round(i), p, pP, pV, 2*time.Second, version)
	}

	// assert lowest vote validateAt time was recorded into payloadArrivals
	require.True(t, pWhite.lowestCredentialArrivals.isFull())
	for i := 0; i < dynamicFilterCredentialArrivalHistory; i++ {
		// only the last historyLen samples are kept, so the first one is discarded
		timestamp := 500 + i
		require.Equal(t, time.Duration(timestamp)*time.Millisecond, pWhite.lowestCredentialArrivals.history[i])
	}
}

// Helper function to send voteVerified message
func sendVoteVerified(t *testing.T, helper *voteMakerHelper, pWhite *player, pM ioAutomata, addrIndex int,
	curRound round, voteRound round, votePeriod period, pV *proposalValue, validatedAt time.Duration,
	historicalClocks map[round]roundStartTimer) {
	vVote := helper.MakeVerifiedVote(t, addrIndex, voteRound, votePeriod, propose, *pV)
	sendVoteVerifiedForVote(t, vVote, pWhite, pM, curRound, validatedAt, historicalClocks, 0)
}

func sendVoteVerifiedForVote(t *testing.T, vVote vote, pWhite *player, pM ioAutomata,
	curRound round, validatedAt time.Duration, historicalClocks map[round]roundStartTimer, taskIndex uint64) {
	inMsg := messageEvent{T: voteVerified, Input: message{Vote: vVote, UnauthenticatedVote: vVote.u()}, TaskIndex: taskIndex}
	inMsg = inMsg.AttachValidatedAt(testClockForRound(t, pWhite, validatedAt, curRound, historicalClocks))
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
}

func sendVotePresent(t *testing.T, helper *voteMakerHelper, pWhite *player, pM ioAutomata, addrIndex int,
	voteRound round, votePeriod period, pV *proposalValue, version protocol.ConsensusVersion) vote {
	vVote := helper.MakeVerifiedVote(t, addrIndex, voteRound, votePeriod, propose, *pV)
	inMsg := messageEvent{T: votePresent, Input: message{UnauthenticatedVote: vVote.u()}, Proto: ConsensusVersionView{Version: version}}
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
	return vVote
}

// Helper function to send payloadPresent message
func sendPayloadPresent(t *testing.T, pWhite *player, pM ioAutomata, curRound round, pP *proposal, receivedAt time.Duration, historicalClocks map[round]roundStartTimer) {
	m := message{UnauthenticatedProposal: pP.u()}
	inMsg := messageEvent{T: payloadPresent, Input: m}
	inMsg = inMsg.AttachReceivedAt(testClockForRound(t, pWhite, receivedAt, curRound, historicalClocks))
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
}

// Helper function to send a compound PP message (votePresent + payloadPresent)
func sendCompoundMessage(t *testing.T, helper *voteMakerHelper, pWhite *player, pM ioAutomata, curRound round, voteRound round, votePeriod period, pP *proposal, pV *proposalValue, receivedAt time.Duration, historicalClocks map[round]roundStartTimer, version protocol.ConsensusVersion) vote {
	vVote := helper.MakeVerifiedVote(t, 0, voteRound, votePeriod, propose, *pV)
	sendCompoundMessageForVote(t, vVote, pWhite, pM, curRound, pP, receivedAt, historicalClocks, version)
	return vVote
}

func sendCompoundMessageForVote(t *testing.T, vVote vote, pWhite *player, pM ioAutomata, curRound round, pP *proposal, receivedAt time.Duration, historicalClocks map[round]roundStartTimer, version protocol.ConsensusVersion) {
	unverifiedVoteMsg := message{UnauthenticatedVote: vVote.u()}
	proposalMsg := message{UnauthenticatedProposal: pP.u()}
	compoundMsg := messageEvent{
		T:     votePresent,
		Input: unverifiedVoteMsg,
		Tail: &messageEvent{
			T:     payloadPresent,
			Input: proposalMsg,
			Proto: ConsensusVersionView{Version: version},
		},
		Proto: ConsensusVersionView{Version: version},
	}
	inMsg := compoundMsg.AttachReceivedAt(testClockForRound(t, pWhite, receivedAt, curRound, historicalClocks)) // call AttachReceivedAt like demux would
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)
}

// Helper function to assert lowest vote validateAt time was recorded into lowestCredentialArrivals
func assertSingleCredentialArrival(t *testing.T, pWhite *player, expectedTime time.Duration) {
	require.NotZero(t, dynamicFilterCredentialArrivalHistory)
	require.Equal(t, pWhite.lowestCredentialArrivals.writePtr, 1)
	require.False(t, pWhite.lowestCredentialArrivals.isFull())
	require.Equal(t, expectedTime, pWhite.lowestCredentialArrivals.history[0])
}

// Helper function to submit payloadVerified message and a bundleVerified for a cert threshold
// to move into the next round.
// Assumes payloadPresent has alread been sent and the verifyPayload action has already requested.
func moveToRound(t *testing.T, pWhite *player, pM ioAutomata, helper *voteMakerHelper,
	r round, p period, pP *proposal, pV *proposalValue, validatedAt time.Duration, ver protocol.ConsensusVersion) {

	// make sure payload verify request
	verifyEvent := ev(verifyPayloadAction(messageEvent{Input: message{UnauthenticatedProposal: pP.u()}}, r-1, p, false))
	require.Truef(t, pM.getTrace().Contains(verifyEvent), "Player should verify payload")

	// payloadVerified
	inMsg := messageEvent{T: payloadVerified, Input: message{Proposal: *pP}, Proto: ConsensusVersionView{Version: ver}}
	inMsg = inMsg.AttachValidatedAt(testClockForRound(t, pWhite, validatedAt, r-1, nil)) // call AttachValidatedAt like demux would
	err, panicErr := pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	// // now, trigger soft vote timeout
	// err, panicErr = pM.transition(makeTimeoutEvent())
	// require.NoError(t, err)
	// require.NoError(t, panicErr)
	// softVoteEvent := ev(pseudonodeAction{T: attest, Round: r - 1, Period: p, Step: soft, Proposal: *pV})
	// require.Truef(t, pM.getTrace().Contains(softVoteEvent), "Player should issue soft vote")

	// gen cert to move into the next round
	votes := make([]vote, int(cert.threshold(config.Consensus[ver])))
	for i := 0; i < int(cert.threshold(config.Consensus[ver])); i++ {
		votes[i] = helper.MakeVerifiedVote(t, i, r-1, p, cert, *pV)
	}
	bun := unauthenticatedBundle{
		Round:    r - 1,
		Period:   p,
		Proposal: *pV,
	}
	inMsg = messageEvent{
		T: bundleVerified,
		Input: message{
			Bundle: bundle{
				U:     bun,
				Votes: votes,
			},
			UnauthenticatedBundle: bun,
		},
		Proto: ConsensusVersionView{Version: ver},
	}
	err, panicErr = pM.transition(inMsg)
	require.NoError(t, err)
	require.NoError(t, panicErr)

	require.Equalf(t, r, pWhite.Round, "player did not enter new round")
	require.Equalf(t, period(0), pWhite.Period, "player did not enter period 0 in new round")
	commitEvent := ev(ensureAction{Certificate: Certificate(bun), Payload: *pP})
	require.Truef(t, pM.getTrace().Contains(commitEvent), "Player should try to ensure block/digest on ledger")
}

// inspect the ensureAction for round R and assert the correct payload timings
func assertPayloadTimings(t *testing.T, pWhite *player, pM ioAutomata, r round, pV *proposalValue, receivedAt time.Duration, validatedAt time.Duration) {

	// find and unwrap ensureAction from trace
	var ea ensureAction
	var foundEA bool
	for _, ev := range pM.getTrace().events {
		if wae, ok := ev.(wrappedActionEvent); ok {
			if wae.action.t() == ensure {
				require.False(t, foundEA)
				ea = wae.action.(ensureAction)
				// looking just for ensureAction on this round
				if r == ea.Payload.Round() {
					foundEA = true
					break
				}
			}
		}
	}
	require.True(t, foundEA)
	require.Equal(t, *pV, ea.Certificate.Proposal)
	require.Equal(t, r, ea.Payload.Round())
	require.Equal(t, validatedAt, ea.Payload.validatedAt)
	require.Equal(t, receivedAt, ea.Payload.receivedAt)
}

// todo: test pipelined rounds, and round interruption
