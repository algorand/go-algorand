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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testpartitioning"
)

func testSetup(periodCount uint64) (player, rootRouter, testAccountData, testBlockFactory, Ledger) {
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture10()
	accs := testAccountData{addresses: addresses, vrfs: vrfSecrets, ots: otSecrets}
	round := ledger.NextRound()
	period := period(periodCount)
	player := player{Round: round, Period: period, Step: soft}

	var p actor = ioLoggedActor{checkedActor{actor: &player, actorContract: playerContract{}}, playerTracer}
	router := routerFixture
	router.root = p
	f := testBlockFactory{Owner: 1} // TODO this should change with given address

	return player, router, accs, f, ledger
}

func createProposalsTesting(accs testAccountData, round basics.Round, period period, factory BlockFactory, ledger Ledger) (ps []proposal, vs []vote) {
	ve, err := factory.AssembleBlock(round, time.Now().Add(time.Minute))
	if err != nil {
		logging.Base().Errorf("Could not generate a proposal for round %d: %v", round, err)
		return nil, nil
	}

	// TODO this common code should be refactored out
	var votes []vote
	proposals := make([]proposal, 0)
	for i := range accs.addresses {
		payload, proposal, _ := proposalForBlock(accs.addresses[i], accs.vrfs[i], ve, period, ledger)

		// attempt to make the vote
		rv := rawVote{Sender: accs.addresses[i], Round: round, Period: period, Step: propose, Proposal: proposal}
		uv, err := makeVote(rv, accs.ots[i], accs.vrfs[i], ledger)
		if err != nil {
			logging.Base().Errorf("AccountManager.makeVotes: Could not create vote: %v", err)
			return
		}
		vote, err := uv.verify(ledger)
		if err != nil {
			continue
		}

		// create the block proposal
		proposals = append(proposals, payload)
		votes = append(votes, vote)
	}
	return proposals, votes
}

func createProposalEvents(t *testing.T, player player, accs testAccountData, f testBlockFactory, ledger Ledger) (voteBatch []event, payloadBatch []event, lowestProposal proposalValue) {
	payloads, votes := createProposalsTesting(accs, player.Round, player.Period, f, ledger)
	if len(votes) == 0 {
		return
	}

	for i := range votes {
		vote := votes[i]
		msg := message{Tag: protocol.AgreementVoteTag, Vote: vote}
		e := messageEvent{T: voteVerified, Input: msg}
		voteBatch = append(voteBatch, e)

		payload := payloads[i]
		msg = message{Tag: protocol.ProposalPayloadTag, Proposal: payload}
		e = messageEvent{T: payloadVerified, Input: msg}
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

func TestProposalCreation(t *testing.T) {
	testpartitioning.PartitionTest(t)

	player, router, accounts, factory, ledger := testSetup(0)

	proposalVoteEventBatch, _, _ := createProposalEvents(t, player, accounts, factory, ledger)

	simulateProposalVotes(t, &router, &player, proposalVoteEventBatch)
}

func TestProposalFunctions(t *testing.T) {
	testpartitioning.PartitionTest(t)

	player, _, accs, factory, ledger := testSetup(0)
	round := player.Round
	period := player.Period
	ve, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", round, err)

	validator := testBlockValidator{}

	for i := range accs.addresses {
		proposal, proposalValue, _ := proposalForBlock(accs.addresses[i], accs.vrfs[i], ve, period, ledger)

		//validate returning unauthenticatedProposal from proposalPayload
		unauthenticatedProposalResult := proposal
		require.NotNil(t, unauthenticatedProposalResult)

		//  validate unauthenticatedProposal
		unauthenticatedProposal := proposal.u()
		validatedProposal, err := unauthenticatedProposal.validate(context.Background(), round, ledger, validator)
		require.NoError(t, err)
		require.NotNil(t, validatedProposal)

		// validate checking for corrupted digest
		digest := proposalValue.BlockDigest
		encDigest := proposalValue.EncodingDigest
		err = proposalValue.matches(digest, encDigest)
		require.NoError(t, err)

		err = proposalValue.matches(encDigest, encDigest)
		require.Error(t, err)

		err = proposalValue.matches(digest, digest)
		require.Error(t, err)

	}
}

func TestProposalUnauthenticated(t *testing.T) {
	testpartitioning.PartitionTest(t)

	player, _, accounts, factory, ledger := testSetup(0)

	round := player.Round
	period := player.Period
	testBlockFactory, err := factory.AssembleBlock(player.Round, time.Now().Add(time.Minute))
	require.NoError(t, err, "Could not generate a proposal for round %d: %v", round, err)

	validator := testBlockValidator{}

	accountIndex := 0

	proposal, _, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, period, ledger)
	accountIndex++

	// validate a good unauthenticated proposal
	unauthenticatedProposal := proposal.u()
	block := unauthenticatedProposal.Block
	require.NotNil(t, block)
	proposal, err = unauthenticatedProposal.validate(context.Background(), round, ledger, validator)
	require.NotNil(t, proposal)
	require.NoError(t, err)

	// test bad round number
	proposal, err = unauthenticatedProposal.validate(context.Background(), round+1, ledger, validator)
	require.Error(t, err)
	proposal, err = unauthenticatedProposal.validate(context.Background(), round, ledger, validator)
	require.NotNil(t, proposal)
	require.NoError(t, err)

	// validate a good unauthenticated proposal
	proposal, _, _ = proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, period, ledger)
	accountIndex++
	unauthenticatedProposal = proposal.u()
	block = unauthenticatedProposal.Block
	require.NotNil(t, block)

	// validate corruption of SeedProof
	proposal3, _, _ := proposalForBlock(accounts.addresses[accountIndex], accounts.vrfs[accountIndex], testBlockFactory, period, ledger)
	accountIndex++
	unauthenticatedProposal3 := proposal3.u()
	unauthenticatedProposal3.SeedProof = unauthenticatedProposal.SeedProof
	_, err = unauthenticatedProposal3.validate(context.Background(), round, ledger, validator)
	require.Error(t, err)
}

func unauthenticatedProposalBlockPanicWrapper(t *testing.T, message string, uap unauthenticatedProposal, validator BlockValidator) (block bookkeeping.Block) {
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() { block = uap.Block })
	logging.Base().SetOutput(os.Stderr)
	return
}
