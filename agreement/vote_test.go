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
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
)

// error is set if this address is not selected
func makeVoteTesting(addr basics.Address, vrfSecs *crypto.VRFSecrets, otSecs crypto.OneTimeSigner, ledger Ledger, round basics.Round, period period, step step, digest crypto.Digest) (vote, error) {
	var proposal proposalValue
	proposal.BlockDigest = digest
	rv := rawVote{Sender: addr, Round: round, Period: period, Step: step, Proposal: proposal}
	v, fatalerr := makeVote(rv, otSecs, vrfSecs, ledger)
	if fatalerr != nil {
		panic(fatalerr)
	}
	return v.verify(ledger)
}

func TestVoteValidation(t *testing.T) {
   testPartitioning.PartitionTest(t)

	numAddresses := 50
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	var processedVote = false

	for i, address := range addresses[:numAddresses] {
		var proposal proposalValue
		proposal.BlockDigest = randomBlockHash()
		proposal.OriginalProposer = address
		rv := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal}
		unauthenticatedVote, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
		require.NoError(t, err)

		m, err := membership(ledger, address, round, period, step(i))
		require.NoError(t, err)

		//loop to find votes selected to participate
		_, err = unauthenticatedVote.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)
		selected := err == nil
		if selected {
			processedVote = true
			av, err := unauthenticatedVote.verify(ledger)
			require.NoError(t, err)

			require.Equal(t, av.R.Round, round)
			require.Equal(t, av.R.Period, period)
			require.Equal(t, av.R.Step, step(i))

			unauthenticatedVote := av.u()
			require.NotNil(t, unauthenticatedVote)

			noSig := unauthenticatedVote
			noSig.Sig = crypto.OneTimeSignature{}
			_, err = noSig.verify(ledger)
			require.Error(t, err)

			noCred := unauthenticatedVote
			noCred.Cred = committee.UnauthenticatedCredential{}
			_, err = noCred.verify(ledger)
			require.Error(t, err)

			badRound := unauthenticatedVote
			badRound.R.Round++
			_, err = badRound.verify(ledger)
			require.Error(t, err)

			badPeriod := unauthenticatedVote
			badPeriod.R.Period++
			_, err = badPeriod.verify(ledger)
			require.Error(t, err)

			badStep := unauthenticatedVote
			badStep.R.Step++
			_, err = badStep.verify(ledger)
			require.Error(t, err)

			badBlockHash := unauthenticatedVote
			badBlockHash.R.Proposal.BlockDigest = randomBlockHash()
			_, err = badBlockHash.verify(ledger)
			require.Error(t, err)

			badProposer := unauthenticatedVote
			badProposer.R.Proposal.OriginalProposer = basics.Address(randomBlockHash())
			_, err = badProposer.verify(ledger)
			require.Error(t, err)
		}
	}
	require.True(t, processedVote, "No votes were processed")
}

func TestVoteReproposalValidation(t *testing.T) {
   testPartitioning.PartitionTest(t)

	numAddresses := 50
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	per := period(1)
	var processedVote = false

	for i, address := range addresses[:numAddresses] {
		var proposal proposalValue
		proposal.BlockDigest = randomBlockHash()
		proposal.OriginalProposer = address
		proposal.OriginalPeriod = per
		rv := rawVote{Sender: address, Round: round, Period: per, Step: step(0), Proposal: proposal}
		unauthenticatedVote, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
		require.NoError(t, err)

		m, err := membership(ledger, address, round, per, step(0))
		require.NoError(t, err)

		//loop to find votes selected to participate
		_, err = unauthenticatedVote.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)
		selected := err == nil
		if selected {
			processedVote = true
			_, err := unauthenticatedVote.verify(ledger)
			require.NoError(t, err)

			// good period-1 reproposal for a period-0 original proposal
			rv = rawVote{Sender: address, Round: round, Period: per, Step: step(0), Proposal: proposal}
			rv.Proposal.OriginalPeriod = period(0)
			rv.Proposal.OriginalProposer = basics.Address(randomBlockHash())
			reproposalVote, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			_, err = reproposalVote.verify(ledger)
			require.NoError(t, err)

			// bad period-1 fresh proposal because original proposer is not sender
			rv = rawVote{Sender: address, Round: round, Period: per, Step: step(0), Proposal: proposal}
			rv.Proposal.OriginalPeriod = period(1)
			rv.Proposal.OriginalProposer = basics.Address(randomBlockHash())
			badReproposalVote, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			_, err = badReproposalVote.verify(ledger)
			require.Error(t, err)

			// bad period-1 reproposal for a period 2 original proposal
			rv = rawVote{Sender: address, Round: round, Period: per, Step: step(0), Proposal: proposal}
			rv.Proposal.OriginalPeriod = period(2)
			rv.Proposal.OriginalProposer = address
			badReproposalVote, err = makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			_, err = badReproposalVote.verify(ledger)
			require.Error(t, err)
		}
	}
	require.True(t, processedVote, "No votes were processed")
}

func TestVoteMakeVote(t *testing.T) {
   testPartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()

	round := ledger.NextRound()
	period := period(0)
	addressIndex := 0

	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()

	address := addresses[addressIndex]
	rv := rawVote{Sender: address, Round: round, Period: period, Step: step(addressIndex), Proposal: proposal}
	unauthenticatedVote, err := makeVote(rv, otSecrets[addressIndex], vrfSecrets[addressIndex], ledger)
	require.NoError(t, err)
	require.NotNil(t, unauthenticatedVote)

	addressIndex++
	address = addresses[addressIndex]

	// TODO, fail membership and one time signature
	rv = rawVote{Sender: basics.Address{}, Round: round, Period: period, Step: step(addressIndex), Proposal: proposal}
	unauthenticatedVote, err = makeVote(rv, otSecrets[addressIndex], vrfSecrets[addressIndex], ledger)
	//require.Error(t, err)

	//  creating a vote in cert and bottom mode results in panic.
	addressIndex++
	address = addresses[addressIndex]
	rv = rawVote{Sender: address, Round: round, Period: period, Step: cert, Proposal: bottom}
	makeVotePanicWrapper(t, "makeVote: votes from step 2 cannot validate bottom", rv, otSecrets[addressIndex], vrfSecrets[addressIndex], ledger)

}

func makeVotePanicWrapper(t *testing.T, message string, rv rawVote, voting crypto.OneTimeSigner, selection *crypto.VRFSecrets, l Ledger) (uav unauthenticatedVote, err error) {
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() { uav, err = makeVote(rv, voting, selection, l) })
	logging.Base().SetOutput(os.Stderr)
	return
}

func TestVoteValidationStepCertAndProposalBottom(t *testing.T) {
   testPartitioning.PartitionTest(t)


	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)

	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()

	for i, address := range addresses {

		//  creating a vote in cert and bottom mode results in panic.
		rawVote := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal}
		unauthenticatedVote, err := makeVote(rawVote, otSecrets[i], vrfSecrets[i], ledger)

		_, err = unauthenticatedVote.verify(ledger)
		//loop to find votes selected to participate
		selected := err == nil
		if selected {

			unauthenticatedVote.R.Step = cert
			unauthenticatedVote.R.Proposal = bottom
			_, err = unauthenticatedVote.verify(ledger)
			require.Error(t, err)

		}
	}
}

// Test Equivocation Vote Validation
func TestEquivocationVoteValidation(t *testing.T) {
   testPartitioning.PartitionTest(t)

	numAddresses := 50
	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)

	var processedVote = false
	for i, address := range addresses[:numAddresses] {
		var proposal1 proposalValue
		proposal1.BlockDigest = randomBlockHash()
		rv0 := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal1}
		unauthenticatedVote0, err := makeVote(rv0, otSecrets[i], vrfSecrets[i], ledger)
		require.NoError(t, err)

		rv0Copy := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal1}
		unauthenticatedVote0Copy, err := makeVote(rv0Copy, otSecrets[i], vrfSecrets[i], ledger)
		require.NoError(t, err)

		var proposal2 proposalValue
		proposal2.BlockDigest = randomBlockHash()
		rv1 := rawVote{Sender: address, Round: round, Period: period, Step: step(i), Proposal: proposal2}
		unauthenticatedVote1, err := makeVote(rv1, otSecrets[i], vrfSecrets[i], ledger)
		require.NoError(t, err)

		m, err := membership(ledger, address, round, period, step(i))
		require.NoError(t, err)
		require.NotNil(t, m, "membership should not be nil")

		ev := unauthenticatedEquivocationVote{
			Sender:    address,
			Round:     round,
			Period:    period,
			Step:      step(i),
			Cred:      unauthenticatedVote0.Cred,
			Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote1.R.Proposal},
			Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote1.Sig},
		}

		evSameVote := unauthenticatedEquivocationVote{
			Sender:    address,
			Round:     round,
			Period:    period,
			Step:      step(i),
			Cred:      unauthenticatedVote0.Cred,
			Proposals: [2]proposalValue{unauthenticatedVote0.R.Proposal, unauthenticatedVote0Copy.R.Proposal},
			Sigs:      [2]crypto.OneTimeSignature{unauthenticatedVote0.Sig, unauthenticatedVote0Copy.Sig},
		}

		require.NotNil(t, ev, "unauthenticated equivocation vote should not be null")
		_, err = ev.verify(ledger)
		//loop to find votes selected to participate
		selected := err == nil
		if selected {
			processedVote = true
			aev, err := ev.verify(ledger)
			require.NoError(t, err)
			require.NotNil(t, aev, "authenticated equivocation vote should not be null")

			// check for same vote
			_, err = evSameVote.verify(ledger)
			require.Error(t, err)

			// test vote accessors
			v0 := aev.v0()
			require.NotNil(t, v0)
			_, err = v0.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)

			v1 := aev.v1()
			require.NotNil(t, v1)
			_, err = v1.Cred.Verify(config.Consensus[protocol.ConsensusCurrentVersion], m)

			noSig := ev
			noSig.Sigs = [2]crypto.OneTimeSignature{{}, {}}
			_, err = noSig.verify(ledger)
			require.Error(t, err)

			noCred := ev
			noCred.Cred = committee.UnauthenticatedCredential{}
			_, err = noCred.verify(ledger)
			require.Error(t, err)

			badRound := ev
			badRound.Round++
			_, err = badRound.verify(ledger)
			require.Error(t, err)

			badPeriod := ev
			badPeriod.Period++
			_, err = badPeriod.verify(ledger)
			require.Error(t, err)

			badStep := ev
			badStep.Step++
			_, err = badStep.verify(ledger)
			require.Error(t, err)

			badBlockHash1 := ev
			badBlockHash1.Proposals[0].BlockDigest = randomBlockHash()
			_, err = badBlockHash1.verify(ledger)
			require.Error(t, err)

			badBlockHash2 := ev
			badBlockHash2.Proposals[1].BlockDigest = randomBlockHash()
			_, err = badBlockHash2.verify(ledger)
			require.Error(t, err)

			badSender := ev
			badSender.Sender = basics.Address{}
			_, err = badSender.verify(ledger)
			require.Error(t, err)
		}
	}
	require.True(t, processedVote, "No votes were processed")
}
