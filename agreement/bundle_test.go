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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testpartitioning"
)

// Test Bundle Creation
func TestBundleCreation(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)

	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	for s := 1; s <= 4; s++ {
		var votes []vote
		for i := range addresses {
			address := addresses[i]
			step := step(s)
			rv := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
			uv, err := makeVote(rv, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)

			vote, err := uv.verify(ledger)
			if err != nil {
				continue
			}

			votes = append(votes, vote)
		}

		ub := makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, nil)
		_, err := ub.verify(context.Background(), ledger, avv)
		require.NoError(t, err)
	}

}

// Test Bundle validation with Zero Votes
func TestBundleCreationWithZeroVotes(t *testing.T) {
	testpartitioning.PartitionTest(t)

	//ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	ledger, _, _, _ := readOnlyFixture100()

	var proposal proposalValue
	proposal.BlockDigest = randomBlockHash()

	var bundles []bundle
	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	for s := 1; s <= 5; s++ {
		var votes []vote
		// don't add any votes to the bundle to check non zero vote count validation

		var ub unauthenticatedBundle
		makeBundlePanicWrapper(t, "makeBundle: no votes present in bundle (len(equivocationVotes) =", proposal, votes, nil)

		bundle, err := ub.verify(context.Background(), ledger, avv)
		require.Error(t, err)

		bundles = append(bundles, bundle)
	}

	_ = bundles[0].u()
}

func makeBundlePanicWrapper(t *testing.T, message string, proposal proposalValue, votes []vote, equivocationVotes []equivocationVote) (uab unauthenticatedBundle) {
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() {
		uab = makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, equivocationVotes)
	})
	logging.Base().SetOutput(os.Stderr)

	return uab
}

//Test Bundle Creation with Validation for duplicate votes from same sender
func TestBundleCreationWithVotesFromSameAddress(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture10()
	round := ledger.NextRound()
	period := period(0)

	var proposal proposalValue
	var proposal2 proposalValue
	proposal.BlockDigest = randomBlockHash()
	proposal2.BlockDigest = randomBlockHash()

	for s := 1; s <= 5; s++ {
		var votes []vote
		var equivocationVotes []equivocationVote

		for i := range addresses {
			address := addresses[i]
			step := step(s)

			rv0 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
			uv0, err := makeVote(rv0, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote0, err := uv0.verify(ledger)
			if err != nil {
				continue
			}

			rv1 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal2}
			uv1, err := makeVote(rv1, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote1, err := uv1.verify(ledger)
			if err != nil {
				continue
			}

			if i < 4 {
				votes = append(votes, vote0)
				votes = append(votes, vote1)
			} else {

				unauthenticatedEquivocationVote := unauthenticatedEquivocationVote{
					Sender:    address,
					Round:     round,
					Period:    period,
					Step:      step,
					Cred:      uv1.Cred,
					Proposals: [2]proposalValue{vote0.R.Proposal, vote1.R.Proposal},
					Sigs:      [2]crypto.OneTimeSignature{vote0.Sig, vote1.Sig},
				}

				ev, err := unauthenticatedEquivocationVote.verify(ledger)
				require.NoError(t, err)

				equivocationVotes = append(equivocationVotes, ev)
			}
		}

		makeBundlePanicWrapper(t, "makeBundle: invalid vote passed into function", proposal, votes, equivocationVotes)

	}

}

//Test Bundle Creation with Validation
func TestBundleCreationWithEquivocationVotes(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture10()
	round := ledger.NextRound()
	period := period(0)

	var proposal proposalValue
	var proposal2 proposalValue
	proposal.BlockDigest = randomBlockHash()
	proposal2.BlockDigest = randomBlockHash()

	var unauthenticatedBundles []unauthenticatedBundle
	for s := 1; s <= 10; s++ {
		var votes []vote
		var equivocationVotes []equivocationVote

		for i := range addresses {
			address := addresses[i]
			step := step(s)

			rv0 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
			uv0, err := makeVote(rv0, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote0, err := uv0.verify(ledger)
			if err != nil {
				continue
			}

			rv1 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal2}
			uv1, err := makeVote(rv1, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote1, err := uv1.verify(ledger)
			if err != nil {
				continue
			}

			if i < 4 {
				votes = append(votes, vote0)

			} else {

				unauthenticatedEquivocationVote := unauthenticatedEquivocationVote{
					Sender:    address,
					Round:     round,
					Period:    period,
					Step:      step,
					Cred:      uv1.Cred,
					Proposals: [2]proposalValue{vote0.R.Proposal, vote1.R.Proposal},
					Sigs:      [2]crypto.OneTimeSignature{vote0.Sig, vote1.Sig},
				}

				ev, err := unauthenticatedEquivocationVote.verify(ledger)
				require.NoError(t, err)

				equivocationVotes = append(equivocationVotes, ev)
			}
		}

		ub := makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, equivocationVotes)
		unauthenticatedBundles = append(unauthenticatedBundles, ub)

	}
	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()

	for i := range unauthenticatedBundles {
		_, err := unauthenticatedBundles[i].verify(context.Background(), ledger, avv)
		require.NoError(t, err)
	}

	voteBadCredBundle := unauthenticatedBundles[0]
	voteBadCredBundle.Votes[0].Cred = committee.UnauthenticatedCredential{}
	_, err := voteBadCredBundle.verify(context.Background(), ledger, avv)
	require.Error(t, err)

	voteBadSenderBundle := unauthenticatedBundles[1]
	voteBadSenderBundle.Votes[0].Sender = basics.Address{}
	_, err = voteBadSenderBundle.verify(context.Background(), ledger, avv)
	require.Error(t, err)

	voteNoQuorumBundle := unauthenticatedBundles[2]
	voteNoQuorumBundle.Votes = voteNoQuorumBundle.Votes[:2]
	voteNoQuorumBundle.EquivocationVotes = voteNoQuorumBundle.EquivocationVotes[:2]
	_, err = voteNoQuorumBundle.verify(context.Background(), ledger, avv)
	require.Error(t, err)

	evBadCredBundle := unauthenticatedBundles[3]
	evBadCredBundle.EquivocationVotes[0].Cred = committee.UnauthenticatedCredential{}
	_, err = evBadCredBundle.verify(context.Background(), ledger, avv)
	require.Error(t, err)

	evBadEVBundle := unauthenticatedBundles[4]
	evBadEVBundle.EquivocationVotes[0].Sigs = [2]crypto.OneTimeSignature{{}, {}}
	_, err = evBadEVBundle.verify(context.Background(), ledger, avv)
	require.Error(t, err)

	duplicateVoteBundle := unauthenticatedBundles[5]
	duplicateVoteBundle.Votes = append(duplicateVoteBundle.Votes, duplicateVoteBundle.Votes[0])
	_, err = duplicateVoteBundle.verify(context.Background(), ledger, avv)
	require.Error(t, err)

	duplicateEquivocationVoteBundle := unauthenticatedBundles[6]
	duplicateEquivocationVoteBundle.EquivocationVotes = append(duplicateEquivocationVoteBundle.EquivocationVotes, duplicateEquivocationVoteBundle.EquivocationVotes[0])
	_, err = duplicateEquivocationVoteBundle.verify(context.Background(), ledger, avv)
	require.Error(t, err)

}

//Test Bundle Creation with Validation
func TestBundleCertificationWithEquivocationVotes(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture10()
	round := ledger.NextRound()
	period := period(0)

	var proposal proposalValue
	var proposal2 proposalValue
	proposal.BlockDigest = randomBlockHash()
	proposal2.BlockDigest = randomBlockHash()

	for s := 1; s <= 5; s++ {
		var votes []vote
		var equivocationVotes []equivocationVote

		for i := range addresses {
			address := addresses[i]
			step := step(s)

			rv0 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
			uv0, err := makeVote(rv0, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote0, err := uv0.verify(ledger)
			if err != nil {
				continue
			}

			rv1 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal2}
			uv1, err := makeVote(rv1, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote1, err := uv1.verify(ledger)
			if err != nil {
				continue
			}

			if i < 4 {
				votes = append(votes, vote0)

			} else {

				unauthenticatedEquivocationVote := unauthenticatedEquivocationVote{
					Sender:    address,
					Round:     round,
					Period:    period,
					Step:      step,
					Cred:      uv1.Cred,
					Proposals: [2]proposalValue{vote0.R.Proposal, vote1.R.Proposal},
					Sigs:      [2]crypto.OneTimeSignature{vote0.Sig, vote1.Sig},
				}

				ev, err := unauthenticatedEquivocationVote.verify(ledger)
				require.NoError(t, err)

				equivocationVotes = append(equivocationVotes, ev)
			}
		}

		ub := makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, equivocationVotes)
		if step(s) != cert {
			certificatePanicWrapper(t, "bundle.Certificate: expected step=cert but got step=", ub)
		} else {
			ub.Certificate()
		}

	}
}

func certificatePanicWrapper(t *testing.T, message string, ub unauthenticatedBundle) {
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() { ub.Certificate() })
	logging.Base().SetOutput(os.Stderr)
}

// Test Bundle Creation with Equivocation Votes under Quorum
func TestBundleCreationWithEquivocationVotesUnderQuorum(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)

	var proposal proposalValue
	var proposal2 proposalValue
	proposal.BlockDigest = randomBlockHash()
	proposal2.BlockDigest = randomBlockHash()

	for s := 1; s <= 5; s++ {
		var votes []vote

		for i := range addresses {
			address := addresses[i]
			step := step(s)

			rv0 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal}
			uv0, err := makeVote(rv0, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote0, err := uv0.verify(ledger)
			if err != nil {
				continue
			}

			rv1 := rawVote{Sender: address, Round: round, Period: period, Step: step, Proposal: proposal2}
			uv1, err := makeVote(rv1, otSecrets[i], vrfSecrets[i], ledger)
			require.NoError(t, err)
			vote1, err := uv1.verify(ledger)
			if err != nil {
				continue
			}

			votes = append(votes, vote0)
			votes = append(votes, vote1)

			unauthenticatedEquivocationVote := unauthenticatedEquivocationVote{
				Sender:    address,
				Round:     round,
				Period:    period,
				Step:      step,
				Cred:      uv1.Cred,
				Proposals: [2]proposalValue{vote0.R.Proposal, vote1.R.Proposal},
				Sigs:      [2]crypto.OneTimeSignature{vote0.Sig, vote1.Sig},
			}

			_, err = unauthenticatedEquivocationVote.verify(ledger)
			require.NoError(t, err)
		}

		// test with reduced number of votes that don't reach quorum
		makeBundlePanicWrapper(t, "makeBundle: invalid vote passed into function: expected proposal-value", proposal, votes, nil)
	}
}
