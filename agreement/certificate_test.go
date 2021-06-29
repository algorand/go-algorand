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
	"math/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testpartitioning"
)

func makeCertTesting(digest crypto.Digest, votes []vote, equiVotes []equivocationVote) Certificate {
	var proposal proposalValue
	proposal.BlockDigest = digest
	return makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, equiVotes).Certificate()
}

func verifyBundleAgainstLedger(b unauthenticatedBundle, l Ledger, avv *AsyncVoteVerifier) error {
	_, err := b.verify(context.Background(), l, avv)
	return err
}

func TestCertificateGoodCertificateBasic(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block := makeRandomBlock(1)

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, block.Digest())
		if err == nil {
			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
		}
	}

	cert := makeCertTesting(block.Digest(), votes, equiVotes)
	require.NotEqual(t, Certificate{}, cert)
	require.NoError(t, cert.claimsToAuthenticate(block))

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	require.NoError(t, cert.Authenticate(block, ledger, avv))
}

func TestCertificateGoodCertificateEarlyBreak(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block := makeRandomBlock(1)

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, block.Digest())
		if err == nil {
			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
		}
	}

	cert := makeCertTesting(block.Digest(), votes, equiVotes)
	require.NotEqual(t, Certificate{}, cert)
	require.NoError(t, cert.claimsToAuthenticate(block))

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	require.NoError(t, cert.Authenticate(block, ledger, avv))
}

func TestCertificateFinalCert(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block := makeRandomBlock(1)

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, block.Digest())
		if err == nil {
			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
		}
	}

	cert := makeCertTesting(block.Digest(), votes, equiVotes)
	require.NotEqual(t, Certificate{}, cert)
	require.NoError(t, cert.claimsToAuthenticate(block))

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	require.NoError(t, cert.Authenticate(block, ledger, avv))
}

func TestCertificateBadCertificateWithFakeDoubleVote(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block, lastHash := makeRandomBlock(1), randomBlockHash()

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	i := 0

	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, block.Digest())
		if err == nil {
			if i < 30 {
				votes = append(votes, vote)
			} else {
				v1, err1 := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, lastHash)
				v2, err2 := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, lastHash)

				require.NoError(t, err1)
				require.NoError(t, err2)

				// this is a faulty equivocationVote as the proposal values are the same
				ev := equivocationVote{
					Sender:    v1.R.Sender,
					Round:     v1.R.Round,
					Period:    v1.R.Period,
					Step:      v1.R.Step,
					Cred:      v1.Cred,
					Proposals: [2]proposalValue{v1.R.Proposal, v2.R.Proposal},
					Sigs:      [2]crypto.OneTimeSignature{v1.Sig, v2.Sig},
				}

				equiVotes = append(equiVotes, ev)
			}
			totalWeight += vote.Cred.Weight
			i++
		}
	}

	cert := makeCertTesting(block.Digest(), votes, equiVotes)
	require.NotEqual(t, Certificate{}, cert)

	require.NoError(t, cert.claimsToAuthenticate(block))
	require.True(t, len(cert.EquivocationVotes) > 0)
	require.True(t, len(cert.Votes) > 0)

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	require.Error(t, cert.Authenticate(block, ledger, avv))
}

func TestCertificateDifferentBlock(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block, lastHash := makeRandomBlock(1), randomBlockHash()

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, lastHash)
		if err == nil {
			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
		}
	}

	cert := makeCertTesting(lastHash, votes, equiVotes)
	bundle := unauthenticatedBundle(cert)
	require.NotEqual(t, Certificate{}, cert)

	require.Error(t, cert.claimsToAuthenticate(block))

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	require.NoError(t, verifyBundleAgainstLedger(bundle, ledger, avv))
	require.Error(t, cert.Authenticate(block, ledger, avv))
}

func TestCertificateNoCertStep(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block, _ := makeRandomBlock(1), randomBlockHash()

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, next, block.Digest())
		if err == nil {
			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
		}
	}

	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() { makeCertTesting(block.Digest(), votes, equiVotes) })
	logging.Base().SetOutput(os.Stderr)
}

func TestCertificateNotEnoughVotesToCert(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)

	var lastHash crypto.Digest
	rand.Read(lastHash[:])

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, lastHash)
		if err == nil {
			if cert.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], totalWeight+vote.Cred.Weight) {
				break
			}

			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
		}
	}

	var proposal proposalValue
	proposal.BlockDigest = lastHash
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() {
		makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, equiVotes).Certificate()
	})
	logging.Base().SetOutput(os.Stderr)
}

func TestCertificateCertWrongRound(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block := makeRandomBlock(1 - 1)

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64

	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, block.Digest())
		if err == nil {
			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
		}
	}

	cert := makeCertTesting(block.Digest(), votes, equiVotes)
	bundle := unauthenticatedBundle(cert)
	require.NotEqual(t, Certificate{}, cert)
	require.Error(t, cert.claimsToAuthenticate(block))

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	require.NoError(t, verifyBundleAgainstLedger(bundle, ledger, avv))
	require.Error(t, cert.Authenticate(block, ledger, avv))
}

func TestCertificateCertWithTooFewVotes(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block, _ := makeRandomBlock(1), randomBlockHash()

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64

	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, block.Digest())
		if err == nil {
			votes = append(votes, vote)
			totalWeight += vote.Cred.Weight
			break
		}
	}

	var proposal proposalValue
	proposal.BlockDigest = block.Digest()
	logging.Base().SetOutput(nullWriter{})
	require.Panics(t, func() {
		makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], proposal, votes, equiVotes).Certificate()
	})
	logging.Base().SetOutput(os.Stderr)
}

func TestCertificateDupVote(t *testing.T) {
	testpartitioning.PartitionTest(t)

	ledger, addresses, vrfSecrets, otSecrets := readOnlyFixture100()
	round := ledger.NextRound()
	period := period(0)
	block, _ := makeRandomBlock(1), randomBlockHash()

	votes := make([]vote, 0)
	equiVotes := make([]equivocationVote, 0)
	var totalWeight uint64
	i := 0

	for j, addr := range addresses {
		vote, err := makeVoteTesting(addr, vrfSecrets[j], otSecrets[j], ledger, round, period, cert, block.Digest())
		if err == nil {
			votes = append(votes, vote)
			if i == 0 {
				votes = append(votes, vote)
			}
			totalWeight += vote.Cred.Weight
			i++
		}
	}

	cert := makeCertTesting(block.Digest(), votes, equiVotes)
	bundle := unauthenticatedBundle(cert)
	require.NotEqual(t, Certificate{}, cert)
	require.NoError(t, cert.claimsToAuthenticate(block))

	avv := MakeAsyncVoteVerifier(nil)
	defer avv.Quit()
	require.Error(t, verifyBundleAgainstLedger(bundle, ledger, avv))
	require.Error(t, cert.Authenticate(block, ledger, avv))
}
