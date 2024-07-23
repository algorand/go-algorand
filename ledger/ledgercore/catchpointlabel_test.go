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

package ledgercore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestUniqueCatchpointLabel(t *testing.T) {
	partitiontest.PartitionTest(t)

	uniqueSet := make(map[string]bool)

	ledgerRoundBlockHashes := []crypto.Digest{}
	stateProofVerificationContextHashes := []crypto.Digest{}
	balancesMerkleRoots := []crypto.Digest{}
	totals := []AccountTotals{}
	for i := 0; i < 10; i++ {
		ledgerRoundBlockHashes = append(ledgerRoundBlockHashes, crypto.Hash([]byte{byte(i)}))
		stateProofVerificationContextHashes = append(stateProofVerificationContextHashes, crypto.Hash([]byte{byte(i), byte(1)}))
		balancesMerkleRoots = append(balancesMerkleRoots, crypto.Hash([]byte{byte(i), byte(i), byte(1)}))
		totals = append(totals,
			AccountTotals{
				RewardsLevel: uint64(i * 500000),
			},
		)
	}

	for r := basics.Round(0); r <= basics.Round(100); r += basics.Round(7) {
		for _, ledgerRoundHash := range ledgerRoundBlockHashes {
			for _, balancesMerkleRoot := range balancesMerkleRoots {
				for _, stateProofVerificationContextHash := range stateProofVerificationContextHashes {
					for _, total := range totals {
						labelMaker := MakeCatchpointLabelMakerCurrent(r, &ledgerRoundHash, &balancesMerkleRoot, total, &stateProofVerificationContextHash)
						labelString := MakeLabel(labelMaker)
						require.False(t, uniqueSet[labelString])
						uniqueSet[labelString] = true
					}
				}
			}
		}
	}
}

func TestCatchpointLabelParsing(t *testing.T) {
	partitiontest.PartitionTest(t)

	ledgerRoundBlockHashes := []crypto.Digest{}
	stateProofVerificationContextHashes := []crypto.Digest{}
	balancesMerkleRoots := []crypto.Digest{}
	totals := []AccountTotals{}
	for i := 0; i < 10; i++ {
		ledgerRoundBlockHashes = append(ledgerRoundBlockHashes, crypto.Hash([]byte{byte(i)}))
		stateProofVerificationContextHashes = append(stateProofVerificationContextHashes, crypto.Hash([]byte{byte(i), byte(1)}))
		balancesMerkleRoots = append(balancesMerkleRoots, crypto.Hash([]byte{byte(i), byte(i), byte(1)}))
		totals = append(totals,
			AccountTotals{
				RewardsLevel: uint64(i * 500000),
			},
		)
	}

	for r := basics.Round(0); r <= basics.Round(100); r += basics.Round(7) {
		for _, ledgerRoundHash := range ledgerRoundBlockHashes {
			for _, balancesMerkleRoot := range balancesMerkleRoots {
				for _, stateProofVerificationContextHash := range stateProofVerificationContextHashes {
					for _, total := range totals {
						labelMaker := MakeCatchpointLabelMakerCurrent(r, &ledgerRoundHash, &balancesMerkleRoot, total, &stateProofVerificationContextHash)
						labelString := MakeLabel(labelMaker)
						parsedRound, parsedHash, err := ParseCatchpointLabel(labelString)
						require.Equal(t, r, parsedRound)
						require.NotEqual(t, crypto.Digest{}, parsedHash)
						require.NoError(t, err)
					}
				}
			}
		}
	}
}
func TestCatchpointLabelParsing2(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, _, err := ParseCatchpointLabel("5893060#KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJAB")
	require.Error(t, err)
	_, _, err = ParseCatchpointLabel("5893060KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJA")
	require.Error(t, err)
	_, _, err = ParseCatchpointLabel("5893060##KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJA")
	require.Error(t, err)
	_, _, err = ParseCatchpointLabel("5x893060#KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJA")
	require.Error(t, err)
	_, _, err = ParseCatchpointLabel("-5893060#KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJA")
	require.Error(t, err)
	_, _, err = ParseCatchpointLabel("5893060#aURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJA")
	require.Error(t, err)
}
