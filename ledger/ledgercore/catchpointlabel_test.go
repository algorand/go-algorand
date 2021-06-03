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

package ledgercore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

func TestUniqueCatchpointLabel(t *testing.T) {
	uniqueSet := make(map[string]bool)

	ledgerRoundBlockHashes := []crypto.Digest{}
	balancesMerkleRoots := []crypto.Digest{}
	totals := []AccountTotals{}
	for i := 0; i < 10; i++ {
		ledgerRoundBlockHashes = append(ledgerRoundBlockHashes, crypto.Hash([]byte{byte(i)}))
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
				for _, total := range totals {
					label := MakeCatchpointLabel(r, ledgerRoundHash, balancesMerkleRoot, total)
					require.False(t, uniqueSet[label.String()])
					uniqueSet[label.String()] = true
				}
			}
		}
	}
}

func TestCatchpointLabelParsing(t *testing.T) {
	ledgerRoundBlockHashes := []crypto.Digest{}
	balancesMerkleRoots := []crypto.Digest{}
	totals := []AccountTotals{}
	for i := 0; i < 10; i++ {
		ledgerRoundBlockHashes = append(ledgerRoundBlockHashes, crypto.Hash([]byte{byte(i)}))
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
				for _, total := range totals {
					label := MakeCatchpointLabel(r, ledgerRoundHash, balancesMerkleRoot, total)
					parsedRound, parsedHash, err := ParseCatchpointLabel(label.String())
					require.Equal(t, r, parsedRound)
					require.NotEqual(t, crypto.Digest{}, parsedHash)
					require.NoError(t, err)
				}
			}
		}
	}
}
func TestCatchpointLabelParsing2(t *testing.T) {
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
