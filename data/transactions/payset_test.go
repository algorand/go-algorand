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

package transactions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func preparePayset(txnCount, acctCount int) Payset {
	_, stxns, _, _ := generateTestObjects(txnCount, acctCount)
	var stxnb []SignedTxnInBlock
	for _, stxn := range stxns {
		stxnb = append(stxnb, SignedTxnInBlock{
			SignedTxnWithAD: SignedTxnWithAD{
				SignedTxn: stxn,
			},
		})
	}
	return Payset(stxnb)
}
func TestPaysetCommitsToTxnOrder(t *testing.T) {
	for _, flat := range []bool{true, false} {
		payset := preparePayset(50, 50)
		commit1 := payset.Commit(flat)
		payset[0], payset[1] = payset[1], payset[0]
		commit2 := payset.Commit(flat)
		require.NotEqual(t, commit1, commit2)
	}
}

func TestPaysetDoesNotCommitToSignatures(t *testing.T) {
	payset := preparePayset(50, 50)
	commit1 := payset.Commit(false)
	payset[0].SignedTxn.MessUpSigForTesting()
	commit2 := payset.Commit(false)
	require.Equal(t, commit1, commit2)
}

func TestEmptyPaysetCommitment(t *testing.T) {
	const nilFlatPaysetHash = "WRS2VL2OQ5LPWBYLNBCZV3MEQ4DACSRDES6IUKHGOWYQERJRWC5A"
	const emptyFlatPaysetHash = "E54GFMNS2LISPG5VUGOQ3B2RR7TRKAHRE24LUM3HOW6TJGQ6PNZQ"
	const merklePaysetHash = "4OYMIQUY7QOBJGX36TEJS35ZEQT24QPEMSNZGTFESWMRW6CSXBKQ"

	// Non-genesis blocks should encode empty paysets identically to nil paysets
	var nilPayset Payset
	require.Equal(t, nilFlatPaysetHash, Payset{}.Commit(true).String())
	require.Equal(t, nilFlatPaysetHash, nilPayset.Commit(true).String())

	// Genesis block should encode the empty payset differently
	require.Equal(t, emptyFlatPaysetHash, Payset{}.CommitGenesis(true).String())
	require.Equal(t, nilFlatPaysetHash, nilPayset.CommitGenesis(true).String())

	// Non-flat paysets (which we have dropped support for) should encode
	// the same regardless of nilness or if this is a genesis block
	require.Equal(t, merklePaysetHash, Payset{}.CommitGenesis(false).String())
	require.Equal(t, merklePaysetHash, nilPayset.CommitGenesis(false).String())
	require.Equal(t, merklePaysetHash, Payset{}.Commit(false).String())
	require.Equal(t, merklePaysetHash, nilPayset.Commit(false).String())
}

func BenchmarkCommit(b *testing.B) {
	payset := preparePayset(5000, 50)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payset.Commit(true)
	}
	b.ReportMetric(float64(len(payset)), "transactions/block")
}

func BenchmarkToBeHashed(b *testing.B) {
	payset := preparePayset(5000, 50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payset.ToBeHashed()
	}
	b.ReportMetric(float64(len(payset)), "transactions/block")
}
