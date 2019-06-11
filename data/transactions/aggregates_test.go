// Copyright (C) 2019 Algorand, Inc.
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

func TestPaysetCommitsToTxnOrder(t *testing.T) {
	for _, flat := range []bool{true, false} {
		_, stxns, _, _ := generateTestObjects(50, 50)
		var stxnb []SignedTxnInBlock
		for _, stxn := range stxns {
			stxnb = append(stxnb, SignedTxnInBlock{
				SignedTxnWithAD: SignedTxnWithAD{
					SignedTxn: stxn,
				},
			})
		}
		payset := Payset(stxnb)
		commit1 := payset.Commit(flat)
		payset[0], payset[1] = payset[1], payset[0]
		commit2 := payset.Commit(flat)
		require.NotEqual(t, commit1, commit2)
	}
}

func TestPaysetDoesNotCommitToSignatures(t *testing.T) {
	_, stxns, _, _ := generateTestObjects(50, 50)
	var stxnb []SignedTxnInBlock
	for _, stxn := range stxns {
		stxnb = append(stxnb, SignedTxnInBlock{
			SignedTxnWithAD: SignedTxnWithAD{
				SignedTxn: stxn,
			},
		})
	}
	payset := Payset(stxnb)
	commit1 := payset.Commit(false)
	payset[0].SignedTxn.MessUpSigForTesting()
	commit2 := payset.Commit(false)
	require.Equal(t, commit1, commit2)
}
