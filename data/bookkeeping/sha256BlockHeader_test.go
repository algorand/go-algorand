// Copyright (C) 2019-2022 Algorand, Inc.
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

package bookkeeping

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConvertSha256Header(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var gh crypto.Digest
	crypto.RandBytes(gh[:])

	var txnCommit TxnCommitments
	crypto.RandBytes(txnCommit.Sha256Commitment[:])
	blockHeader := BlockHeader{Round: 200, GenesisHash: gh, TxnCommitments: txnCommit}
	sha256Header := blockHeader.ToSha256BlockHeader()

	a.Equal(basics.Round(200), sha256Header.RoundNumber)
	a.Equal(txnCommit.Sha256Commitment[:], []byte(sha256Header.Sha256TxnCommitment))
	a.Equal(gh, sha256Header.GenesisHash)
}
