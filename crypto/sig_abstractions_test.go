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

package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestInvalidSinger(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sigAlgo, err := NewSigner(Ed25519Type)
	a.NoError(err)
	sigAlgo.Type = MaxAlgorithmType

	dummyMsg := make([]byte, 6)
	_, err = sigAlgo.GetSigner().SignBytes(dummyMsg)
	a.Error(err)

	dummySig := make([]byte, 6)
	a.Error(sigAlgo.GetSigner().GetVerifyingKey().GetVerifier().VerifyBytes(dummyMsg, dummySig))

	sigAlgo, err = NewSigner(FalconType)
	a.NoError(err)
	sigAlgo.Type = MaxAlgorithmType

	dummyMsg = make([]byte, 6)

	_, err = sigAlgo.GetSigner().SignBytes(dummyMsg)
	a.Error(err)

	dummySig = make([]byte, 6)
	a.Error(sigAlgo.GetSigner().GetVerifyingKey().GetVerifier().VerifyBytes(dummyMsg, dummySig))
}
