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
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSignAndVerifyFalcon(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var seed FalconSeed
	SystemRNG.RandBytes(seed[:])
	key, err := GenerateFalconSigner(seed)
	a.NoError(err)

	msg := []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")
	byteSig, err := key.SignBytes(msg)
	a.NoError(err)

	verifier := key.GetVerifyingKey()
	err = verifier.GetVerifier().VerifyBytes(msg, byteSig)
	a.NoError(err)
}
