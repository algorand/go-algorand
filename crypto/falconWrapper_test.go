// Copyright (C) 2019-2023 Algorand, Inc.
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

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
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
	err = verifier.VerifyBytes(msg, byteSig)
	a.NoError(err)
}

func TestSignAndVerifyFalconHashable(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	msg := TestingHashable{data: []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")}
	var seed FalconSeed
	SystemRNG.RandBytes(seed[:])
	key, err := GenerateFalconSigner(seed)
	a.NoError(err)

	byteSig, err := key.Sign(msg)
	a.NoError(err)

	verifier := key.GetVerifyingKey()
	err = verifier.Verify(msg, byteSig)
	a.NoError(err)
}

func TestFalconCanHandleNilSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var seed FalconSeed
	SystemRNG.RandBytes(seed[:])
	key, err := GenerateFalconSigner(seed)
	a.NoError(err)

	err = key.GetVerifyingKey().VerifyBytes([]byte("Test"), nil)
	a.Error(err)
}

func TestVerificationBytes(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var seed FalconSeed
	SystemRNG.RandBytes(seed[:])
	key, err := GenerateFalconSigner(seed)
	a.NoError(err)

	verifyingRawKey := key.GetVerifyingKey().GetFixedLengthHashableRepresentation()

	a.Equal(verifyingRawKey, key.PublicKey[:])
}

func TestFalconsFormatConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var seed FalconSeed
	SystemRNG.RandBytes(seed[:])
	key, err := GenerateFalconSigner(seed)
	a.NoError(err)

	msg := []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")
	sig, err := key.SignBytes(msg)
	a.NoError(err)

	falconSig := falcon.CompressedSignature(sig)
	ctFormat, err := falconSig.ConvertToCT()

	rawFormat, err := sig.GetFixedLengthHashableRepresentation()
	a.NoError(err)
	a.NotEqual([]byte(sig), rawFormat)

	a.Equal(ctFormat[:], rawFormat)
}

func TestFalconSignature_ValidateVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	msg := TestingHashable{data: []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")}
	var seed FalconSeed
	SystemRNG.RandBytes(seed[:])
	key, err := GenerateFalconSigner(seed)
	a.NoError(err)

	byteSig, err := key.Sign(msg)
	a.NoError(err)

	a.True(byteSig.IsSaltVersionEqual(falcon.CurrentSaltVersion))

	byteSig[1]++
	a.False(byteSig.IsSaltVersionEqual(falcon.CurrentSaltVersion))
}
