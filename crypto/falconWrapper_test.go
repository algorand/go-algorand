// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/algorand/falcon"

	"github.com/algorand/go-algorand/test/partitiontest"
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

func TestVerifyFalcon1024RejectsMalformedInputs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	msg := TestingHashable{data: []byte("verify falcon-1024 malformed inputs")}
	var seed FalconSeed
	seed[0] = 1
	signer, err := GenerateFalconSigner(seed)
	require.NoError(t, err)

	signature, err := signer.Sign(msg)
	require.NoError(t, err)

	longPublicKey := append([]byte{}, signer.PublicKey[:]...)
	longPublicKey = append(longPublicKey, 0)

	tests := []struct {
		name      string
		publicKey []byte
		signature []byte
	}{
		{
			name:      "short public key",
			publicKey: signer.PublicKey[:len(signer.PublicKey)-1],
			signature: signature,
		},
		{
			name:      "long public key",
			publicKey: longPublicKey,
			signature: signature,
		},
		{
			name:      "empty signature",
			publicKey: signer.PublicKey[:],
			signature: nil,
		},
		{
			name:      "oversized signature",
			publicKey: signer.PublicKey[:],
			signature: make([]byte, FalconMaxSignatureSize+1),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := VerifyFalcon1024(msg, test.publicKey, test.signature)
			require.ErrorIs(t, err, ErrPQFalcon1024SigInvalid)
		})
	}
}

func TestFalconCanHandleNilSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var seed FalconSeed
	SystemRNG.RandBytes(seed[:])
	key, err := GenerateFalconSigner(seed)
	a.NoError(err)

	err = key.GetVerifyingKey().VerifyBytes([]byte("Test"), nil)
	require.ErrorIs(t, err, falcon.ErrVerifyFail)
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
