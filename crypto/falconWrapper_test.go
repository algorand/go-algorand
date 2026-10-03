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

// falconTestKey adapts a generated signer of one Falcon scheme to a
// byte-oriented API so the tests below can run identically against both
// schemes.
type falconTestKey struct {
	publicKey   []byte
	sign        func(message Hashable) ([]byte, error)
	signBytes   func(data []byte) ([]byte, error)
	verify      func(message Hashable, sig []byte) error
	verifyBytes func(data []byte, sig []byte) error
	// verifierRepr is GetVerifyingKey().GetFixedLengthHashableRepresentation().
	verifierRepr func() []byte
}

// falconTestScheme holds one Falcon scheme's constants and package-level
// entry points.
type falconTestScheme struct {
	name               string
	maxSignatureSize   int
	currentSaltVersion byte
	errSigInvalid      error
	generate           func(seed FalconSeed) (falconTestKey, error)
	verify             func(message Hashable, publicKey, signature []byte) error
	// convertToCT converts a compressed signature to CT form via the falcon
	// library directly, bypassing the wrapper.
	convertToCT        func(sig []byte) ([]byte, error)
	sigRepr            func(sig []byte) ([]byte, error)
	isSaltVersionEqual func(sig []byte, version byte) bool
}

var falconTestSchemes = []falconTestScheme{
	{
		name:               "falcon-1024",
		maxSignatureSize:   Falcon1024MaxSignatureSize,
		currentSaltVersion: falcon.CurrentSaltVersion,
		errSigInvalid:      ErrPQFalcon1024SigInvalid,
		generate: func(seed FalconSeed) (falconTestKey, error) {
			key, err := GenerateFalcon1024Signer(seed)
			if err != nil {
				return falconTestKey{}, err
			}
			verifier := key.GetVerifyingKey()
			return falconTestKey{
				publicKey:    key.PublicKey[:],
				sign:         func(message Hashable) ([]byte, error) { return key.Sign(message) },
				signBytes:    func(data []byte) ([]byte, error) { return key.SignBytes(data) },
				verify:       func(message Hashable, sig []byte) error { return verifier.Verify(message, sig) },
				verifyBytes:  func(data []byte, sig []byte) error { return verifier.VerifyBytes(data, sig) },
				verifierRepr: verifier.GetFixedLengthHashableRepresentation,
			}, nil
		},
		verify: VerifyFalcon1024,
		convertToCT: func(sig []byte) ([]byte, error) {
			falconSig := falcon.CompressedSignature(sig)
			ct, err := falconSig.ConvertToCT()
			return ct[:], err
		},
		sigRepr: func(sig []byte) ([]byte, error) {
			return Falcon1024Signature(sig).GetFixedLengthHashableRepresentation()
		},
		isSaltVersionEqual: func(sig []byte, version byte) bool {
			return Falcon1024Signature(sig).IsSaltVersionEqual(version)
		},
	},
	{
		name:               "falcon-512",
		maxSignatureSize:   Falcon512MaxSignatureSize,
		currentSaltVersion: falcon.Det512CurrentSaltVersion,
		errSigInvalid:      ErrPQFalcon512SigInvalid,
		generate: func(seed FalconSeed) (falconTestKey, error) {
			key, err := GenerateFalcon512Signer(seed)
			if err != nil {
				return falconTestKey{}, err
			}
			verifier := key.GetVerifyingKey()
			return falconTestKey{
				publicKey:    key.PublicKey[:],
				sign:         func(message Hashable) ([]byte, error) { return key.Sign(message) },
				signBytes:    func(data []byte) ([]byte, error) { return key.SignBytes(data) },
				verify:       func(message Hashable, sig []byte) error { return verifier.Verify(message, sig) },
				verifyBytes:  func(data []byte, sig []byte) error { return verifier.VerifyBytes(data, sig) },
				verifierRepr: verifier.GetFixedLengthHashableRepresentation,
			}, nil
		},
		verify: VerifyFalcon512,
		convertToCT: func(sig []byte) ([]byte, error) {
			falconSig := falcon.Det512CompressedSignature(sig)
			ct, err := falconSig.ConvertToCT()
			return ct[:], err
		},
		sigRepr: func(sig []byte) ([]byte, error) {
			return Falcon512Signature(sig).GetFixedLengthHashableRepresentation()
		},
		isSaltVersionEqual: func(sig []byte, version byte) bool {
			return Falcon512Signature(sig).IsSaltVersionEqual(version)
		},
	},
}

func TestSignAndVerifyFalcon(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, scheme := range falconTestSchemes {
		t.Run(scheme.name, func(t *testing.T) {
			a := require.New(t)

			var seed FalconSeed
			SystemRNG.RandBytes(seed[:])
			key, err := scheme.generate(seed)
			a.NoError(err)

			msg := []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")
			byteSig, err := key.signBytes(msg)
			a.NoError(err)

			err = key.verifyBytes(msg, byteSig)
			a.NoError(err)
		})
	}
}

func TestSignAndVerifyFalconHashable(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, scheme := range falconTestSchemes {
		t.Run(scheme.name, func(t *testing.T) {
			a := require.New(t)

			msg := TestingHashable{data: []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")}
			var seed FalconSeed
			SystemRNG.RandBytes(seed[:])
			key, err := scheme.generate(seed)
			a.NoError(err)

			byteSig, err := key.sign(msg)
			a.NoError(err)

			err = key.verify(msg, byteSig)
			a.NoError(err)
		})
	}
}

func TestVerifyFalconRejectsMalformedInputs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, scheme := range falconTestSchemes {
		t.Run(scheme.name, func(t *testing.T) {
			t.Parallel()

			msg := TestingHashable{data: []byte("verify falcon malformed inputs")}
			var seed FalconSeed
			seed[0] = 1
			key, err := scheme.generate(seed)
			require.NoError(t, err)

			signature, err := key.sign(msg)
			require.NoError(t, err)

			longPublicKey := append([]byte{}, key.publicKey...)
			longPublicKey = append(longPublicKey, 0)

			tests := []struct {
				name      string
				publicKey []byte
				signature []byte
			}{
				{
					name:      "short public key",
					publicKey: key.publicKey[:len(key.publicKey)-1],
					signature: signature,
				},
				{
					name:      "long public key",
					publicKey: longPublicKey,
					signature: signature,
				},
				{
					name:      "empty signature",
					publicKey: key.publicKey,
					signature: nil,
				},
				{
					name:      "oversized signature",
					publicKey: key.publicKey,
					signature: make([]byte, scheme.maxSignatureSize+1),
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()

					err := scheme.verify(msg, test.publicKey, test.signature)
					require.ErrorIs(t, err, scheme.errSigInvalid)
				})
			}
		})
	}
}

func TestFalconCanHandleNilSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, scheme := range falconTestSchemes {
		t.Run(scheme.name, func(t *testing.T) {
			a := require.New(t)

			var seed FalconSeed
			SystemRNG.RandBytes(seed[:])
			key, err := scheme.generate(seed)
			a.NoError(err)

			err = key.verifyBytes([]byte("Test"), nil)
			a.ErrorIs(err, falcon.ErrVerifyFail)
		})
	}
}

func TestVerificationBytes(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, scheme := range falconTestSchemes {
		t.Run(scheme.name, func(t *testing.T) {
			a := require.New(t)

			var seed FalconSeed
			SystemRNG.RandBytes(seed[:])
			key, err := scheme.generate(seed)
			a.NoError(err)

			verifyingRawKey := key.verifierRepr()
			a.Equal(verifyingRawKey, key.publicKey)
		})
	}
}

func TestFalconsFormatConversion(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, scheme := range falconTestSchemes {
		t.Run(scheme.name, func(t *testing.T) {
			a := require.New(t)

			var seed FalconSeed
			SystemRNG.RandBytes(seed[:])
			key, err := scheme.generate(seed)
			a.NoError(err)

			msg := []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")
			sig, err := key.signBytes(msg)
			a.NoError(err)

			ctFormat, err := scheme.convertToCT(sig)
			a.NoError(err)

			rawFormat, err := scheme.sigRepr(sig)
			a.NoError(err)
			a.NotEqual(sig, rawFormat)

			a.Equal(ctFormat, rawFormat)
		})
	}
}

func TestFalconSignature_ValidateVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, scheme := range falconTestSchemes {
		t.Run(scheme.name, func(t *testing.T) {
			a := require.New(t)

			msg := TestingHashable{data: []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet")}
			var seed FalconSeed
			SystemRNG.RandBytes(seed[:])
			key, err := scheme.generate(seed)
			a.NoError(err)

			byteSig, err := key.sign(msg)
			a.NoError(err)

			a.True(scheme.isSaltVersionEqual(byteSig, scheme.currentSaltVersion))

			byteSig[1]++
			a.False(scheme.isSaltVersionEqual(byteSig, scheme.currentSaltVersion))
		})
	}
}
