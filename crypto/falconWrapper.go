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

package crypto

import (
	cfalcon "github.com/algorand/falcon"
)

const (
	// FalconSeedSize Represents the size in bytes of the random bytes used to generate Falcon keys
	FalconSeedSize = 48

	// FalconSigSize is the size of a falcon signature
	FalconSigSize = cfalcon.SigSize
)

type (
	// FPublicKey is a wrapper for cfalcon.PublicKeySizey (used for packing)
	FPublicKey [cfalcon.PublicKeySize]byte
	// FSecretKey is a wrapper for cfalcon.PrivateKeySize (used for packing)
	FSecretKey [cfalcon.PrivateKeySize]byte
	// FalconSeed represents the seed which is being used to generate Falcon keys
	FalconSeed [FalconSeedSize]byte
)

// FalconSigner is the implementation of Signer for the Falcon signature scheme.
type FalconSigner struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey FPublicKey `codec:"pk"`
	SecretKey FSecretKey `codec:"sk"`
}

// GenerateFalconSigner Generates a Falcon Signer.
func GenerateFalconSigner(seed FalconSeed) (FalconSigner, error) {
	sk, pk, err := cfalcon.GenerateKey(seed[:])
	return FalconSigner{
		PublicKey: FPublicKey(pk),
		SecretKey: FSecretKey(sk),
	}, err
}

// Sign receives a message and generates a signature over that message.
func (d *FalconSigner) Sign(message Hashable) (ByteSignature, error) {
	hs := Hash(HashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
func (d *FalconSigner) SignBytes(data []byte) (ByteSignature, error) {
	return (*cfalcon.FalconPrivateKey)(&d.SecretKey).SignBytes(data)
}

// GetVerifyingKey Outputs a verifying key object which is serializable.
func (d *FalconSigner) GetVerifyingKey() *GenericVerifyingKey {
	return &GenericVerifyingKey{
		Type:            FalconType,
		FalconPublicKey: FalconVerifier{PublicKey: d.PublicKey},
	}
}

// FalconVerifier implements the type Verifier interface for the falcon signature scheme.
type FalconVerifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey FPublicKey `codec:"k"`
}

// Verify follows falcon algorithm to verify a signature.
func (d *FalconVerifier) Verify(message Hashable, sig ByteSignature) error {
	hs := Hash(HashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func (d *FalconVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	return (*cfalcon.FalconPublicKey)(&d.PublicKey).VerifyBytes(data, sig)
}
