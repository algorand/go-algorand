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
	cfalcon "github.com/algoidan/falcon"
)

const (
	// FalconSeedSize Represents the size in bytes of the random bytes used to generate Falcon keys
	FalconSeedSize = 48

	// FalconMaxSignatureSize Represents the max possible size in bytes of a falcon signature
	FalconMaxSignatureSize = cfalcon.CTSignatureSize
)

type (
	// FalconPublicKey is a wrapper for cfalcon.PublicKeySizey (used for packing)
	FalconPublicKey [cfalcon.PublicKeySize]byte
	// FalconPrivateKey is a wrapper for cfalcon.PrivateKeySize (used for packing)
	FalconPrivateKey [cfalcon.PrivateKeySize]byte
	// FalconSeed represents the seed which is being used to generate Falcon keys
	FalconSeed [FalconSeedSize]byte
)

// FalconSigner is the implementation of Signer for the Falcon signature scheme.
type FalconSigner struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey  FalconPublicKey  `codec:"pk"`
	PrivateKey FalconPrivateKey `codec:"sk"`
}

// GenerateFalconSigner Generates a Falcon Signer.
func GenerateFalconSigner(seed FalconSeed) (FalconSigner, error) {
	pk, sk, err := cfalcon.GenerateKey(seed[:])
	return FalconSigner{
		PublicKey:  FalconPublicKey(pk),
		PrivateKey: FalconPrivateKey(sk),
	}, err
}

// Sign receives a message and generates a signature over that message.
func (d *FalconSigner) Sign(message Hashable) (ByteSignature, error) {
	hs := Hash(HashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
func (d *FalconSigner) SignBytes(data []byte) (ByteSignature, error) {
	signedData, err := (*cfalcon.PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return ByteSignature(signedData), err
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

	PublicKey FalconPublicKey `codec:"k"`
}

// Verify follows falcon algorithm to verify a signature.
func (d *FalconVerifier) Verify(message Hashable, sig ByteSignature) error {
	hs := Hash(HashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func (d *FalconVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	// The wrapper, currently, support only the compress form signature. so we can
	// assume that the signature given is in a compress form
	falconSig := cfalcon.CompressedSignature(sig)
	return (*cfalcon.PublicKey)(&d.PublicKey).Verify(falconSig, data)
}

// GetFixedLengthHashableRepresentation is used to fetch a plain serialized version of the public data (without the use of the msgpack).
func (d *FalconVerifier) GetFixedLengthHashableRepresentation() []byte {
	return d.PublicKey[:]
}

// GetSignatureFixedLengthHashableRepresentation returns a serialized version of the signature
func (d *FalconVerifier) GetSignatureFixedLengthHashableRepresentation(signature ByteSignature) ([]byte, error) {
	compressedSignature := cfalcon.CompressedSignature(signature)
	ctSignature, err := compressedSignature.ConvertToCT()
	return ctSignature[:], err
}
