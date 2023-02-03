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
	cfalcon "github.com/algorand/falcon"
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
	// FalconSignature represents a Falcon signature in a compressed-form
	//msgp:allocbound FalconSignature FalconMaxSignatureSize
	FalconSignature []byte
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
func (d *FalconSigner) Sign(message Hashable) (FalconSignature, error) {
	hs := Hash(HashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
func (d *FalconSigner) SignBytes(data []byte) (FalconSignature, error) {
	signedData, err := (*cfalcon.PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return FalconSignature(signedData), err
}

// GetVerifyingKey Outputs a verifying key object which is serializable.
func (d *FalconSigner) GetVerifyingKey() *FalconVerifier {
	return &FalconVerifier{
		PublicKey: d.PublicKey,
	}
}

// FalconVerifier implements the type Verifier interface for the falcon signature scheme.
type FalconVerifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey FalconPublicKey `codec:"k"`
}

// Verify follows falcon algorithm to verify a signature.
func (d *FalconVerifier) Verify(message Hashable, sig FalconSignature) error {
	hs := Hash(HashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func (d *FalconVerifier) VerifyBytes(data []byte, sig FalconSignature) error {
	// The wrapper, currently, support only the compress form signature. so we can
	// assume that the signature given is in a compress form
	falconSig := cfalcon.CompressedSignature(sig)
	return (*cfalcon.PublicKey)(&d.PublicKey).Verify(falconSig, data)
}

// GetFixedLengthHashableRepresentation is used to fetch a plain serialized version of the public data (without the use of the msgpack).
func (d *FalconVerifier) GetFixedLengthHashableRepresentation() []byte {
	return d.PublicKey[:]
}

// NewFalconSigner creates a falconSigner that is used to sign and verify falcon signatures
func NewFalconSigner() (*FalconSigner, error) {
	var seed FalconSeed
	RandBytes(seed[:])
	signer, err := GenerateFalconSigner(seed)
	if err != nil {
		return &FalconSigner{}, err
	}
	return &signer, nil
}

// GetFixedLengthHashableRepresentation returns a serialized version of the signature
func (s FalconSignature) GetFixedLengthHashableRepresentation() ([]byte, error) {
	compressedSignature := cfalcon.CompressedSignature(s)
	ctSignature, err := compressedSignature.ConvertToCT()
	return ctSignature[:], err
}

// IsSaltVersionEqual of the signature matches the given version
func (s FalconSignature) IsSaltVersionEqual(version byte) bool {
	return (*cfalcon.CompressedSignature)(&s).SaltVersion() == version
}
