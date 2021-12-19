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
	"errors"
	cfalcon "github.com/algoidan/falcon"
)

const (
	// FalconSeedSize Represents the size in bytes of the random bytes used to generate Falcon keys
	FalconSeedSize = 48

	// MaxFalconSignatureSize Represents the max possible size in bytes of a falcon signature
	MaxFalconSignatureSize = cfalcon.CTSignatureSize

	// FalconSaltVersion Represents the current supported falcon version by go-algorand code.
	// if needed this value could be replaced with consensus param.
	FalconSaltVersion = 0
)

var (
	errFalconWrongSaltVersion = errors.New("Unexpected salt version")
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
	pk, sk, err := cfalcon.GenerateKey(seed[:])
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
	signedData, err := (*cfalcon.PrivateKey)(&d.SecretKey).SignCompressed(data)
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

	PublicKey FPublicKey `codec:"k"`
}

// Verify follows falcon algorithm to verify a signature.
func (d *FalconVerifier) Verify(message Hashable, sig ByteSignature) error {
	hs := Hash(HashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func (d *FalconVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	// we explicitly verify the signature's salt version.
	// This verification is mandatory in order to avoid a collection of signatures with multiple versions.
	// a collection built with different signatures will fail the SNARK verifier
	falconSig := cfalcon.CompressedSignature(sig)
	if falconSig.SaltVersion() != FalconSaltVersion {
		return errFalconWrongSaltVersion
	}
	return (*cfalcon.PublicKey)(&d.PublicKey).Verify(falconSig, data)
}

// GetVerificationBytes is used to fetch a plain serialized version of the public data (without the use of the msgpack).
func (d *FalconVerifier) GetVerificationBytes() []byte {
	return d.PublicKey[:]
}

// GetSerializedSignature returns a serialized version of the signature
func (d *FalconVerifier) GetSerializedSignature(signature ByteSignature) ([]byte, error) {
	compressedSignature := cfalcon.CompressedSignature(signature)
	ctSignature, err := compressedSignature.ConvertToCT()
	return ctSignature[:], err
}
