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
	"errors"
	"fmt"

	cfalcon "github.com/algorand/falcon"
)

var (
	errFalconPublicKeySize = errors.New("falcon public key size invalid")
	errFalconSignatureSize = errors.New("falcon signature size invalid")
	errFalconSeedTooShort  = errors.New("falcon seed too short")
)

const (
	// FalconSeedSize Represents the size in bytes of the random bytes used to generate Falcon keys
	FalconSeedSize = 48

	// FalconPublicKeySize represents the size in bytes of a Falcon public key.
	FalconPublicKeySize = cfalcon.PublicKeySize

	// FalconPrivateKeySize represents the size in bytes of a Falcon private key.
	FalconPrivateKeySize = cfalcon.PrivateKeySize

	// FalconMaxSignatureSize Represents the max possible size in bytes of a falcon signature
	FalconMaxSignatureSize = cfalcon.CTSignatureSize
)

type (
	// FalconPublicKey is a wrapper for cfalcon.PublicKeySize (used for packing)
	FalconPublicKey [FalconPublicKeySize]byte
	// FalconPrivateKey is a wrapper for cfalcon.PrivateKeySize (used for packing)
	FalconPrivateKey [FalconPrivateKeySize]byte
	// FalconSeed represents the fixed-length seed used by default Falcon keygen.
	FalconSeed [FalconSeedSize]byte
	// FalconSignature represents a Falcon signature in a compressed-form
	//msgp:allocbound FalconSignature FalconMaxSignatureSize
	FalconSignature []byte
)

// FalconPublicKeyFromBytes constructs a Falcon public key from its byte representation.
func FalconPublicKeyFromBytes(publicKey []byte) (FalconPublicKey, error) {
	if len(publicKey) != FalconPublicKeySize {
		return FalconPublicKey{}, fmt.Errorf("%w: got %d, want %d", errFalconPublicKeySize, len(publicKey), FalconPublicKeySize)
	}

	var pk FalconPublicKey
	copy(pk[:], publicKey)
	return pk, nil
}

// FalconSignatureFromBytes constructs a Falcon signature from its byte representation.
func FalconSignatureFromBytes(signature []byte) (FalconSignature, error) {
	if len(signature) == 0 || len(signature) > FalconMaxSignatureSize {
		return nil, fmt.Errorf("%w: got %d, want 1..%d", errFalconSignatureSize, len(signature), FalconMaxSignatureSize)
	}
	return signature, nil
}

// FalconSigner is the implementation of Signer for the Falcon signature scheme.
type FalconSigner struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey  FalconPublicKey  `codec:"pk"`
	PrivateKey FalconPrivateKey `codec:"sk"`
}

// GenerateFalconSigner generates a Falcon signer from the fixed-size Falcon
// seed type.
func GenerateFalconSigner(seed FalconSeed) (FalconSigner, error) {
	return GenerateFalconSignerFromVarLenSeed(seed[:])
}

// GenerateFalconSignerFromVarLenSeed generates a Falcon signer from caller-derived
// variable length seed bytes. Callers are responsible for domain separation before
// passing seed. The seed must carry at least DigestSize bytes of entropy; a
// shorter (or empty) seed is rejected so it cannot yield a fixed, public keypair.
func GenerateFalconSignerFromVarLenSeed(seed []byte) (FalconSigner, error) {
	if len(seed) < DigestSize {
		return FalconSigner{}, fmt.Errorf("%w: got %d, want >= %d", errFalconSeedTooShort, len(seed), DigestSize)
	}
	pk, sk, err := cfalcon.GenerateKey(seed)
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
