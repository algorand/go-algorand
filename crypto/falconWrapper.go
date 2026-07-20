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
	// ErrPQFalcon1024SigInvalid is returned when Falcon-1024 signature verification fails.
	ErrPQFalcon1024SigInvalid = errors.New("invalid falcon-1024 signature")
)

const (
	// FalconSeedSize is the size in bytes of a Falcon keygen seed: 32 bytes
	// (256-bit entropy). The previous value of 48 was inherited from falcon.c's
	// SHAKE256 explicit-seed.
	FalconSeedSize = 32

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
	//msgp:ignore FalconSeed
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

// GenerateFalconSigner generates a Falcon signer from the fixed-size Falcon
// seed type.
func GenerateFalconSigner(seed FalconSeed) (FalconSigner, error) {
	pk, sk, err := cfalcon.GenerateKey(seed[:])
	return FalconSigner{
		PublicKey:  FalconPublicKey(pk),
		PrivateKey: FalconPrivateKey(sk),
	}, err
}

// Sign receives a message and generates a signature over that message's to-be-hashed representation.
func (d *FalconSigner) Sign(message Hashable) (FalconSignature, error) {
	hs := HashRep(message)
	return d.SignBytes(hs[:])
}

// SignHashedMessage receives a message and generates a signature over the hash of that message.
func (d *FalconSigner) SignHashedMessage(message Hashable) (FalconSignature, error) {
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
	hs := HashRep(message)
	return d.VerifyBytes(hs[:], sig)
}

// VerifyHashedMessage follows falcon algorithm to verify a signature.
func (d *FalconVerifier) VerifyHashedMessage(message Hashable, sig FalconSignature) error {
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

// VerifyFalcon1024 verifies a Falcon-1024 signature over message.
func VerifyFalcon1024(message Hashable, publicKey []byte, signature []byte) error {
	if len(publicKey) != FalconPublicKeySize {
		return fmt.Errorf("%w: public key size %d, want %d", ErrPQFalcon1024SigInvalid, len(publicKey), FalconPublicKeySize)
	}
	// No signature size checks needed: cfalcon rejects empty, undersized, and
	// oversized signatures itself before doing any work.
	var fv FalconVerifier
	copy(fv.PublicKey[:], publicKey)
	if err := fv.Verify(message, FalconSignature(signature)); err != nil {
		return fmt.Errorf("%w: %w", ErrPQFalcon1024SigInvalid, err)
	}
	return nil
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
	if len(s) < 2 {
		return nil, errInvalidNumberOfSignature
	}
	compressedSignature := cfalcon.CompressedSignature(s)
	ctSignature, err := compressedSignature.ConvertToCT()
	return ctSignature[:], err
}

// IsSaltVersionEqual of the signature matches the given version
func (s FalconSignature) IsSaltVersionEqual(version byte) bool {
	return (*cfalcon.CompressedSignature)(&s).SaltVersion() == version
}
