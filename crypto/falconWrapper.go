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

	// ErrPQFalcon512SigInvalid is returned when Falcon-512 signature verification fails.
	ErrPQFalcon512SigInvalid = errors.New("invalid falcon-512 signature")
)

// FalconSeedSize is the size in bytes of a Falcon keygen seed: 32 bytes
// (256-bit entropy). The previous value of 48 was inherited from falcon.c's
// SHAKE256 explicit-seed.
//
// The seed carries no scheme-specific structure, so a single seed type serves
// both Falcon-1024 and Falcon-512 keygen. Do not use the same seed value across
// schemes.
const FalconSeedSize = 32

// FalconSeed represents the fixed-length seed used by default Falcon keygen.
//
//msgp:ignore FalconSeed
type FalconSeed [FalconSeedSize]byte

//
// Falcon-1024
//

const (
	// Falcon1024PublicKeySize represents the size in bytes of a Falcon-1024 public key.
	Falcon1024PublicKeySize = cfalcon.PublicKeySize

	// Falcon1024PrivateKeySize represents the size in bytes of a Falcon-1024 private key.
	Falcon1024PrivateKeySize = cfalcon.PrivateKeySize

	// Falcon1024MaxSignatureSize Represents the max possible size in bytes of a falcon-1024 signature
	Falcon1024MaxSignatureSize = cfalcon.CTSignatureSize
)

type (
	// Falcon1024PublicKey is a wrapper for cfalcon.PublicKeySize (used for packing)
	Falcon1024PublicKey [Falcon1024PublicKeySize]byte
	// Falcon1024PrivateKey is a wrapper for cfalcon.PrivateKeySize (used for packing)
	Falcon1024PrivateKey [Falcon1024PrivateKeySize]byte
	// Falcon1024Signature represents a Falcon-1024 signature in a compressed-form
	//msgp:allocbound Falcon1024Signature Falcon1024MaxSignatureSize
	Falcon1024Signature []byte
)

// Falcon1024Signer is the implementation of Signer for the Falcon-1024 signature scheme.
type Falcon1024Signer struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey  Falcon1024PublicKey  `codec:"pk"`
	PrivateKey Falcon1024PrivateKey `codec:"sk"`
}

// GenerateFalcon1024Signer generates a Falcon-1024 signer from the fixed-size
// Falcon seed type.
func GenerateFalcon1024Signer(seed FalconSeed) (Falcon1024Signer, error) {
	pk, sk, err := cfalcon.GenerateKey(seed[:])
	return Falcon1024Signer{
		PublicKey:  Falcon1024PublicKey(pk),
		PrivateKey: Falcon1024PrivateKey(sk),
	}, err
}

// NewFalcon1024Signer creates a Falcon1024Signer that is used to sign and verify falcon signatures
func NewFalcon1024Signer() (*Falcon1024Signer, error) {
	var seed FalconSeed
	RandBytes(seed[:])
	signer, err := GenerateFalcon1024Signer(seed)
	if err != nil {
		return &Falcon1024Signer{}, err
	}
	return &signer, nil
}

// Sign receives a message and generates a signature over that message's to-be-hashed representation.
func (d *Falcon1024Signer) Sign(message Hashable) (Falcon1024Signature, error) {
	return d.SignBytes(HashRep(message))
}

// SignBytes receives bytes and signs over them.
func (d *Falcon1024Signer) SignBytes(data []byte) (Falcon1024Signature, error) {
	signedData, err := (*cfalcon.PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return Falcon1024Signature(signedData), err
}

// GetVerifyingKey Outputs a verifying key object which is serializable.
func (d *Falcon1024Signer) GetVerifyingKey() *Falcon1024Verifier {
	return &Falcon1024Verifier{
		PublicKey: d.PublicKey,
	}
}

// Falcon1024Verifier implements the type Verifier interface for the Falcon-1024 signature scheme.
type Falcon1024Verifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey Falcon1024PublicKey `codec:"k"`
}

// Verify verifies a Falcon-1024 signature over that message's to-be-hashed representation.
func (d *Falcon1024Verifier) Verify(message Hashable, sig Falcon1024Signature) error {
	return d.VerifyBytes(HashRep(message), sig)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func (d *Falcon1024Verifier) VerifyBytes(data []byte, sig Falcon1024Signature) error {
	// The wrapper, currently, support only the compress form signature. so we can
	// assume that the signature given is in a compress form
	falconSig := cfalcon.CompressedSignature(sig)
	return (*cfalcon.PublicKey)(&d.PublicKey).Verify(falconSig, data)
}

// GetFixedLengthHashableRepresentation is used to fetch a plain serialized version of the public data (without the use of the msgpack).
func (d *Falcon1024Verifier) GetFixedLengthHashableRepresentation() []byte {
	return d.PublicKey[:]
}

// GetFixedLengthHashableRepresentation returns a serialized version of the signature
func (s Falcon1024Signature) GetFixedLengthHashableRepresentation() ([]byte, error) {
	if len(s) < 2 {
		return nil, errInvalidNumberOfSignature
	}
	compressedSignature := cfalcon.CompressedSignature(s)
	ctSignature, err := compressedSignature.ConvertToCT()
	return ctSignature[:], err
}

// IsSaltVersionEqual of the signature matches the given version
func (s Falcon1024Signature) IsSaltVersionEqual(version byte) bool {
	return (*cfalcon.CompressedSignature)(&s).SaltVersion() == version
}

// VerifyFalcon1024 verifies a Falcon-1024 signature over message.
func VerifyFalcon1024(message Hashable, publicKey []byte, signature []byte) error {
	if len(publicKey) != Falcon1024PublicKeySize {
		return fmt.Errorf("%w: public key size %d, want %d", ErrPQFalcon1024SigInvalid, len(publicKey), Falcon1024PublicKeySize)
	}
	// No signature size checks needed: cfalcon rejects empty, undersized, and
	// oversized signatures itself before doing any work.
	var fv Falcon1024Verifier
	copy(fv.PublicKey[:], publicKey)
	if err := fv.Verify(message, Falcon1024Signature(signature)); err != nil {
		return fmt.Errorf("%w: %w", ErrPQFalcon1024SigInvalid, err)
	}
	return nil
}

//
// Falcon-512
//

const (
	// Falcon512PublicKeySize represents the size in bytes of a Falcon-512 public key.
	Falcon512PublicKeySize = cfalcon.Det512PublicKeySize

	// Falcon512PrivateKeySize represents the size in bytes of a Falcon-512 private key.
	Falcon512PrivateKeySize = cfalcon.Det512PrivateKeySize

	// Falcon512MaxSignatureSize Represents the max possible size in bytes of a falcon-512 signature
	Falcon512MaxSignatureSize = cfalcon.Det512CTSignatureSize
)

type (
	// Falcon512PublicKey is a wrapper for cfalcon.Det512PublicKeySize (used for packing)
	Falcon512PublicKey [Falcon512PublicKeySize]byte
	// Falcon512PrivateKey is a wrapper for cfalcon.Det512PrivateKeySize (used for packing)
	Falcon512PrivateKey [Falcon512PrivateKeySize]byte
	// Falcon512Signature represents a Falcon-512 signature in a compressed-form
	//msgp:allocbound Falcon512Signature Falcon512MaxSignatureSize
	Falcon512Signature []byte
)

// Falcon512Signer is the implementation of Signer for the Falcon-512 signature scheme.
type Falcon512Signer struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey  Falcon512PublicKey  `codec:"pk"`
	PrivateKey Falcon512PrivateKey `codec:"sk"`
}

// GenerateFalcon512Signer generates a Falcon-512 signer from the fixed-size
// Falcon seed type.
func GenerateFalcon512Signer(seed FalconSeed) (Falcon512Signer, error) {
	pk, sk, err := cfalcon.Det512GenerateKey(seed[:])
	return Falcon512Signer{
		PublicKey:  Falcon512PublicKey(pk),
		PrivateKey: Falcon512PrivateKey(sk),
	}, err
}

// NewFalcon512Signer creates a Falcon512Signer that is used to sign and verify falcon signatures
func NewFalcon512Signer() (*Falcon512Signer, error) {
	var seed FalconSeed
	RandBytes(seed[:])
	signer, err := GenerateFalcon512Signer(seed)
	if err != nil {
		return &Falcon512Signer{}, err
	}
	return &signer, nil
}

// Sign receives a message and generates a signature over that message's to-be-hashed representation.
func (d *Falcon512Signer) Sign(message Hashable) (Falcon512Signature, error) {
	return d.SignBytes(HashRep(message))
}

// SignBytes receives bytes and signs over them.
func (d *Falcon512Signer) SignBytes(data []byte) (Falcon512Signature, error) {
	signedData, err := (*cfalcon.Det512PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return Falcon512Signature(signedData), err
}

// GetVerifyingKey Outputs a verifying key object which is serializable.
func (d *Falcon512Signer) GetVerifyingKey() *Falcon512Verifier {
	return &Falcon512Verifier{
		PublicKey: d.PublicKey,
	}
}

// Falcon512Verifier implements the type Verifier interface for the Falcon-512 signature scheme.
type Falcon512Verifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey Falcon512PublicKey `codec:"k"`
}

// Verify verifies a Falcon-512 signature over that message's to-be-hashed representation.
func (d *Falcon512Verifier) Verify(message Hashable, sig Falcon512Signature) error {
	return d.VerifyBytes(HashRep(message), sig)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func (d *Falcon512Verifier) VerifyBytes(data []byte, sig Falcon512Signature) error {
	// The wrapper, currently, support only the compress form signature. so we can
	// assume that the signature given is in a compress form
	falconSig := cfalcon.Det512CompressedSignature(sig)
	return (*cfalcon.Det512PublicKey)(&d.PublicKey).Verify(falconSig, data)
}

// GetFixedLengthHashableRepresentation is used to fetch a plain serialized version of the public data (without the use of the msgpack).
func (d *Falcon512Verifier) GetFixedLengthHashableRepresentation() []byte {
	return d.PublicKey[:]
}

// GetFixedLengthHashableRepresentation returns a serialized version of the signature
func (s Falcon512Signature) GetFixedLengthHashableRepresentation() ([]byte, error) {
	if len(s) < 2 {
		return nil, errInvalidNumberOfSignature
	}
	compressedSignature := cfalcon.Det512CompressedSignature(s)
	ctSignature, err := compressedSignature.ConvertToCT()
	return ctSignature[:], err
}

// IsSaltVersionEqual of the signature matches the given version
func (s Falcon512Signature) IsSaltVersionEqual(version byte) bool {
	return (*cfalcon.Det512CompressedSignature)(&s).SaltVersion() == version
}

// VerifyFalcon512 verifies a Falcon-512 signature over message.
func VerifyFalcon512(message Hashable, publicKey []byte, signature []byte) error {
	if len(publicKey) != Falcon512PublicKeySize {
		return fmt.Errorf("%w: public key size %d, want %d", ErrPQFalcon512SigInvalid, len(publicKey), Falcon512PublicKeySize)
	}
	// No signature size checks needed: cfalcon rejects empty, undersized, and
	// oversized signatures itself before doing any work.
	var fv Falcon512Verifier
	copy(fv.PublicKey[:], publicKey)
	if err := fv.Verify(message, Falcon512Signature(signature)); err != nil {
		return fmt.Errorf("%w: %w", ErrPQFalcon512SigInvalid, err)
	}
	return nil
}
