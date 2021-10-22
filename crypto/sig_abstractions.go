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
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/protocol"
)

type (
	//ByteSignature using unspecified bound.
	//msgp:allocbound ByteSignature
	ByteSignature []byte

	// AlgorithmType enum type for signing algorithms
	AlgorithmType uint64
)

// all AlgorithmType enums
const (
	DilithiumType AlgorithmType = iota
	Ed25519Type

	maxAlgorithmType
)

// IsValid verifies that the type of the algorithm is known
func (z AlgorithmType) IsValid() error {
	if z >= maxAlgorithmType {
		return protocol.ErrInvalidObject
	}
	return nil
}

// Signer interface represents the possible operations that can be done with a signing key.
type Signer interface {
	Sign(message Hashable) ByteSignature
	SignBytes(message []byte) ByteSignature
	GetVerifyingKey() *VerifyingKey
}

// ErrBadSignature represents a bad signature
var ErrBadSignature = fmt.Errorf("invalid signature")

// Verifier interface represents any algorithm that can verify signatures for a specific signing scheme.
type Verifier interface {
	// Verify and VerifyBytes returns error on bad signature, and any other problem.
	Verify(message Hashable, sig ByteSignature) error
	VerifyBytes(message []byte, sig ByteSignature) error
}

// SignatureAlgorithm holds a Signer, and the type of algorithm the Signer conforms with.
// to add a key - verify that PackedSignatureAlgorithm's function (getSigner) returns your key.
//msgp:postunmarshalcheck SignatureAlgorithm IsValid
type SignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType            `codec:"sigType"`
	Pack PackedSignatureAlgorithm `codec:"keys"`
}

// IsValid states whether the SignatureAlgorithm is valid, and is safe to use.
func (z *SignatureAlgorithm) IsValid() error {
	return z.Type.IsValid()
}

// VerifyingKey is an abstraction of a key store of verifying keys.
// it can return the correct key according to the underlying algorithm.
// Implements Hashable too.
//
// NOTE: The VerifyingKey key might not be a valid key if a malicious client sent it over the network
// make certain it is valid.
//msgp:postunmarshalcheck VerifyingKey IsValid
type VerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType      `codec:"type"`
	Pack PackedVerifyingKey `codec:"pks"`
}

// IsValid states whether the VerifyingKey is valid, and is safe to use.
func (z *VerifyingKey) IsValid() error {
	return z.Type.IsValid()
}

// ToBeHashed makes it easier to hash the VeryfyingKey struct.
func (z *VerifyingKey) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.VerifyingKey, protocol.Encode(z)
}

// GetSigner fetches the Signer type that is stored inside this SignatureAlgorithm.
func (z *SignatureAlgorithm) GetSigner() Signer {
	return z.Pack.getSigner(z.Type)
}

// GetVerifier fetches the Verifier type that is stored inside this VerifyingKey.
func (z *VerifyingKey) GetVerifier() Verifier {
	return z.Pack.getVerifier(z.Type)
}

// PackedVerifyingKey is a key store. Allows for easy marshal/unmarshal.
type PackedVerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	DilithiumPublicKey DilithiumVerifier `codec:"dpk"`
	Ed25519PublicKey   Ed25519PublicKey  `codec:"edpk"`
	invalidVerifier    invalidVerifier
}

var errUnknownVerifier = errors.New("could not find stored Verifier")

func (p *PackedVerifyingKey) getVerifier(t AlgorithmType) Verifier {
	switch t {
	case DilithiumType:
		return &p.DilithiumPublicKey
	case Ed25519Type:
		return &p.Ed25519PublicKey
	default:
		return &p.invalidVerifier
	}
}

// PackedSignatureAlgorithm helps  marshal SignatureAlgorithm
type PackedSignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	DilithiumSigner DilithiumSigner `codec:"ds"`
	Ed25519Singer   Ed25519Key      `codec:"edds"`
	invalidSinger   invalidSinger
}

var errUnknownSigner = errors.New("could not find stored signer")

func (p *PackedSignatureAlgorithm) getSigner(t AlgorithmType) Signer {
	switch t {
	case DilithiumType:
		return &p.DilithiumSigner
	case Ed25519Type:
		return &p.Ed25519Singer
	default:
		return &p.invalidSinger
	}
}

var errNonExistingSignatureAlgorithmType = errors.New("signing algorithm type does not exist")

// NewSigner receives a type of signing algorithm and generates keys.
func NewSigner(t AlgorithmType) (*SignatureAlgorithm, error) {
	var p PackedSignatureAlgorithm
	switch t {
	case DilithiumType:
		signer := NewDilithiumSigner().(*DilithiumSigner)
		p = PackedSignatureAlgorithm{
			DilithiumSigner: *signer,
		}
	case Ed25519Type:
		var seed Seed
		SystemRNG.RandBytes(seed[:])
		key := GenerateEd25519Key(seed)
		p = PackedSignatureAlgorithm{
			Ed25519Singer: *key,
		}
	default:
		return nil, errNonExistingSignatureAlgorithmType
	}
	return &SignatureAlgorithm{
		Type: t,
		Pack: p,
	}, nil
}
