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
	"fmt"
	"github.com/algorand/go-algorand/protocol"
)

// AlgorithmType enum type for signing algorithms

type (
	//ByteSignature using unspecified bound.
	//msgp:allocbound ByteSignature
	ByteSignature []byte

	AlgorithmType uint64
)

// all AlgorithmType enums
const (
	minAlgorithmType AlgorithmType = iota

	PlaceHolderType

	maxAlgorithmType
)

func (t AlgorithmType) isValidType() bool {
	return minAlgorithmType < t && t < maxAlgorithmType
}

// Signer interface represents the possible operations that can be done with a signing key.
type Signer interface {
	Sign(message Hashable) ByteSignature
	SignBytes(message []byte) ByteSignature
	GetVerifyingKey() VerifyingKey
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
type SignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType            `codec:"sigType"`
	Pack PackedSignatureAlgorithm `codec:"keys"`
}

// VerifyingKey is an abstraction of a key store of verifying keys.
// it can return the correct key according to the underlying algorithm.
// Implements Hashable too.
//
// NOTE: The VerifyingKey key might not be a valid key if a malicious client sent it over the network
// make certain it is valid.
type VerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType      `codec:"type"`
	Pack PackedVerifyingKey `codec:"pks"`
}

// ToBeHashed makes it easier to hash the VeryfyingKey struct.
func (z *VerifyingKey) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.VerifyingKey, protocol.Encode(z)
}

// IsValid Makes certain struct is valid.
func (z *SignatureAlgorithm) IsValid() bool {
	return !(z == nil) && z.Type.isValidType()
}

// GetSigner fetches the Signer type that is stored inside this SignatureAlgorithm.
func (z *SignatureAlgorithm) GetSigner() Signer {
	return z.Pack.getSigner(z.Type)
}

// IsValid Makes certain struct is valid.
func (z *VerifyingKey) IsValid() bool {
	return !(z == nil) && z.Type.isValidType()
}

// GetVerifier fetches the Verifier type that is stored inside this VerifyingKey.
func (z *VerifyingKey) GetVerifier() Verifier {
	return z.Pack.getVerifier(z.Type)
}

// PackedVerifyingKey is a key store. Allows for easy marshal/unmarshal.
type PackedVerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PlaceHolderPublicKey PlaceHolderPublicKey `codec:"placeholder"`
}

func (p *PackedVerifyingKey) getVerifier(t AlgorithmType) Verifier {
	switch t {
	case PlaceHolderType:
		return &p.PlaceHolderPublicKey
	default:
		panic("unknown type")
	}
}

// PackedSignatureAlgorithm helps  marshal SignatureAlgorithm
type PackedSignatureAlgorithm struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PlaceHolderKey PlaceHolderKey `codec:"placeholderkey"`
}

func (p *PackedSignatureAlgorithm) getSigner(t AlgorithmType) Signer {
	switch t {
	case PlaceHolderType:
		return &p.PlaceHolderKey
	default:
		panic("unknown type")
	}
}

// NewSigner receives a type of signing algorithm and generates keys.
func NewSigner(t AlgorithmType) *SignatureAlgorithm {
	var p PackedSignatureAlgorithm
	switch t {
	case PlaceHolderType:
		var seed Seed
		SystemRNG.RandBytes(seed[:])
		key := GeneratePlaceHolderKey(seed)
		p = PackedSignatureAlgorithm{
			PlaceHolderKey: *key,
		}
	default:
		panic("non existing signer type.")
	}
	return &SignatureAlgorithm{
		Type: t,
		Pack: p,
	}
}
