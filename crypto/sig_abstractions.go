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
	"fmt"

	"github.com/algorand/go-algorand/protocol"
)

const (
	// MaxSignatureSize is the size of the largest signature
	// Used signature schemes: ed25519Signature and Falcon signature
	MaxSignatureSize = FalconMaxSignatureSize
)

type (
	//ByteSignature using unspecified bound.
	//msgp:allocbound ByteSignature MaxSignatureSize
	ByteSignature []byte

	// AlgorithmType enum type for signing algorithms
	AlgorithmType uint16
)

// all AlgorithmType enums
const (
	FalconType AlgorithmType = iota
	Ed25519Type

	MaxAlgorithmType
)

// IsValid verifies that the type of the algorithm is known
func (z AlgorithmType) IsValid() error {
	if z >= MaxAlgorithmType {
		return protocol.ErrInvalidObject
	}
	return nil
}

// Signer interface represents the possible operations that can be done with a signing key.
type Signer interface {
	Sign(message Hashable) (ByteSignature, error)
	SignBytes(message []byte) (ByteSignature, error)
	GetVerifyingKey() *GenericVerifyingKey
}

// ErrBadSignature represents a bad signature
var ErrBadSignature = fmt.Errorf("invalid signature")

// Verifier interface represents any algorithm that can verify signatures for a specific signing scheme.
type Verifier interface {
	// Verify and VerifyBytes returns error on bad signature, and any other problem.
	Verify(message Hashable, sig ByteSignature) error
	VerifyBytes(message []byte, sig ByteSignature) error
	// GetFixedLengthHashableRepresentation returns a fixed length (for each crypo scheme) hashable representation of the verification key
	// (without the using msgpack).
	GetFixedLengthHashableRepresentation() []byte
	// GetSignatureFixedLengthHashableRepresentation returns  a fixed length (for each crypo scheme) hashable representation of the signature
	// (without the using msgpack).
	GetSignatureFixedLengthHashableRepresentation(signature ByteSignature) ([]byte, error)
}

// GenericSigningKey holds a Signer, and the type of algorithm the Signer conforms with.
//msgp:postunmarshalcheck GenericSigningKey IsValid
type GenericSigningKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType `codec:"sigType"`

	FalconSigner  FalconSigner `codec:"fs"`
	Ed25519Singer Ed25519Key   `codec:"edds"`
}

// IsValid states whether the GenericSigningKey is valid, and is safe to use.
func (z *GenericSigningKey) IsValid() error {
	return z.Type.IsValid()
}

// GenericVerifyingKey is an abstraction of a key store of verifying keys.
// it can return the correct key according to the underlying algorithm.
// Implements Hashable too.
//
// NOTE: The GenericVerifyingKey key might not be a valid key if a malicious client sent it over the network
// make certain it is valid.
//msgp:postunmarshalcheck GenericVerifyingKey IsValid
type GenericVerifyingKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type AlgorithmType `codec:"type"`

	FalconPublicKey  FalconVerifier   `codec:"fpk"`
	Ed25519PublicKey Ed25519PublicKey `codec:"edpk"`
}

// IsValid states whether the VerifyingKey is valid, and is safe to use.
func (z *GenericVerifyingKey) IsValid() error {
	return z.Type.IsValid()
}

// GetSigner fetches the Signer type that is stored inside this GenericSigningKey.
func (z *GenericSigningKey) GetSigner() Signer {
	switch z.Type {
	case FalconType:
		return &z.FalconSigner
	case Ed25519Type:
		return &z.Ed25519Singer
	default:
		return NewInvalidSinger()
	}
}

// GetVerifier fetches the Verifier type that is stored inside this GenericVerifyingKey.
func (z *GenericVerifyingKey) GetVerifier() Verifier {
	switch z.Type {
	case FalconType:
		return &z.FalconPublicKey
	case Ed25519Type:
		return &z.Ed25519PublicKey
	default:
		return &invalidVerifier{}
	}
}

var errNonExistingSignatureAlgorithmType = errors.New("signing algorithm type does not exist")

// NewSigner receives a type of signing algorithm and generates keys.
func NewSigner(t AlgorithmType) (*GenericSigningKey, error) {
	switch t {
	case FalconType:
		return newFalconSinger(t)
	case Ed25519Type:
		return newEd25519Signer(t)
	default:
		return nil, errNonExistingSignatureAlgorithmType
	}
}

func newEd25519Signer(t AlgorithmType) (*GenericSigningKey, error) {
	var seed Seed
	RandBytes(seed[:])
	key := GenerateEd25519Key(seed)
	return &GenericSigningKey{
		Type:          t,
		Ed25519Singer: *key,
	}, nil
}

func newFalconSinger(t AlgorithmType) (*GenericSigningKey, error) {
	var seed FalconSeed
	RandBytes(seed[:])
	signer, err := GenerateFalconSigner(seed)
	if err != nil {
		return &GenericSigningKey{}, err
	}
	return &GenericSigningKey{
		Type:         t,
		FalconSigner: signer,
	}, nil
}
