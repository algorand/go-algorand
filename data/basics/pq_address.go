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

package basics

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

var (
	ErrPQSchemeNotSupported     = errors.New("pq signature scheme not supported")
	errPQPublicKeySize          = errors.New("pq public key size invalid")
	errNoCanonicalPQAddressSalt = errors.New("no canonical salt exists for this public key and scheme")
)

const (
	// pqSchemeSize is the consensus byte length of a post-quantum signature scheme tag.
	pqSchemeSize = 2

	// pqAddressSaltSize is the consensus byte length of a post-quantum address salt.
	pqAddressSaltSize = 1
)

// PQScheme is a 2-bytes ASCII identifier of a post-quantum account authorization scheme.
// Conventionally: the first bytes is the PQ-DSA family, the second byte is a version
// or variant identifier.
type PQScheme [pqSchemeSize]byte

// Supported post-quantum signature schemes:
// - f1: Deterministic Falcon-1024 account authorization.
func PQSchemeFalcon1024() PQScheme {
	return PQScheme{'f', '1'}
}

// IsSupported reports whether this scheme is supported. Note: currently only "f1"
// is supported, but this method is intended to be updated as new schemes are added.
func (s PQScheme) IsSupported() bool {
	return s == PQSchemeFalcon1024()
}

// ValidatePublicKey checks that the given public key is valid for the given scheme.
func (s PQScheme) ValidatePublicKey(publicKey []byte) error {
	switch s {
	case PQSchemeFalcon1024():
		if len(publicKey) != crypto.FalconPublicKeySize {
			return fmt.Errorf("%w: got %d, want %d", errPQPublicKeySize, len(publicKey), crypto.FalconPublicKeySize)
		}
		return nil

	default:
		return ErrPQSchemeNotSupported
	}
}

// PQAddressSalt is a 1-byte salt that selects an address for a post-quantum
// public key when deriving a 32-byte address; it is public and included in the
// address derivation.
type PQAddressSalt uint8

// pqAddressPreimage is the Hashable payload used to derive a native post-quantum
// account address from a fixed-width PQScheme, an explicit fixed-width public
// PQAddressSalt, and a public key. Its ToBeHashed method defines the consensus
// byte layout.
type pqAddressPreimage struct {
	scheme PQScheme
	salt   PQAddressSalt
	pk     []byte
}

// ToBeHashed returns the preimage for post-quantum address hash derivation:
// (protocol.PostQuantumAddress || PQScheme || PQAddressSalt || pk).
// The scheme tag and public salt are part of the address identity, so the same
// public key may derive multiple PQ addresses.
func (pq pqAddressPreimage) ToBeHashed() (protocol.HashID, []byte) {
	payload := make([]byte, 0, pqAddressSchemeSize+pqAddressSaltSize+len(pq.pk))
	payload = append(payload, pq.scheme[:]...)
	payload = append(payload, byte(pq.salt))
	payload = append(payload, pq.pk...)
	return protocol.PostQuantumAddress, payload
}

// pqAddress returns the address derived from a pqAddressPreimage and true if it
// does not decode to any Edwards25519 point according to the broader predicate
// expressed by crypto.IsEdwards25519Point, false otherwise.
func pqAddress(scheme pqSignatureScheme, salt PQAddressSalt, pk []byte) (Address, bool) {
	addr := Address(crypto.HashObj(pqAddressPreimage{scheme, salt, pk}))
	return addr, !crypto.IsEdwards25519Point(addr[:])
}

// Falcon1024Address derives an address controlled by a Deterministic Falcon-1024
// signature from a public salt and a Falcon-1024 public key. The boolean is false
// when the public key is nil or the derived address decodes as an Edwards25519
// point and therefore is invalid for PQ account use.
func Falcon1024Address(salt PQAddressSalt, pk *crypto.FalconPublicKey) (Address, bool) {
	if pk == nil {
		return Address{}, false
	}
	return pqAddress(falcon1024DeterministicScheme(), salt, pk[:])
}
