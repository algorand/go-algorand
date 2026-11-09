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
	"math"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errNoCanonicalAddressSalt = errors.New("no canonical salt exists for this public key and scheme")
)

// AddressSalt is a 1-byte salt that selects an address for a signature-scheme
// public key when deriving a 32-byte salted address; it is public and included in the
// address derivation.
type AddressSalt uint8

// saltedAddressPreimage is the Hashable payload used to derive a salted
// account address from a fixed-width SigScheme, an explicit fixed-width public
// AddressSalt, and a public key. Its ToBeHashed method defines the consensus
// byte layout.
type saltedAddressPreimage struct {
	scheme protocol.SigScheme
	salt   AddressSalt
	pk     []byte
}

// ToBeHashed returns the preimage for salted address hash derivation:
// (protocol.PostQuantumAddress || SigScheme || AddressSalt || pk).
// The scheme tag and public salt are part of the address identity, so the same
// public key may derive multiple salted addresses.
func (preimage saltedAddressPreimage) ToBeHashed() (protocol.HashID, []byte) {
	payload := make([]byte, 0, len(preimage.scheme)+1+len(preimage.pk))
	payload = append(payload, preimage.scheme[:]...)
	payload = append(payload, byte(preimage.salt))
	payload = append(payload, preimage.pk...)
	return protocol.PostQuantumAddress, payload
}

// SaltedAddress returns the address derived from a signature scheme, an explicit
// salt, and a scheme-canonical public key.
func SaltedAddress(scheme protocol.SigScheme, salt AddressSalt, pk []byte) Address {
	return Address(crypto.HashObj(saltedAddressPreimage{scheme, salt, pk}))
}

// CanonicalAddressSalt returns the lowest salt whose derived address for a
// SigScheme/public-key pair complies with the crypto.IsEdwards25519Point
// rejection-sampling predicate (ascending 0..255 scan order).
func CanonicalAddressSalt(scheme protocol.SigScheme, publicKey []byte) (AddressSalt, Address, error) {
	// If no valid salt is found rejection-sampling within this range, the publicKey
	// has no salted address for the given SigScheme; the vanishingly small probability
	// of this happening is ~2^(-256).
	for salt := 0; salt <= math.MaxUint8; salt++ {
		addr := SaltedAddress(scheme, AddressSalt(salt), publicKey)
		if addr.IsOffEd25519Curve() {
			return AddressSalt(salt), addr, nil
		}
	}
	return 0, Address{}, errNoCanonicalAddressSalt
}
