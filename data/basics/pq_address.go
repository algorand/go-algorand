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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// Post-quantum signature schemes
type pqSignatureScheme string

const falcon1024DeterministicScheme pqSignatureScheme = "f1"

// PQAddressSalt selects an address for a post-quantum public key when deriving a
// 32-byte address; it is public and included in the address derivation.
type PQAddressSalt byte

const pqAddressSaltSize = 1

// pqAddressPreimage is the Hashable payload used to derive a native post-quantum
// account address from a pqSignatureScheme, an explicit public PQAddressSalt, and
// a public key. Its ToBeHashed method defines the consensus byte layout.
type pqAddressPreimage struct {
	scheme pqSignatureScheme
	salt   PQAddressSalt
	pk     []byte
}

// ToBeHashed returns the fixed, preimage for post-quantum address derivation:
// H(protocol.PostQuantumAddress || scheme || salt || pk). The scheme byte string
// and public salt are part of the address identity, so the same public key may
// derive multiple pqAddress.
func (pq pqAddressPreimage) ToBeHashed() (protocol.HashID, []byte) {
	payload := make([]byte, 0, len(pq.scheme)+pqAddressSaltSize+len(pq.pk))
	payload = append(payload, string(pq.scheme)...)
	payload = append(payload, byte(pq.salt))
	payload = append(payload, pq.pk...)
	return protocol.PostQuantumAddress, payload
}

// pqAddress returns the address and true if the address derived from a pqAddressPreimage
// does not decode to any Edwards25519 point according to the broader predicate
// expressed by crypto.IsEdwards25519Point, false otherwise.
func pqAddress(scheme pqSignatureScheme, salt PQAddressSalt, pk []byte) (Address, bool) {
	addr := Address(crypto.HashObj(pqAddressPreimage{scheme, salt, pk}))
	return addr, !crypto.IsEdwards25519Point(addr[:])
}

func Falcon1024Address(pk crypto.FalconPublicKey, salt PQAddressSalt) (Address, bool) {
	return pqAddress(falcon1024DeterministicScheme, salt, pk[:])
}
