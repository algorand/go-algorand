// Copyright (C) 2019-2023 Algorand, Inc.
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

package merklesignature

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type (
	// committablePublicKeyArray used to arrange the keys so a merkle tree could be build on them.
	//msgp:ignore committablePublicKeyArray
	committablePublicKeyArray struct {
		keys        []crypto.FalconSigner
		firstValid  uint64
		keyLifetime uint64
	}

	// CommittablePublicKey is used to create a binary representation of public keys in the merkle
	// signature scheme.
	CommittablePublicKey struct {
		VerifyingKey crypto.FalconVerifier
		Round        uint64
	}
)

// ErrIndexOutOfBound returned when an index is out of the array's bound
var ErrIndexOutOfBound = errors.New("index is out of bound")

// Length returns the number of elements in the key array
func (k *committablePublicKeyArray) Length() uint64 {
	return uint64(len(k.keys))
}

// Marshal Gets []byte to represent a GenericVerifyingKey tied to the signatureAlgorithm in a pos.
// used to implement the merklearray.Array interface needed to build a tree.
func (k *committablePublicKeyArray) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= uint64(len(k.keys)) {
		return nil, fmt.Errorf("%w: pos %d past end %d", ErrIndexOutOfBound, pos, len(k.keys))
	}

	ephPK := CommittablePublicKey{
		VerifyingKey: *k.keys[pos].GetVerifyingKey(),
		Round:        indexToRound(k.firstValid, k.keyLifetime, pos),
	}

	return &ephPK, nil
}

// ToBeHashed returns the sequence of bytes that would be used as an input for the hash function when creating a merkle tree.
// In order to create a more SNARK-friendly commitment we must avoid using the msgpack infrastructure.
// msgpack creates a compressed representation of the struct which might be varied in length, this will
// be bad for creating SNARK
func (e *CommittablePublicKey) ToBeHashed() (protocol.HashID, []byte) {
	verifyingRawKey := e.VerifyingKey.GetFixedLengthHashableRepresentation()

	var roundAsBytes [8]byte
	binary.LittleEndian.PutUint64(roundAsBytes[:], e.Round)

	var schemeAsBytes [2]byte
	binary.LittleEndian.PutUint16(schemeAsBytes[:], CryptoPrimitivesID)

	keyCommitment := make([]byte, 0, len(schemeAsBytes)+len(verifyingRawKey)+len(roundAsBytes))
	keyCommitment = append(keyCommitment, schemeAsBytes[:]...)
	keyCommitment = append(keyCommitment, roundAsBytes[:]...)
	keyCommitment = append(keyCommitment, verifyingRawKey...)

	return protocol.KeysInMSS, keyCommitment
}
