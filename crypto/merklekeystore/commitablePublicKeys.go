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

package merklekeystore

import (
	"encoding/binary"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type (
	// CommittablePublicKeyArray used to arrange the keys so a merkle tree could be build on them.
	CommittablePublicKeyArray struct {
		keys       []crypto.GenericSigningKey
		firstValid uint64
		interval   uint64
	}

	// CommittablePublicKey is a key tied to a specific round and is committed by the merklekeystore.Signer.
	CommittablePublicKey struct {
		VerifyingKey crypto.GenericVerifyingKey
		Round        uint64
	}
)

// Length returns the number of elements in the key array
func (k *CommittablePublicKeyArray) Length() uint64 {
	return uint64(len(k.keys))
}

// Marshal Gets []byte to represent a GenericVerifyingKey tied to the signatureAlgorithm in a pos.
// used to implement the merklearray.Array interface needed to build a tree.
func (k *CommittablePublicKeyArray) Marshal(pos uint64) ([]byte, error) {
	signer := k.keys[pos].GetSigner()
	ephPK := CommittablePublicKey{
		VerifyingKey: *signer.GetVerifyingKey(),
		Round:        indexToRound(k.firstValid, k.interval, pos),
	}

	return crypto.HashRep(&ephPK), nil
}

// ToBeHashed returns the sequence of bytes that would be used as an input for the hash function when creating a merkle tree.
// In order to create a more SNARK-friendly commitment we must avoid using the msgpack infrastructure.
// msgpack creates a compressed representation of the struct which might be varied in length, which will
// be bad for creating SNARK
func (e *CommittablePublicKey) ToBeHashed() (protocol.HashID, []byte) {
	verifyingRawKey := e.VerifyingKey.GetVerifier().GetRawVerificationBytes()

	binaryRound := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryRound, e.Round)

	keyCommitment := make([]byte, 0, len(verifyingRawKey)+len(binaryRound))

	keyCommitment = append(keyCommitment, binaryRound...)
	keyCommitment = append(keyCommitment, verifyingRawKey...)

	return protocol.KeystorePK, keyCommitment
}
