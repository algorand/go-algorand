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

package stateproof

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type committableSignatureSlot struct {
	sigCommit           sigslotCommit
	serializedSignature []byte
	isEmptySlot         bool
}

// ErrIndexOutOfBound returned when an index is out of the array's bound
var ErrIndexOutOfBound = errors.New("index is out of bound")

// committableSignatureSlotArray is used to create a merkle tree on the stateproof's
// signature array. it serializes the MSS signatures using a specific format
// state proof signature array.
//msgp:ignore committableSignatureSlotArray
type committableSignatureSlotArray []sigslot

func (sc committableSignatureSlotArray) Length() uint64 {
	return uint64(len(sc))
}

func (sc committableSignatureSlotArray) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= uint64(len(sc)) {
		return nil, fmt.Errorf("%w: pos %d past end %d", ErrIndexOutOfBound, pos, len(sc))
	}

	signatureSlot, err := buildCommittableSignature(sc[pos].sigslotCommit)
	if err != nil {
		return nil, err
	}

	return signatureSlot, nil
}

func buildCommittableSignature(sigCommit sigslotCommit) (*committableSignatureSlot, error) {
	if sigCommit.Sig.MsgIsZero() { // Empty merkle signature
		return &committableSignatureSlot{isEmptySlot: true}, nil
	}
	if sigCommit.Sig.Signature == nil { // Merkle signature is not empty, but falcon signature is (invalid case)
		return nil, fmt.Errorf("buildCommittableSignature: Falcon signature is nil")
	}
	sigBytes, err := sigCommit.Sig.GetFixedLengthHashableRepresentation()
	if err != nil {
		return nil, err
	}
	return &committableSignatureSlot{sigCommit: sigCommit, serializedSignature: sigBytes, isEmptySlot: false}, nil
}

// ToBeHashed returns the sequence of bytes that would be used as an input for the hash function when creating a merkle tree.
// In order to create a more SNARK-friendly commitment we must avoid using the msgpack infrastructure.
// msgpack creates a compressed representation of the struct which might be varied in length, this will
// be bad for creating SNARK
func (cs *committableSignatureSlot) ToBeHashed() (protocol.HashID, []byte) {
	if cs.isEmptySlot {
		return protocol.StateProofSig, []byte{}
	}
	var binaryLValue [8]byte
	binary.LittleEndian.PutUint64(binaryLValue[:], cs.sigCommit.L)

	sigSlotByteRepresentation := make([]byte, 0, len(binaryLValue)+len(cs.serializedSignature))
	sigSlotByteRepresentation = append(sigSlotByteRepresentation, binaryLValue[:]...)
	sigSlotByteRepresentation = append(sigSlotByteRepresentation, cs.serializedSignature...)

	return protocol.StateProofSig, sigSlotByteRepresentation
}
