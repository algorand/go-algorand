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

package compactcert

import (
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type commitableSignatureSlot struct {
	sigCommit           sigslotCommit
	serializedSignature []byte
}

//msgp:ignore commitableSignatureSlotArray
type commitableSignatureSlotArray []sigslot

func (sc commitableSignatureSlotArray) Length() uint64 {
	return uint64(len(sc))
}

func (sc commitableSignatureSlotArray) Marshal(pos uint64) ([]byte, error) {
	if pos >= uint64(len(sc)) {
		return nil, fmt.Errorf("pos %d past end %d", pos, len(sc))
	}

	signatureSlot, err := buildCommitableSignature(sc[pos].sigslotCommit)
	if err != nil {
		return nil, err
	}

	return crypto.HashRep(signatureSlot), nil

}

func buildCommitableSignature(sigCommit sigslotCommit) (*commitableSignatureSlot, error) {
	if sigCommit.Sig.Signature.ByteSignature == nil {
		// TODO we get here if we don't have a signature in a particular slot.
		// advise on what to do here. + create a TEST
		return &commitableSignatureSlot{sigCommit: sigCommit, serializedSignature: []byte{}}, nil
	}
	sigBytes, err := sigCommit.Sig.GetSerializedSignature()
	if err != nil {
		return nil, err
	}
	return &commitableSignatureSlot{sigCommit: sigCommit, serializedSignature: sigBytes}, nil
}

// ToBeHashed returns the sequence of bytes that would be used as an input for the hash function when creating a merkle tree.
// In order to create a more SNARK-friendly commitment we must avoid using the msgpack infrastructure.
// msgpack creates a compressed representation of the struct which might be varied in length, this will
// be bad for creating SNARK
func (cs *commitableSignatureSlot) ToBeHashed() (protocol.HashID, []byte) {
	binaryLValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryLValue, cs.sigCommit.L)

	sigSlotCommitment := make([]byte, 0, len(binaryLValue)+len(cs.serializedSignature))
	sigSlotCommitment = append(sigSlotCommitment, binaryLValue...)
	sigSlotCommitment = append(sigSlotCommitment, cs.serializedSignature...)

	return protocol.CompactCertSig, sigSlotCommitment
}
