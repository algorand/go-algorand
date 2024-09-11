// Copyright (C) 2019-2024 Algorand, Inc.
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
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/protocol"
)

const (
	// ErrIndexOutOfBound returned when an index is out of the array's bound
	ErrIndexOutOfBound = "pos %d past end %d"
)

// A Participant corresponds to an account whose AccountData.Status
// is Online, and for which the expected sigRound satisfies
// AccountData.VoteFirstValid <= sigRound <= AccountData.VoteLastValid.
//
// In the Algorand ledger, it is possible for multiple accounts to have
// the same PK.  Thus, the PK is not necessarily unique among Participants.
// However, each account will produce a unique Participant struct, to avoid
// potential DoS attacks where one account claims to have the same VoteID PK
// as another account.
type Participant struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// PK is the identifier used to verify the signature for a specific participant
	PK merklesignature.Verifier `codec:"p"`

	// Weight is AccountData.MicroAlgos.
	Weight uint64 `codec:"w"`
}

// ToBeHashed implements the crypto.Hashable interface.
// In order to create a more SNARK-friendly commitments on the signature we must avoid using the msgpack infrastructure.
// msgpack creates a compressed representation of the struct which might be varied in length, which will
// be bad for creating SNARK
func (p Participant) ToBeHashed() (protocol.HashID, []byte) {

	var weightAsBytes [8]byte
	binary.LittleEndian.PutUint64(weightAsBytes[:], p.Weight)

	var keyLifetimeBytes [8]byte
	binary.LittleEndian.PutUint64(keyLifetimeBytes[:], p.PK.KeyLifetime)

	publicKeyBytes := p.PK.Commitment

	partCommitment := make([]byte, 0, len(weightAsBytes)+len(publicKeyBytes)+len(keyLifetimeBytes))
	partCommitment = append(partCommitment, weightAsBytes[:]...)
	partCommitment = append(partCommitment, keyLifetimeBytes[:]...)
	partCommitment = append(partCommitment, publicKeyBytes[:]...)

	return protocol.StateProofPart, partCommitment
}

// ParticipantsArray implements merklearray.Array and is used to commit
// to a Merkle tree of online accounts.
//
//msgp:ignore ParticipantsArray
type ParticipantsArray []Participant

// Length returns the ledger of the array.
func (p ParticipantsArray) Length() uint64 {
	return uint64(len(p))
}

// Marshal Returns the hash for the given position.
func (p ParticipantsArray) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= uint64(len(p)) {
		return nil, fmt.Errorf(ErrIndexOutOfBound, pos, len(p))
	}

	return p[pos], nil
}
