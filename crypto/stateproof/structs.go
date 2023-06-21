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
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

// MessageHash represents the message that a state proof will attest to.
type MessageHash [32]byte

//msgp:ignore sigslot
type sigslot struct {
	// Weight is the weight of the participant signing this message.
	// This information is tracked here for convenience, but it does
	// not appear in the commitment to the sigs array; it comes from
	// the Weight field of the corresponding participant.
	Weight uint64

	// Include the parts of the sigslot that form the commitment to
	// the sigs array.
	sigslotCommit
}

// A sigslotCommit is a single slot in the sigs array that forms the state proof.
type sigslotCommit struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Sig is a signature by the participant on the expected message.
	Sig merklesignature.Signature `codec:"s"`

	// L is the total weight of signatures in lower-numbered slots.
	// This is initialized once the builder has collected a sufficient
	// number of signatures.
	L uint64 `codec:"l"`
}

// Reveal is a single array position revealed as part of a state
// proof.  It reveals an element of the signature array and
// the corresponding element of the participants array.
type Reveal struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigSlot sigslotCommit      `codec:"s"`
	Part    basics.Participant `codec:"p"`
}

// StateProof represents a proof on Algorand's state.
type StateProof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigCommit                  crypto.GenericDigest `codec:"c"`
	SignedWeight               uint64               `codec:"w"`
	SigProofs                  merklearray.Proof    `codec:"S,maxtotalbytes=SigPartProofMaxSize"`
	PartProofs                 merklearray.Proof    `codec:"P,maxtotalbytes=SigPartProofMaxSize"`
	MerkleSignatureSaltVersion byte                 `codec:"v"`
	// Reveals is a sparse map from the position being revealed
	// to the corresponding elements from the sigs and participants
	// arrays.
	Reveals           map[uint64]Reveal `codec:"r,allocbound=MaxReveals"`
	PositionsToReveal []uint64          `codec:"pr,allocbound=MaxReveals"`
}

// SigPartProofMaxSize is the maximum valid size of SigProofs and PartProofs elements of the Stateproof struct in bytes.
// It is equal to merklearray.ProofMaxSizeByElements(config.StateProofTopVoters/2)
// See merklearray.Proof comment for explanation on the bound calculation
const SigPartProofMaxSize = 35353

func (s StateProof) stringBuild() (b strings.Builder) {
	b.WriteString("StateProof: {")
	defer b.WriteRune('}')

	if s.MsgIsZero() {
		return
	}

	b.WriteString(fmt.Sprintf("%v", s.SigCommit))
	b.WriteString(", ")
	b.WriteString(strconv.FormatUint(s.SignedWeight, 10))
	b.WriteString(", ")
	b.WriteString(strconv.Itoa(len(s.PositionsToReveal)))

	return
}

func (s StateProof) String() string {
	b := s.stringBuild()
	return b.String()
}

// SortUint64 implements sorting by uint64 keys for
// canonical encoding of maps in msgpack format.
type SortUint64 = basics.SortUint64
