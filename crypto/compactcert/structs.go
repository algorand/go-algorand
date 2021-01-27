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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// Params defines common parameters for the verifier and builder.
type Params struct {
	Msg          crypto.Hashable // Message to be cerified
	ProvenWeight uint64          // Weight threshold proven by the certificate
	SigRound     basics.Round    // Ephemeral signature round to expect
	SecKQ        uint64          // Security parameter (k+q) from analysis document
}

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

	// PK is AccountData.VoteID.
	PK crypto.OneTimeSignatureVerifier `codec:"p"`

	// Weight is AccountData.MicroAlgos.
	Weight uint64 `codec:"w"`

	// KeyDilution is AccountData.KeyDilution() with the protocol for sigRound
	// as expected by the Builder.
	KeyDilution uint64 `codec:"d"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (p Participant) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertPart, protocol.Encode(&p)
}

// CompactOneTimeSignature is crypto.OneTimeSignature with omitempty
type CompactOneTimeSignature struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	crypto.OneTimeSignature
}

// A sigslotCommit is a single slot in the sigs array that forms the certificate.
type sigslotCommit struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Sig is a signature by the participant on the expected message.
	Sig CompactOneTimeSignature `codec:"s"`

	// L is the total weight of signatures in lower-numbered slots.
	// This is initialized once the builder has collected a sufficient
	// number of signatures.
	L uint64 `codec:"l"`
}

func (ssc sigslotCommit) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertSig, protocol.Encode(&ssc)
}

// Reveal is a single array position revealed as part of a compact
// certificate.  It reveals an element of the signature array and
// the corresponding element of the participants array.
type Reveal struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigSlot sigslotCommit `codec:"s"`
	Part    Participant   `codec:"p"`
}

// maxReveals is a bound on allocation and on numReveals to limit log computation
const maxReveals = 1024
const maxProofDigests = 20 * maxReveals

// Cert represents a compact certificate.
type Cert struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigCommit    crypto.Digest   `codec:"c"`
	SignedWeight uint64          `codec:"w"`
	SigProofs    []crypto.Digest `codec:"S,allocbound=maxProofDigests"`
	PartProofs   []crypto.Digest `codec:"P,allocbound=maxProofDigests"`

	// Reveals is a sparse map from the position being revealed
	// to the corresponding elements from the sigs and participants
	// arrays.
	Reveals map[uint64]Reveal `codec:"r,allocbound=maxReveals"`
}

// SortUint64 implements sorting by uint64 keys for
// canonical encoding of maps in msgpack format.
type SortUint64 = basics.SortUint64
