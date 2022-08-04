// Copyright (C) 2019-2022 Algorand, Inc.
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
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

// Params defines common parameters for the verifier and builder.
type Params struct {
	Msg          crypto.Hashable // Message to be certified
	ProvenWeight uint64          // Weight threshold proven by the certificate
	SigRound     basics.Round    // The round for which the ephemeral key is committed to
	SecKQ        uint64          // Security parameter (k+q) from analysis document
}

// CompactOneTimeSignature is crypto.OneTimeSignature with omitempty
type CompactOneTimeSignature struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	merklesignature.Signature
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

// Reveal is a single array position revealed as part of a compact
// certificate.  It reveals an element of the signature array and
// the corresponding element of the participants array.
type Reveal struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigSlot sigslotCommit      `codec:"s"`
	Part    basics.Participant `codec:"p"`
}

// Cert represents a compact certificate.
type Cert struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigCommit    crypto.GenericDigest `codec:"c"`
	SignedWeight uint64               `codec:"w"`
	SigProofs    merklearray.Proof    `codec:"S"`
	PartProofs   merklearray.Proof    `codec:"P"`

	// Reveals is a sparse map from the position being revealed
	// to the corresponding elements from the sigs and participants
	// arrays.
	Reveals map[uint64]Reveal `codec:"r,allocbound=MaxReveals"`
}

// SortUint64 implements sorting by uint64 keys for
// canonical encoding of maps in msgpack format.
type SortUint64 = basics.SortUint64
