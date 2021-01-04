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

package ledger

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var base32Encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrCatchpointParsingFailed is used when we attempt to parse and catchpoint label and failing doing so.
var ErrCatchpointParsingFailed = errors.New("catchpoint parsing failed")

// CatchpointLabel represent a single catchpoint label. It will "assemble" a label based on the components
type CatchpointLabel struct {
	ledgerRound          basics.Round
	ledgerRoundBlockHash crypto.Digest
	balancesMerkleRoot   crypto.Digest
	totals               AccountTotals
}

func makeCatchpointLabel(ledgerRound basics.Round, ledgerRoundBlockHash crypto.Digest, balancesMerkleRoot crypto.Digest, totals AccountTotals) CatchpointLabel {
	return CatchpointLabel{
		ledgerRound:          ledgerRound,
		ledgerRoundBlockHash: ledgerRoundBlockHash,
		balancesMerkleRoot:   balancesMerkleRoot,
		totals:               totals,
	}
}

// String return the user-facing representation of this catchpoint label. ( i.e. the "label" )
func (l CatchpointLabel) String() string {
	hash := l.Hash()
	encodedHash := base32Encoder.EncodeToString(hash[:])
	out := fmt.Sprintf("%d#%s", l.ledgerRound, encodedHash)
	logging.Base().Infof("Creating a catchpoint label %s for round=%d, block digest=%s, accounts digest=%s", out, l.ledgerRound, l.ledgerRoundBlockHash, l.balancesMerkleRoot)
	return out
}

// Hash return the hash portion of this catchpoint label
func (l CatchpointLabel) Hash() crypto.Digest {
	encodedTotals := protocol.EncodeReflect(&l.totals)
	buffer := make([]byte, 2*crypto.DigestSize+len(encodedTotals))
	copy(buffer[:], l.ledgerRoundBlockHash[:])
	copy(buffer[crypto.DigestSize:], l.balancesMerkleRoot[:])
	copy(buffer[crypto.DigestSize*2:], encodedTotals)
	return crypto.Hash(buffer[:crypto.DigestSize*2+len(encodedTotals)])
}

// ParseCatchpointLabel parse the given label and breaks it into the round and hash components. In case of a parsing failuire,
// the returned err is non-nil.
func ParseCatchpointLabel(label string) (round basics.Round, hash crypto.Digest, err error) {
	err = ErrCatchpointParsingFailed
	splitted := strings.Split(label, "#")
	if len(splitted) != 2 {
		return
	}
	var uintRound uint64
	// first portion is a round number.
	uintRound, err = strconv.ParseUint(splitted[0], 10, 64)
	if err != nil {
		return
	}
	round = basics.Round(uintRound)
	var hashBytes []byte
	hashBytes, err = base32Encoder.DecodeString(splitted[1])
	if err != nil {
		return
	}
	if len(hashBytes) > crypto.DigestSize {
		err = ErrCatchpointParsingFailed
		return
	}
	copy(hash[:], hashBytes[:])
	err = nil
	return
}
