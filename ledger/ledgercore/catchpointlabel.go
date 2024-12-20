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

package ledgercore

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

// CatchpointLabelMaker is used for abstract the creation of different catchpoints versions.
// Different catchpoint version might hash different fields.
type CatchpointLabelMaker interface {
	// buffer returns a image used for hashing. (concatenating all fields in the label)
	buffer() []byte
	// round returns the catchpoint label round
	round() basics.Round
	// message returns a printable string containing all the relevant fields in the label.
	message() string
}

// CatchpointLabelMakerV6 represent a single catchpoint label maker, matching catchpoints of version V6 and below.
type CatchpointLabelMakerV6 struct {
	ledgerRound          basics.Round
	ledgerRoundBlockHash crypto.Digest
	balancesMerkleRoot   crypto.Digest
	totals               AccountTotals
}

// MakeCatchpointLabelMakerV6 creates a V6 catchpoint label given the catchpoint label parameters.
func MakeCatchpointLabelMakerV6(ledgerRound basics.Round, ledgerRoundBlockHash *crypto.Digest,
	balancesMerkleRoot *crypto.Digest, totals AccountTotals) *CatchpointLabelMakerV6 {
	return &CatchpointLabelMakerV6{
		ledgerRound:          ledgerRound,
		ledgerRoundBlockHash: *ledgerRoundBlockHash,
		balancesMerkleRoot:   *balancesMerkleRoot,
		totals:               totals,
	}
}

func (l *CatchpointLabelMakerV6) buffer() []byte {
	encodedTotals := protocol.EncodeReflect(&l.totals)
	buffer := make([]byte, 2*crypto.DigestSize+len(encodedTotals))
	copy(buffer[:], l.ledgerRoundBlockHash[:])
	copy(buffer[crypto.DigestSize:], l.balancesMerkleRoot[:])
	copy(buffer[crypto.DigestSize*2:], encodedTotals)

	return buffer
}

func (l *CatchpointLabelMakerV6) round() basics.Round {
	return l.ledgerRound
}

func (l *CatchpointLabelMakerV6) message() string {
	return fmt.Sprintf("round=%d, block digest=%s, accounts digest=%s", l.ledgerRound, l.ledgerRoundBlockHash, l.balancesMerkleRoot)
}

// CatchpointLabelMakerCurrent represents a single catchpoint maker, matching catchpoints of version V7 and above.
type CatchpointLabelMakerCurrent struct {
	v7Label               CatchpointLabelMakerV7
	onlineAccountsHash    crypto.Digest
	onlineRoundParamsHash crypto.Digest
}

// MakeCatchpointLabelMakerCurrent creates a catchpoint label given the catchpoint label parameters.
func MakeCatchpointLabelMakerCurrent(ledgerRound basics.Round, ledgerRoundBlockHash *crypto.Digest,
	balancesMerkleRoot *crypto.Digest, totals AccountTotals, spVerificationContextHash, onlineAccountsHash, onlineRoundParamsHash *crypto.Digest) *CatchpointLabelMakerCurrent {
	return &CatchpointLabelMakerCurrent{
		v7Label:               *MakeCatchpointLabelMakerV7(ledgerRound, ledgerRoundBlockHash, balancesMerkleRoot, totals, spVerificationContextHash),
		onlineAccountsHash:    *onlineAccountsHash,
		onlineRoundParamsHash: *onlineRoundParamsHash,
	}
}

func (l *CatchpointLabelMakerCurrent) buffer() []byte {
	v6Buffer := l.v7Label.buffer()
	v6Buffer = append(v6Buffer, l.onlineAccountsHash[:]...)
	v6Buffer = append(v6Buffer, l.onlineRoundParamsHash[:]...)
	return v6Buffer
}

func (l *CatchpointLabelMakerCurrent) round() basics.Round {
	return l.v7Label.round()
}

func (l *CatchpointLabelMakerCurrent) message() string {
	return fmt.Sprintf("%s onlineaccts digest=%s onlineroundparams digest=%s", l.v7Label.message(), l.onlineAccountsHash, l.onlineRoundParamsHash)
}

// CatchpointLabelMakerV7 represents a single catchpoint maker, matching catchpoints of version V7 and above.
type CatchpointLabelMakerV7 struct {
	v6Label            CatchpointLabelMakerV6
	spVerificationHash crypto.Digest
}

// MakeCatchpointLabelMakerV7 creates a catchpoint label given the catchpoint label parameters.
func MakeCatchpointLabelMakerV7(ledgerRound basics.Round, ledgerRoundBlockHash *crypto.Digest,
	balancesMerkleRoot *crypto.Digest, totals AccountTotals, spVerificationContextHash *crypto.Digest) *CatchpointLabelMakerV7 {
	return &CatchpointLabelMakerV7{
		v6Label:            *MakeCatchpointLabelMakerV6(ledgerRound, ledgerRoundBlockHash, balancesMerkleRoot, totals),
		spVerificationHash: *spVerificationContextHash,
	}
}

func (l *CatchpointLabelMakerV7) buffer() []byte {
	v6Buffer := l.v6Label.buffer()

	return append(v6Buffer, l.spVerificationHash[:]...)
}

func (l *CatchpointLabelMakerV7) round() basics.Round {
	return l.v6Label.round()
}

func (l *CatchpointLabelMakerV7) message() string {
	return fmt.Sprintf("%s spver digest=%s", l.v6Label.message(), l.spVerificationHash)
}

// MakeLabel returns the user-facing representation of this catchpoint label. ( i.e. the "label" )
func MakeLabel(l CatchpointLabelMaker) string {
	hash := crypto.Hash(l.buffer())
	encodedHash := base32Encoder.EncodeToString(hash[:])
	out := fmt.Sprintf("%d#%s", l.round(), encodedHash)
	logging.Base().Infof("Creating a catchpoint label %s for %s", out, l.message())
	return out
}

// ParseCatchpointLabel parse the given label and breaks it into the round and hash components. In case of a parsing failure,
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
