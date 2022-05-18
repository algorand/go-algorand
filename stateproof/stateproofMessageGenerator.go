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

package stateproof

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
)

var errInvalidParams = errors.New("provided parameters are invalid")
var errOutOfBound = errors.New("request pos is out of array bounds")
var errProvenWeightOverflow = errors.New("overflow computing provenWeight")

// The Array implementation for block headers, required to build the merkle tree from them.
//msgp:ignore
type blockHeadersArray struct {
	blockHeaders []bookkeeping.BlockHeader
}

func (b blockHeadersArray) Length() uint64 {
	return uint64(len(b.blockHeaders))
}

func (b blockHeadersArray) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= b.Length() {
		return nil, fmt.Errorf("%w: pos - %d, array length - %d", errOutOfBound, pos, b.Length())
	}
	return b.blockHeaders[pos].ToSha256BlockHeader(), nil
}

// GenerateStateProofMessage returns a stateproof message that contains all the necessary data for proving on Algorand's state.
// In addition, it also includes the trusted data for the next stateproof verification
func GenerateStateProofMessage(l Ledger, votersRound uint64, latestRoundInInterval bookkeeping.BlockHeader) (stateproofmsg.Message, error) {
	proto := config.Consensus[latestRoundInInterval.CurrentProtocol]
	commitment, err := createHeaderCommitment(l, proto, latestRoundInInterval)
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	lnProvenWeight, err := calculateLnProvenWeight(latestRoundInInterval, proto, err)
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	return stateproofmsg.Message{
		BlockHeadersCommitment: commitment.ToSlice(),
		VotersCommitment:       latestRoundInInterval.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		LnProvenWeight:         lnProvenWeight,
		FirstAttestedRound:     votersRound + 1,
		LastAttestedRound:      uint64(latestRoundInInterval.Round),
	}, nil
}

func calculateLnProvenWeight(latestRoundInInterval bookkeeping.BlockHeader, proto config.ConsensusParams, err error) (uint64, error) {
	totalWeight := latestRoundInInterval.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight.ToUint64()
	provenWeight, overflowed := basics.Muldiv(totalWeight, uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed {
		err := fmt.Errorf("GenerateStateProofMessage err: %w -  %d %d * %d / (1<<32)",
			errProvenWeightOverflow, latestRoundInInterval.Round, totalWeight, proto.StateProofWeightThreshold)
		return 0, err
	}

	lnProvenWeight, err := stateproof.LnIntApproximation(provenWeight)
	if err != nil {
		return 0, err
	}
	return lnProvenWeight, nil
}

func createHeaderCommitment(l Ledger, proto config.ConsensusParams, latestRoundInInterval bookkeeping.BlockHeader) (crypto.GenericDigest, error) {
	stateProofInterval := proto.StateProofInterval

	if latestRoundInInterval.Round < basics.Round(stateProofInterval) {
		return nil, fmt.Errorf("GenerateStateProofMessage stateProofRound must be >= than stateproofInterval (%w)", errInvalidParams)
	}

	var blkHdrArr blockHeadersArray
	blkHdrArr.blockHeaders = make([]bookkeeping.BlockHeader, stateProofInterval)
	firstRound := latestRoundInInterval.Round - basics.Round(stateProofInterval) + 1
	for i := uint64(0); i < stateProofInterval; i++ {
		rnd := firstRound + basics.Round(i)
		hdr, err := l.BlockHdr(rnd)
		if err != nil {
			return nil, err
		}
		blkHdrArr.blockHeaders[i] = hdr
	}

	// Build merkle tree from encoded headers
	tree, err := merklearray.BuildVectorCommitmentTree(blkHdrArr, crypto.HashFactory{HashType: crypto.Sha256})
	if err != nil {
		return nil, err
	}
	return tree.Root(), nil
}
