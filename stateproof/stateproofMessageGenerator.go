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
//
//msgp:ignore lightBlockHeaders
type lightBlockHeaders []bookkeeping.LightBlockHeader

func (b lightBlockHeaders) Length() uint64 {
	return uint64(len(b))
}

func (b lightBlockHeaders) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= b.Length() {
		return nil, fmt.Errorf("%w: pos - %d, array length - %d", errOutOfBound, pos, b.Length())
	}
	return &b[pos], nil
}

// GenerateStateProofMessage returns a stateproof message that contains all the necessary data for proving on Algorand's state.
// In addition, it also includes the trusted data for the next stateproof verification
func GenerateStateProofMessage(l BlockHeaderFetcher, round basics.Round) (stateproofmsg.Message, error) {
	latestRoundHeader, err := l.BlockHdr(round)
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	proto := config.Consensus[latestRoundHeader.CurrentProtocol]
	votersRound := uint64(round.SubSaturate(basics.Round(proto.StateProofInterval)))
	commitment, err := createHeaderCommitment(l, &proto, &latestRoundHeader)
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	lnProvenWeight, err := calculateLnProvenWeight(&latestRoundHeader, &proto)
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	return stateproofmsg.Message{
		BlockHeadersCommitment: commitment.ToSlice(),
		VotersCommitment:       latestRoundHeader.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		LnProvenWeight:         lnProvenWeight,
		FirstAttestedRound:     votersRound + 1,
		LastAttestedRound:      uint64(latestRoundHeader.Round),
	}, nil
}

func calculateLnProvenWeight(latestRoundInInterval *bookkeeping.BlockHeader, proto *config.ConsensusParams) (uint64, error) {
	totalWeight := latestRoundInInterval.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight.ToUint64()
	provenWeight, overflowed := basics.Muldiv(totalWeight, uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed {
		err := fmt.Errorf("calculateLnProvenWeight err: %w -  %d %d * %d / (1<<32)",
			errProvenWeightOverflow, latestRoundInInterval.Round, totalWeight, proto.StateProofWeightThreshold)
		return 0, err
	}

	lnProvenWeight, err := stateproof.LnIntApproximation(provenWeight)
	if err != nil {
		return 0, err
	}
	return lnProvenWeight, nil
}

func createHeaderCommitment(l BlockHeaderFetcher, proto *config.ConsensusParams, latestRoundHeader *bookkeeping.BlockHeader) (crypto.GenericDigest, error) {
	stateProofInterval := proto.StateProofInterval

	if latestRoundHeader.Round < basics.Round(stateProofInterval) {
		return nil, fmt.Errorf("createHeaderCommitment stateProofRound must be >= than stateproofInterval (%w)", errInvalidParams)
	}

	var lightHeaders lightBlockHeaders
	lightHeaders, err := FetchLightHeaders(l, stateProofInterval, latestRoundHeader.Round)
	if err != nil {
		return crypto.GenericDigest{}, err
	}

	// Build merkle tree from encoded headers
	tree, err := merklearray.BuildVectorCommitmentTree(
		lightHeaders,
		crypto.HashFactory{HashType: crypto.Sha256},
	)
	if err != nil {
		return nil, err
	}
	return tree.Root(), nil
}

// FetchLightHeaders returns the headers of the blocks in the interval
func FetchLightHeaders(l BlockHeaderFetcher, stateProofInterval uint64, latestRound basics.Round) ([]bookkeeping.LightBlockHeader, error) {
	blkHdrArr := make(lightBlockHeaders, stateProofInterval)
	firstRound := latestRound - basics.Round(stateProofInterval) + 1

	for i := uint64(0); i < stateProofInterval; i++ {
		rnd := firstRound + basics.Round(i)
		hdr, err := l.BlockHdr(rnd)
		if err != nil {
			return nil, err
		}
		blkHdrArr[i] = hdr.ToLightBlockHeader()
	}
	return blkHdrArr, nil
}

// GenerateProofOfLightBlockHeaders sets up a tree over the blkHdrArr and returns merkle proof over one of the blocks.
func GenerateProofOfLightBlockHeaders(stateProofInterval uint64, blkHdrArr lightBlockHeaders, blockIndex uint64) (*merklearray.SingleLeafProof, error) {
	if blkHdrArr.Length() != stateProofInterval {
		return nil, fmt.Errorf("received wrong amount of block headers. err: %w - %d != %d", errInvalidParams, blkHdrArr.Length(), stateProofInterval)
	}

	tree, err := merklearray.BuildVectorCommitmentTree(
		blkHdrArr,
		crypto.HashFactory{HashType: crypto.Sha256},
	)
	if err != nil {
		return nil, err
	}

	return tree.ProveSingleLeaf(blockIndex)
}
