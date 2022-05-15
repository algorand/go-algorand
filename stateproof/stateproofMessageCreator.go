package stateproof

import (
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
)

var errInvalidParams = errors.New("provided parameters are invalid")
var errOutOfBound = errors.New("request pos is out of array bounds")

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
	return b.blockHeaders[pos], nil
}

// GenerateStateProofMessage builds a vector commitment from the block headers of the entire interval (up until current round), and returns the root
// for the account to sign upon. The tree can be stored for performance but does not have to be since it can always be rebuilt from scratch.
// This is the message that state proofs will attest to.
func GenerateStateProofMessage(l Ledger, votersRound bookkeeping.BlockHeader, latestRoundInInterval bookkeeping.BlockHeader, stateProofInterval uint64) (stateproofmsg.Message, error) {
	if latestRoundInInterval.Round < basics.Round(stateProofInterval) {
		return stateproofmsg.Message{}, fmt.Errorf("GenerateStateProofMessage stateProofRound must be >= than stateproofInterval (%w)", errInvalidParams)
	}
	var blkHdrArr blockHeadersArray
	blkHdrArr.blockHeaders = make([]bookkeeping.BlockHeader, stateProofInterval)
	firstRound := latestRoundInInterval.Round - basics.Round(stateProofInterval) + 1
	for i := uint64(0); i < stateProofInterval; i++ {
		rnd := firstRound + basics.Round(i)
		hdr, err := l.BlockHdr(rnd)
		if err != nil {
			return stateproofmsg.Message{}, err
		}
		blkHdrArr.blockHeaders[i] = hdr
	}

	// Build merkle tree from encoded headers
	tree, err := merklearray.BuildVectorCommitmentTree(blkHdrArr, crypto.HashFactory{HashType: crypto.Sha256})
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	provenWeight, err := ledger.GetProvenWeight(votersRound, latestRoundInInterval)
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	return stateproofmsg.Message{
		BlockHeadersCommitment: tree.Root().ToSlice(),
		VotersCommitment:       votersRound.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		LnProvenWeight:         provenWeight,
		FirstAttestedRound:     uint64(votersRound.Round) + 1,
		LastAttestedRound:      uint64(latestRoundInInterval.Round),
	}, nil
}
