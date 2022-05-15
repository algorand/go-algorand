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
	return b.blockHeaders[pos], nil
}

// GenerateStateProofMessage returns a stateproof message that contains all the necessary data for proving on Algorand's state.
// In addition, it also includes the trusted data for the next stateproof verification
func GenerateStateProofMessage(l Ledger, votersRound uint64, latestRoundInInterval bookkeeping.BlockHeader) (stateproofmsg.Message, error) {
	proto := config.Consensus[latestRoundInInterval.CurrentProtocol]
	stateProofInterval := proto.StateProofInterval

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

	totalWeight := latestRoundInInterval.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight.ToUint64()
	provenWeight, overflowed := basics.Muldiv(totalWeight, uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed {
		err := fmt.Errorf("GenerateStateProofMessage err: %w -  %d %d * %d / (1<<32)",
			errProvenWeightOverflow, latestRoundInInterval.Round, totalWeight, proto.StateProofWeightThreshold)
		return stateproofmsg.Message{}, err
	}

	lnProvenWeight, err := stateproof.LnIntApproximation(provenWeight)
	if err != nil {
		return stateproofmsg.Message{}, err
	}

	return stateproofmsg.Message{
		BlockHeadersCommitment: tree.Root().ToSlice(),
		VotersCommitment:       latestRoundInInterval.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		LnProvenWeight:         lnProvenWeight,
		FirstAttestedRound:     votersRound + 1,
		LastAttestedRound:      uint64(latestRoundInInterval.Round),
	}, nil
}
