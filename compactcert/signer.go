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
	"errors"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproof"
	"github.com/algorand/go-algorand/protocol"
)

// sigFromAddr encapsulates a signature on a block header, which
// will eventually be used to form a compact certificate for that
// block.
type sigFromAddr struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Signer basics.Address            `codec:"signer"`
	Round  basics.Round              `codec:"rnd"`
	Sig    merklesignature.Signature `codec:"sig"`
}

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

func (ccw *Worker) signer(latest basics.Round) {
	var nextrnd basics.Round

restart:
	for {
		latestHdr, err := ccw.ledger.BlockHdr(latest)
		if err != nil {
			ccw.log.Warnf("ccw.signer(): BlockHdr(latest %d): %v", latest, err)
			time.Sleep(1 * time.Second)
			latest = ccw.ledger.Latest()
			continue
		}

		nextrnd = latestHdr.CompactCert[protocol.CompactCertBasic].StateProofNextRound
		if nextrnd == 0 {
			// Compact certs not enabled yet.  Keep monitoring new blocks.
			nextrnd = latest + 1
		}
		break
	}

	for {
		select {
		case <-ccw.ledger.Wait(nextrnd):
			hdr, err := ccw.ledger.BlockHdr(nextrnd)
			if err != nil {
				ccw.log.Warnf("ccw.signer(): BlockHdr(next %d): %v", nextrnd, err)
				time.Sleep(1 * time.Second)
				latest = ccw.ledger.Latest()
				goto restart
			}

			ccw.signBlock(hdr)
			ccw.signedBlock(nextrnd)

			nextrnd++

		case <-ccw.ctx.Done():
			ccw.wg.Done()
			return
		}
	}
}

// GenerateStateProofMessage builds a merkle tree from the block headers of the entire interval (up until current round), and returns the root
// for the account to sign upon. The tree can be stored for performance but does not have to be since it can always be rebuilt from scratch.
// This is the message the Compact Certificate will attest to.
func GenerateStateProofMessage(ledger Ledger, compactCertRound basics.Round, compactCertInterval uint64) (stateproof.Message, error) {
	if compactCertRound < basics.Round(compactCertInterval) {
		return stateproof.Message{}, fmt.Errorf("GenerateStateProofMessage compactCertRound must be >= than compactCertInterval (%w)", errInvalidParams)
	}
	var blkHdrArr blockHeadersArray
	blkHdrArr.blockHeaders = make([]bookkeeping.BlockHeader, compactCertInterval)
	firstRound := compactCertRound - basics.Round(compactCertInterval) + 1
	for i := uint64(0); i < compactCertInterval; i++ {
		rnd := firstRound + basics.Round(i)
		hdr, err := ledger.BlockHdr(rnd)
		if err != nil {
			return stateproof.Message{}, err
		}
		blkHdrArr.blockHeaders[i] = hdr
	}

	// Build merkle tree from encoded headers
	tree, err := merklearray.BuildVectorCommitmentTree(blkHdrArr, crypto.HashFactory{HashType: crypto.Sha256})
	if err != nil {
		return stateproof.Message{}, err
	}

	return stateproof.Message{
		BlockHeadersCommitment: tree.Root().ToSlice(),
	}, nil
}

func (ccw *Worker) signBlock(hdr bookkeeping.BlockHeader) {
	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.StateProofInterval == 0 {
		return
	}

	// Only sign blocks that are a multiple of StateProofInterval.
	if hdr.Round%basics.Round(proto.StateProofInterval) != 0 {
		return
	}

	keys := ccw.accts.StateProofKeys(hdr.Round)
	if len(keys) == 0 {
		// No keys, nothing to do.
		return
	}

	// votersRound is the round containing the merkle root commitment
	// for the voters that are going to sign this block.
	votersRound := hdr.Round.SubSaturate(basics.Round(proto.StateProofInterval))
	votersHdr, err := ccw.ledger.BlockHdr(votersRound)
	if err != nil {
		ccw.log.Warnf("ccw.signBlock(%d): BlockHdr(%d): %v", hdr.Round, votersRound, err)
		return
	}

	if votersHdr.CompactCert[protocol.CompactCertBasic].StateProofVotersCommitment.IsEmpty() {
		// No voter commitment, perhaps because compact certs were
		// just enabled.
		return
	}

	sigs := make([]sigFromAddr, 0, len(keys))
	ids := make([]account.ParticipationID, 0, len(keys))

	stateproofMessage, err := GenerateStateProofMessage(ccw.ledger, hdr.Round, proto.StateProofInterval)
	if err != nil {
		ccw.log.Warnf("ccw.signBlock(%d): GenerateStateProofMessage: %v", hdr.Round, err)
		return
	}
	hashedStateproofMessage := stateproofMessage.IntoStateProofMessageHash()

	for _, key := range keys {
		if key.FirstValid > hdr.Round || hdr.Round > key.LastValid {
			continue
		}

		if key.StateProofSecrets == nil {
			ccw.log.Warnf("ccw.signBlock(%d): empty state proof secrets for round", hdr.Round)
			continue
		}

		sig, err := key.StateProofSecrets.SignBytes(hashedStateproofMessage[:])
		if err != nil {
			ccw.log.Warnf("ccw.signBlock(%d): StateProofSecrets.Sign: %v", hdr.Round, err)
			continue
		}

		sigs = append(sigs, sigFromAddr{
			Signer: key.Account,
			Round:  hdr.Round,
			Sig:    sig,
		})
		ids = append(ids, key.ParticipationID)
	}

	// any error in handle sig indicates the signature wasn't stored in disk, thus we cannot delete the key.
	for i, sfa := range sigs {
		if _, err := ccw.handleSig(sfa, nil); err != nil {
			ccw.log.Warnf("ccw.signBlock(%d): handleSig: %v", hdr.Round, err)
			continue
		}

		// Safe to delete key for sfa.Round because the signature is now stored in the disk.
		if err := ccw.accts.DeleteStateProofKey(ids[i], sfa.Round); err != nil {
			ccw.log.Warnf("ccw.signBlock(%d): DeleteStateProofKey: %v", hdr.Round, err)
		}
	}
}
