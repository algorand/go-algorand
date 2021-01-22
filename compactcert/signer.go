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
	"context"
	"database/sql"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
)

// sigFromAddr encapsulates a signature on a block header, which
// will eventually be used to form a compact certificate for that
// block.
type sigFromAddr struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Signer basics.Address          `codec:"signer"`
	Round  basics.Round            `codec:"rnd"`
	Sig    crypto.OneTimeSignature `codec:"sig"`
}

func (ccw *Worker) signer() {
	var nextrnd basics.Round

	for {
		latest := ccw.ledger.Latest()
		latestHdr, err := ccw.ledger.BlockHdr(latest)
		if err != nil {
			ccw.log.Warnf("ccw.signer(): BlockHdr(latest %d): %v", latest, err)
			time.Sleep(1 * time.Second)
			continue
		}

		nextrnd := latestHdr.CompactCertNextRound
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
				continue
			}

			ccw.signBlock(hdr)
			nextrnd++

		case <-ccw.ctx.Done():
			ccw.wg.Done()
			return
		}
	}
}

func (ccw *Worker) signBlock(hdr bookkeeping.BlockHeader) {
	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.CompactCertRounds == 0 {
		return
	}

	// Only sign blocks that are a multiple of CompactCertRounds.
	if hdr.Round%basics.Round(proto.CompactCertRounds) != 0 {
		return
	}

	keys := ccw.accts.Keys()
	if len(keys) == 0 {
		// No keys, nothing to do.
		return
	}

	// Compact cert gets signed by the next round after the block,
	// because by the time agreement is reached on the block,
	// ephemeral keys for that round could be deleted.
	sigKeyRound := hdr.Round + 1

	// votersRound is the round containing the merkle root commitment
	// for the voters that are going to sign this block.
	votersRound := hdr.Round.SubSaturate(basics.Round(proto.CompactCertRounds))
	votersHdr, err := ccw.ledger.BlockHdr(votersRound)
	if err != nil {
		ccw.log.Warnf("ccw.signBlock(%d): BlockHdr(%d): %v", hdr.Round, votersRound, err)
		return
	}

	if votersHdr.CompactCertVoters.IsZero() {
		// No voter commitment, perhaps because compact certs were
		// just enabled.
		return
	}

	votersProto := config.Consensus[votersHdr.CurrentProtocol]

	var sigs []sigFromAddr
	var sigkeys []crypto.OneTimeSignatureVerifier
	for _, key := range ccw.accts.Keys() {
		if key.FirstValid <= sigKeyRound && sigKeyRound <= key.LastValid {
			keyDilution := key.KeyDilution
			if keyDilution == 0 {
				keyDilution = votersProto.DefaultKeyDilution
			}

			ephID := basics.OneTimeIDForRound(sigKeyRound, keyDilution)
			sig := key.Voting.Sign(ephID, hdr)

			sigs = append(sigs, sigFromAddr{
				Signer: key.Parent,
				Round:  hdr.Round,
				Sig:    sig,
			})
			sigkeys = append(sigkeys, key.Voting.OneTimeSignatureVerifier)
		}
	}

	for _, sfa := range sigs {
		_, err = ccw.handleSig(sfa, nil)
		if err != nil {
			ccw.log.Warnf("ccw.signBlock(%d): handleSig: %v", hdr.Round, err)
		}
	}
}

// LatestSigsFromThisNode returns information about compact cert signatures from
// this node's participation keys that are already stored durably on disk.  In
// particular, we return the round nunmber of the latest block signed with each
// account's participation key.  This is intended for use by the ephemeral key
// logic: since we already have these signatures stored on disk, it is safe to
// delete the corresponding ephemeral private keys.
func (ccw *Worker) LatestSigsFromThisNode() (map[basics.Address]basics.Round, error) {
	res := make(map[basics.Address]basics.Round)
	err := ccw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		sigs, err := getPendingSigsFromThisNode(tx)
		if err != nil {
			return err
		}

		for rnd, psigs := range sigs {
			for _, psig := range psigs {
				if res[psig.signer] < rnd {
					res[psig.signer] = rnd
				}
			}
		}

		return nil
	})
	return res, err
}
