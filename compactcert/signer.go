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
	"github.com/algorand/go-algorand/ledger"
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
	var sigkeys []crypto.OneTimeSignatureVerifier
	var nextrnd basics.Round

	err := ccw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		sigkeys, nextrnd, err = getSignedLast(tx)
		return
	})

	if err != nil {
		nextrnd := ccw.ledger.Latest() + 1
		ccw.log.Warnf("ccw.signer(): using nextrnd=%d, cannot obtain last signed: %v", nextrnd, err)
	} else {
		// Check if we have any keys in common with the last signed set.
		// If so, try to sign the next round after that.  Otherwise, if
		// there is no overlap in keys, start with latest round.
		sigkeysmap := make(map[crypto.OneTimeSignatureVerifier]bool)
		for _, key := range sigkeys {
			sigkeysmap[key] = true
		}

		overlap := false
		for _, key := range ccw.accts.Keys() {
			if sigkeysmap[key.Voting.OneTimeSignatureVerifier] {
				overlap = true
			}
		}

		if overlap {
			nextrnd++
		} else {
			nextrnd = ccw.ledger.Latest() + 1
		}
	}

	for {
		select {
		case <-ccw.ledger.Wait(nextrnd):
			hdr, err := ccw.ledger.BlockHdr(nextrnd)
			if err != nil {
				ccw.log.Warnf("ccw.signer(): BlockHdr(%d): %v", nextrnd, err)
				switch err.(type) {
				case ledger.ErrNoEntry:
					nextrnd = ccw.ledger.Latest() + 1

				default:
					time.Sleep(1 * time.Second)
				}
			} else {
				ccw.signBlock(hdr)
				nextrnd++
			}

		case <-ccw.ctx.Done():
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

	err = ccw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return setSignedLast(tx, hdr.Round, sigkeys)
	})
	if err != nil {
		ccw.log.Warnf("ccw.signBlock(%d): setSignedLast: %v", hdr.Round, err)
	}
}
