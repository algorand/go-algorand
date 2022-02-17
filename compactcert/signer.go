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
	"context"
	"database/sql"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
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

		nextrnd = latestHdr.CompactCert[protocol.CompactCertBasic].CompactCertNextRound
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

func (ccw *Worker) signBlock(hdr bookkeeping.BlockHeader) {
	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.CompactCertRounds == 0 {
		return
	}

	// Only sign blocks that are a multiple of CompactCertRounds.
	if hdr.Round%basics.Round(proto.CompactCertRounds) != 0 {
		return
	}

	keys := ccw.accts.StateProofKeys(hdr.Round)
	if len(keys) == 0 {
		// No keys, nothing to do.
		return
	}

	// votersRound is the round containing the merkle root commitment
	// for the voters that are going to sign this block.
	votersRound := hdr.Round.SubSaturate(basics.Round(proto.CompactCertRounds))
	votersHdr, err := ccw.ledger.BlockHdr(votersRound)
	if err != nil {
		ccw.log.Warnf("ccw.signBlock(%d): BlockHdr(%d): %v", hdr.Round, votersRound, err)
		return
	}

	if votersHdr.CompactCert[protocol.CompactCertBasic].CompactCertVoters.IsEmpty() {
		// No voter commitment, perhaps because compact certs were
		// just enabled.
		return
	}

	sigs := make([]sigFromAddr, 0, len(keys))

	for _, key := range keys {
		if key.FirstValid > hdr.Round || hdr.Round > key.LastValid {
			continue
		}

		if key.StateProofSecrets == nil {
			ccw.log.Warnf("ccw.signBlock(%d): empty state proof secrets for round", hdr.Round)
			continue
		}

		sig, err := key.StateProofSecrets.Sign(hdr)
		if err != nil {
			ccw.log.Warnf("ccw.signBlock(%d): StateProofSecrets.Sign: %v", hdr.Round, err)
			continue
		}

		sigs = append(sigs, sigFromAddr{
			Signer: key.Account,
			Round:  hdr.Round,
			Sig:    sig,
		})
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
