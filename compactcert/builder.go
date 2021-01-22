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
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

func (ccw *Worker) builderForRound(rnd basics.Round) (builder, error) {
	hdr, err := ccw.ledger.BlockHdr(rnd)
	if err != nil {
		return builder{}, err
	}

	hdrProto := config.Consensus[hdr.CurrentProtocol]
	votersRnd := rnd.SubSaturate(basics.Round(hdrProto.CompactCertRounds))
	votersHdr, err := ccw.ledger.BlockHdr(votersRnd)
	if err != nil {
		return builder{}, err
	}

	lookback := votersRnd.SubSaturate(basics.Round(hdrProto.CompactCertVotersLookback))
	voters, err := ccw.ledger.CompactCertVoters(lookback)
	if err != nil {
		return builder{}, err
	}

	if voters == nil {
		// Voters not tracked for that round.  Might not be a valid
		// compact cert round; compact certs might not be enabled; etc.
		return builder{}, fmt.Errorf("voters not tracked for lookback round %d", lookback)
	}

	p, err := ledger.CompactCertParams(votersHdr, hdr)
	if err != nil {
		return builder{}, err
	}

	var res builder
	res.votersHdr = votersHdr
	res.voters = voters
	res.Builder, err = compactcert.MkBuilder(p, voters.Participants, voters.Tree)
	if err != nil {
		return builder{}, err
	}

	ccw.builders[rnd] = res
	return res, nil
}

func (ccw *Worker) initBuilders() {
	ccw.mu.Lock()
	defer ccw.mu.Unlock()

	var roundSigs map[basics.Round][]pendingSig
	err := ccw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx)
		return
	})
	if err != nil {
		ccw.log.Warnf("initBuilders: getPendingSigs: %v", err)
		return
	}

	for rnd, sigs := range roundSigs {
		_, ok := ccw.builders[rnd]
		if ok {
			ccw.log.Warnf("initBuilders: round %d already present", rnd)
			continue
		}

		builder, err := ccw.builderForRound(rnd)
		if err != nil {
			ccw.log.Warnf("initBuilders: builderForRound(%d): %v", rnd, err)
			continue
		}

		for _, sig := range sigs {
			pos, ok := builder.voters.AddrToPos[sig.signer]
			if !ok {
				ccw.log.Warnf("initBuilders: cannot find %v in round %d", sig.signer, rnd)
				continue
			}

			err = builder.Add(pos, sig.sig, false)
			if err != nil {
				ccw.log.Warnf("initBuilders: cannot add %v in round %d: %v", sig.signer, rnd, err)
				continue
			}
		}
	}
}

func (ccw *Worker) handleSigMessage(msg network.IncomingMessage) network.OutgoingMessage {
	var ssig sigFromAddr
	err := protocol.Decode(msg.Data, &ssig)
	if err != nil {
		ccw.log.Warnf("ccw.handleSigMessage(): decode: %v", err)
		return network.OutgoingMessage{Action: network.Disconnect}
	}

	fwd, err := ccw.handleSig(ssig, msg.Sender)
	if err != nil {
		ccw.log.Warnf("ccw.handleSigMessage(): %v", err)
	}

	return network.OutgoingMessage{Action: fwd}
}

func (ccw *Worker) handleSig(sfa sigFromAddr, sender network.Peer) (network.ForwardingPolicy, error) {
	ccw.mu.Lock()
	defer ccw.mu.Unlock()

	builder, ok := ccw.builders[sfa.Round]
	if !ok {
		latest := ccw.ledger.Latest()
		latestHdr, err := ccw.ledger.BlockHdr(latest)
		if err != nil {
			return network.Disconnect, err
		}

		if sfa.Round < latestHdr.CompactCertNextRound {
			// Already have a complete compact cert in ledger.
			// Ignore this sig.
			return network.Ignore, nil
		}

		builder, err = ccw.builderForRound(sfa.Round)
		if err != nil {
			return network.Disconnect, err
		}
	}

	pos, ok := builder.voters.AddrToPos[sfa.Signer]
	if !ok {
		return network.Disconnect, fmt.Errorf("handleSig: %v not in participants for %d", sfa.Signer, sfa.Round)
	}

	if builder.Present(pos) {
		// Signature already part of the builder, ignore.
		return network.Ignore, nil
	}

	err := builder.Add(pos, sfa.Sig, true)
	if err != nil {
		return network.Disconnect, err
	}

	err = ccw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return addPendingSig(tx, sfa.Round, pendingSig{
			signer:       sfa.Signer,
			sig:          sfa.Sig,
			fromThisNode: sender == nil,
		})
	})
	if err != nil {
		return network.Ignore, err
	}

	return network.Broadcast, nil
}

func (ccw *Worker) builder(latest basics.Round) {
	// We clock the building of compact certificates based on new
	// blocks.  This is because the acceptable compact certificate
	// size grows over time, so that we aim to construct an extremely
	// compact certificate upfront, but if that doesn't work out, we
	// will settle for a larger certificate.  New blocks also tell us
	// if a compact cert has been committed, so that we can stop trying
	// to build it.
	for {
		ccw.tryBuilding()

		nextrnd := latest + 1
		select {
		case <-ccw.ctx.Done():
			ccw.wg.Done()
			return

		case <-ccw.ledger.Wait(nextrnd):
			// Continue on
		}

		// See if any new compact certificates were formed, according to
		// the new block, which would mean we can clean up some builders.
		hdr, err := ccw.ledger.BlockHdr(nextrnd)
		if err != nil {
			ccw.log.Warnf("ccw.builder: BlockHdr(%d): %v", nextrnd, err)
			continue
		} else {
			ccw.deleteOldSigs(hdr.CompactCertNextRound)
		}

		// Broadcast signatures based on the previous block(s) that
		// were agreed upon.  This ensures that, if we send a signature
		// for block R, nodes will have already verified block R, because
		// block R+1 has been formed.
		proto := config.Consensus[hdr.CurrentProtocol]
		newLatest := ccw.ledger.Latest()
		for r := latest; r < newLatest; r++ {
			// Wait for the signer to catch up; mostly relevant in tests.
			ccw.waitForSignedBlock(r)

			ccw.broadcastSigs(r, proto)
		}
		latest = newLatest
	}
}

// broadcastSigs periodically broadcasts pending signatures for rounds
// that have not been able to form a compact certificate.
//
// Signature re-broadcasting happens in periods of proto.CompactCertRounds
// rounds.
//
// In the first half of each such period, signers of a block broadcast their
// own signatures; this is the expected common path.
//
// In the second half of each such period, any signatures seen by this node
// are broadcast.
//
// The broadcast schedule is randomized by the address of the block signer,
// for load-balancing over time.
func (ccw *Worker) broadcastSigs(brnd basics.Round, proto config.ConsensusParams) {
	if proto.CompactCertRounds == 0 {
		return
	}

	ccw.mu.Lock()
	defer ccw.mu.Unlock()

	var roundSigs map[basics.Round][]pendingSig
	err := ccw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		if brnd%basics.Round(proto.CompactCertRounds) < basics.Round(proto.CompactCertRounds/2) {
			roundSigs, err = getPendingSigsFromThisNode(tx)
		} else {
			roundSigs, err = getPendingSigs(tx)
		}
		return
	})
	if err != nil {
		ccw.log.Warnf("broadcastSigs: getPendingSigs: %v", err)
		return
	}

	for rnd, sigs := range roundSigs {
		if rnd > brnd {
			// Signature is for later block than brnd.  This could happen
			// during catchup or testing.  The caller's loop will eventually
			// invoke this function with a suitably high brnd.
			continue
		}

		for _, sig := range sigs {
			// Randomize which sigs get broadcast over time.
			addr64 := binary.LittleEndian.Uint64(sig.signer[:])
			if addr64%(proto.CompactCertRounds/2) != uint64(brnd)%(proto.CompactCertRounds/2) {
				continue
			}

			sfa := sigFromAddr{
				Signer: sig.signer,
				Round:  rnd,
				Sig:    sig.sig,
			}
			err = ccw.net.Broadcast(context.Background(), protocol.CompactCertSigTag,
				protocol.Encode(&sfa), false, nil)
			if err != nil {
				ccw.log.Warnf("broadcastSigs: Broadcast for %d: %v", rnd, err)
			}
		}
	}
}

func (ccw *Worker) deleteOldSigs(nextCert basics.Round) {
	ccw.mu.Lock()
	defer ccw.mu.Unlock()

	err := ccw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return deletePendingSigsBeforeRound(tx, nextCert)
	})
	if err != nil {
		ccw.log.Warnf("deletePendingSigsBeforeRound(%d): %v", nextCert, err)
	}

	for rnd := range ccw.builders {
		if rnd < nextCert {
			delete(ccw.builders, rnd)
		}
	}
}

func (ccw *Worker) tryBuilding() {
	ccw.mu.Lock()
	defer ccw.mu.Unlock()

	for rnd, b := range ccw.builders {
		firstValid := ccw.ledger.Latest() + 1
		acceptableWeight := ledger.AcceptableCompactCertWeight(b.votersHdr, firstValid)
		if b.SignedWeight() < acceptableWeight {
			// Haven't signed enough to build the cert at this time..
			continue
		}

		if !b.Ready() {
			// Haven't gotten enough signatures to get past ProvenWeight
			continue
		}

		cert, err := b.Build()
		if err != nil {
			ccw.log.Warnf("ccw.tryBuilding: building compact cert for %d: %v", rnd, err)
			continue
		}

		var stxn transactions.SignedTxn
		stxn.Txn.Type = protocol.CompactCertTx
		stxn.Txn.Sender = transactions.CompactCertSender
		stxn.Txn.FirstValid = firstValid
		stxn.Txn.LastValid = firstValid + basics.Round(b.voters.Proto.MaxTxnLife)
		stxn.Txn.GenesisHash = ccw.ledger.GenesisHash()
		stxn.Txn.CertRound = rnd
		stxn.Txn.Cert = *cert
		err = ccw.txnSender.BroadcastSignedTxGroup([]transactions.SignedTxn{stxn})
		if err != nil {
			ccw.log.Warnf("ccw.tryBuilding: broadcasting compact cert txn for %d: %v", rnd, err)
		}
	}
}

func (ccw *Worker) signedBlock(r basics.Round) {
	ccw.mu.Lock()
	ccw.signed = r
	ccw.mu.Unlock()

	select {
	case ccw.signedCh <- struct{}{}:
	default:
	}
}

func (ccw *Worker) lastSignedBlock() basics.Round {
	ccw.mu.Lock()
	defer ccw.mu.Unlock()
	return ccw.signed
}

func (ccw *Worker) waitForSignedBlock(r basics.Round) {
	for {
		if r <= ccw.lastSignedBlock() {
			return
		}

		select {
		case <-ccw.ctx.Done():
			return
		case <-ccw.signedCh:
		}
	}
}
