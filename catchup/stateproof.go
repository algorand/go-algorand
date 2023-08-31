// Copyright (C) 2019-2023 Algorand, Inc.
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

package catchup

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// This file implements state-proof-based validation of new blocks,
// for catching up the state of a node with the rest of the network.

// StateProofVerificationContext specifies the parameters needed to
// verify a state proof for the catchup code.
type StateProofVerificationContext struct {
	// LastRound is the LastAttestedRound in the state proof message
	// that we expect to verify with these parameters.
	LastRound basics.Round

	// LnProvenWeight is passed to stateproof.MkVerifierWithLnProvenWeight.
	LnProvenWeight uint64

	// VotersCommitment is passed to stateproof.MkVerifierWithLnProvenWeight.
	VotersCommitment crypto.GenericDigest

	// Proto specifies the protocol in which state proofs were enabled,
	// used to determine StateProofStrengthTarget and StateProofInterval.
	Proto protocol.ConsensusVersion
}

func spSchemaUpgrade0(_ context.Context, tx *sql.Tx, _ bool) error {
	const createProofsTable = `CREATE TABLE IF NOT EXISTS proofs (
		lastrnd integer,
		proto text,
		msg blob,
		UNIQUE (lastrnd))`

	_, err := tx.Exec(createProofsTable)
	return err
}

func (s *Service) initStateProofs() error {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	if s.stateproofdb == nil {
		return nil
	}

	migrations := []db.Migration{
		spSchemaUpgrade0,
	}

	err := db.Initialize(*s.stateproofdb, migrations)
	if err != nil {
		return err
	}

	stateproofs := make(map[basics.Round]stateProofInfo)
	var stateproofmin basics.Round
	var stateproofmax basics.Round
	var stateproofproto protocol.ConsensusVersion

	err = s.stateproofdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.Query("SELECT proto, msg FROM proofs ORDER BY lastrnd")
		if err != nil {
			return err
		}

		defer rows.Close()
		for rows.Next() {
			var proto protocol.ConsensusVersion
			var msgbuf []byte
			err := rows.Scan(&proto, &msgbuf)
			if err != nil {
				s.log.Warnf("initStateProofs: cannot scan proof from db: %v", err)
				continue
			}

			var msg stateproofmsg.Message
			err = protocol.Decode(msgbuf, &msg)
			if err != nil {
				s.log.Warnf("initStateProofs: cannot decode proof from db: %v", err)
				continue
			}

			stateproofs[msg.LastAttestedRound] = stateProofInfo{
				message: msg,
				proto:   proto,
			}
			stateproofmax = msg.LastAttestedRound
			if stateproofmin == 0 {
				stateproofmin = msg.LastAttestedRound
				stateproofproto = proto
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.stateproofs = stateproofs
	s.stateproofmin = stateproofmin
	s.stateproofmax = stateproofmax
	s.stateproofproto = stateproofproto

	return nil
}

// addStateProof adds a verified state proof message.
func (s *Service) addStateProof(msg stateproofmsg.Message, proto protocol.ConsensusVersion) {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	if s.stateproofdb != nil {
		err := s.stateproofdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO proofs (lastrnd, proto, msg) VALUES (?, ?, ?)",
				msg.LastAttestedRound, proto, protocol.Encode(&msg))
			return err
		})
		if err != nil {
			s.log.Warnf("addStateProof: database error: %v", err)
		}
	}

	if s.stateproofmin == 0 {
		s.stateproofmin = msg.LastAttestedRound
		s.stateproofproto = proto
	}
	if msg.LastAttestedRound > s.stateproofmax {
		s.stateproofmax = msg.LastAttestedRound
	}
	s.stateproofs[msg.LastAttestedRound] = stateProofInfo{
		message: msg,
		proto:   proto,
	}

	for r := msg.FirstAttestedRound; r < msg.LastAttestedRound; r++ {
		ch, ok := s.stateproofwait[r]
		if ok {
			close(ch)
			delete(s.stateproofwait, r)
		}
	}
}

// cleanupStateProofs removes state proofs that are for the latest
// round or earlier.
func (s *Service) cleanupStateProofs(latest basics.Round) {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	if s.stateproofmin == 0 {
		return
	}

	if s.stateproofdb != nil {
		err := s.stateproofdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.Exec("DELETE FROM proofs WHERE lastrnd<=?", latest)
			return err
		})
		if err != nil {
			s.log.Warnf("cleanupStateProofs: database error: %v", err)
		}
	}

	for s.stateproofmin <= latest {
		delete(s.stateproofs, s.stateproofmin)
		s.stateproofmin += basics.Round(config.Consensus[s.stateproofproto].StateProofInterval)
	}
}

// nextStateProofVerifier() returns the latest state proof verification
// context that we have access to.  This might be based on the latest block
// in the ledger, or based on the latest state proof (beyond the end of the
// ledger) that we have, or based on well-known "renaissance block" values.
//
// The return value might be nil if no verification context is available.
func (s *Service) nextStateProofVerifier() *StateProofVerificationContext {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	// As a baseline, use the renaissance verification context (if present).
	res := s.renaissance

	// Check if we have a more recent verified state proof in memory.
	lastProof, ok := s.stateproofs[s.stateproofmax]
	if ok && (res == nil || lastProof.message.LastAttestedRound >= res.LastRound) {
		res = &StateProofVerificationContext{
			LastRound:        lastProof.message.LastAttestedRound + basics.Round(config.Consensus[lastProof.proto].StateProofInterval),
			LnProvenWeight:   lastProof.message.LnProvenWeight,
			VotersCommitment: lastProof.message.VotersCommitment,
			Proto:            s.stateproofproto,
		}
	}

	// Check if the ledger has a more recent state proof verification context.
	latest := s.ledger.LastRound()

	// If we don't know state proof parameters yet, check the ledger.
	proto := s.stateproofproto
	params, paramsOk := config.Consensus[proto]
	if !paramsOk {
		hdr, err := s.ledger.BlockHdr(latest)
		if err != nil {
			s.log.Warnf("nextStateProofVerifier: BlockHdr(%d): %v", latest, err)
		} else {
			proto = hdr.CurrentProtocol
			params, paramsOk = config.Consensus[proto]
		}
	}

	if !paramsOk || params.StateProofInterval == 0 {
		// Ledger's latest block does not support state proof.
		// Return whatever verification context we've found so far.
		return res
	}

	// The next state proof verification context we should expect from
	// the ledger is for StateProofInterval in the future from the most
	// recent multiple of StateProofInterval.
	nextLastRound := latest.RoundDownToMultipleOf(basics.Round(params.StateProofInterval)) + basics.Round(params.StateProofInterval)
	if res != nil && nextLastRound <= res.LastRound {
		// We already have a verification context that's no older.
		return res
	}

	vctx, err := s.ledger.GetStateProofVerificationContext(nextLastRound)
	if err != nil {
		s.log.Warnf("nextStateProofVerifier: GetStateProofVerificationContext(%d): %v", nextLastRound, err)
		return res
	}

	provenWeight, overflowed := basics.Muldiv(vctx.OnlineTotalWeight.ToUint64(), uint64(params.StateProofWeightThreshold), 1<<32)
	if overflowed {
		s.log.Warnf("nextStateProofVerifier: overflow computing provenWeight[%d]: %d * %d / (1<<32)",
			nextLastRound, vctx.OnlineTotalWeight.ToUint64(), params.StateProofWeightThreshold)
		return res
	}

	lnProvenWt, err := stateproof.LnIntApproximation(provenWeight)
	if err != nil {
		s.log.Warnf("nextStateProofVerifier: LnIntApproximation(%d): %v", provenWeight, err)
		return res
	}

	return &StateProofVerificationContext{
		LastRound:        nextLastRound,
		LnProvenWeight:   lnProvenWt,
		VotersCommitment: vctx.VotersCommitment,
		Proto:            proto,
	}
}

// SetRenaissance sets the "renaissance" parameters for validating state proofs.
func (s *Service) SetRenaissance(r StateProofVerificationContext) {
	s.renaissance = &r
}

// SetRenaissanceFromConfig sets the "renaissance" parameters for validating state
// proofs based on the settings in the specified cfg.
func (s *Service) SetRenaissanceFromConfig(cfg config.Local) {
	if cfg.RenaissanceCatchupRound == 0 {
		return
	}

	votersCommitment, err := base64.StdEncoding.DecodeString(cfg.RenaissanceCatchupVotersCommitment)
	if err != nil {
		s.log.Warnf("SetRenaissanceFromConfig: cannot decode voters commitment: %v", err)
		return
	}

	vc := StateProofVerificationContext{
		LastRound:        basics.Round(cfg.RenaissanceCatchupRound),
		LnProvenWeight:   cfg.RenaissanceCatchupLnProvenWeight,
		VotersCommitment: votersCommitment,
		Proto:            protocol.ConsensusVersion(cfg.RenaissanceCatchupProto),
	}

	interval := basics.Round(config.Consensus[vc.Proto].StateProofInterval)
	if interval == 0 {
		s.log.Warnf("SetRenaissanceFromConfig: state proofs not enabled in specified proto %s", vc.Proto)
		return
	}

	if (vc.LastRound % interval) != 0 {
		s.log.Warnf("SetRenaissanceFromConfig: round %d not multiple of state proof interval %d", vc.LastRound, interval)
		return
	}

	s.SetRenaissance(vc)
}

func (s *Service) stateProofWaitEnable() {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	s.stateproofwait = make(map[basics.Round]chan struct{})
}

func (s *Service) stateProofWaitDisable() {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	for _, ch := range s.stateproofwait {
		close(ch)
	}
	s.stateproofwait = nil
}

func (s *Service) stateProofWait(r basics.Round) chan struct{} {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	if r <= s.stateproofmax {
		ch := make(chan struct{})
		close(ch)
		return ch
	}

	if s.stateproofwait == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}

	ch, ok := s.stateproofwait[r]
	if !ok {
		ch = make(chan struct{})
		s.stateproofwait[r] = ch
	}

	return ch
}

func (s *Service) getStateProof(r basics.Round) *stateProofInfo {
	s.stateproofmu.Lock()
	defer s.stateproofmu.Unlock()

	interval := config.Consensus[s.stateproofproto].StateProofInterval
	if interval == 0 {
		return nil
	}

	proofrnd := r.RoundUpToMultipleOf(basics.Round(interval))
	proofInfo, ok := s.stateproofs[proofrnd]
	if !ok {
		return nil
	}

	return &proofInfo
}

func (s *Service) startStateProofFetcher(ctx context.Context) {
	s.stateProofWaitEnable()
	s.workers.Add(1)
	go s.stateProofFetcher(ctx)
}

// stateProofFetcher repeatedly tries to fetch the next verifiable state proof,
// until cancelled or no more state proofs can be fetched.
//
// The caller must s.workers.Add(1) and s.stateProofWaitEnable() before spawning
// stateProofFetcher.
func (s *Service) stateProofFetcher(ctx context.Context) {
	defer s.workers.Done()
	defer s.stateProofWaitDisable()

	latest := s.ledger.LastRound()
	s.cleanupStateProofs(latest)

	peerSelector := createPeerSelector(s.net, s.cfg, true)
	retry := 0

	for {
		vc := s.nextStateProofVerifier()
		if vc == nil {
			s.log.Debugf("catchup.stateProofFetcher: no verifier available")
			return
		}

		if retry >= catchupRetryLimit {
			s.log.Debugf("catchup.stateProofFetcher: cannot fetch %d, giving up", vc.LastRound)
			return
		}
		retry++

		select {
		case <-ctx.Done():
			s.log.Debugf("catchup.stateProofFetcher: aborted")
			return
		default:
		}

		psp, err := peerSelector.getNextPeer()
		if err != nil {
			s.log.Warnf("catchup.stateProofFetcher: unable to getNextPeer: %v", err)
			return
		}

		fetcher := makeUniversalBlockFetcher(s.log, s.net, s.cfg)
		proofs, _, err := fetcher.fetchStateProof(ctx, protocol.StateProofBasic, vc.LastRound, psp.Peer)
		if err != nil {
			s.log.Warnf("catchup.fetchStateProof(%d): attempt %d: %v", vc.LastRound, retry, err)
			peerSelector.rankPeer(psp, peerRankDownloadFailed)
			continue
		}

		if len(proofs.Proofs) == 0 {
			s.log.Warnf("catchup.fetchStateProof(%d): attempt %d: no proofs returned", vc.LastRound, retry)
			peerSelector.rankPeer(psp, peerRankDownloadFailed)
			continue
		}

		for idx, pf := range proofs.Proofs {
			if idx > 0 {
				// This is an extra state proof returned optimistically by the server.
				// We need to get the corresponding verification context.
				vc = s.nextStateProofVerifier()
				if vc == nil {
					break
				}
			}

			verifier := stateproof.MkVerifierWithLnProvenWeight(vc.VotersCommitment, vc.LnProvenWeight, config.Consensus[vc.Proto].StateProofStrengthTarget)
			err = verifier.Verify(uint64(vc.LastRound), pf.Message.Hash(), &pf.StateProof)
			if err != nil {
				s.log.Warnf("catchup.stateProofFetcher: cannot verify round %d: %v", vc.LastRound, err)
				peerSelector.rankPeer(psp, peerRankInvalidDownload)
				break
			}

			s.log.Debugf("catchup.stateProofFetcher: validated proof for %d", vc.LastRound)
			s.addStateProof(pf.Message, vc.Proto)
			retry = 0
		}
	}
}

func verifyBlockStateProof(r basics.Round, spmsg *stateproofmsg.Message, block *bookkeeping.Block, proofData []byte) error {
	l := block.ToLightBlockHeader()

	if !config.Consensus[block.CurrentProtocol].StateProofBlockHashInLightHeader {
		return fmt.Errorf("block %d protocol %s does not authenticate block in light block header", r, block.CurrentProtocol)
	}

	proof, err := merklearray.ProofDataToSingleLeafProof(crypto.Sha256.String(), proofData)
	if err != nil {
		return err
	}

	elems := make(map[uint64]crypto.Hashable)
	elems[uint64(r-spmsg.FirstAttestedRound)] = &l

	return merklearray.VerifyVectorCommitment(spmsg.BlockHeadersCommitment, elems, proof.ToProof())
}
