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

package agreement

import (
	"context"
	"fmt"
	"github.com/algorand/go-algorand/logging"

	"github.com/algorand/go-algorand/logging/logspec"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
)

//go:generate stringer -type=actionType
//msgp:ignore actionType
type actionType int

const (
	noop actionType = iota

	// network
	ignore
	broadcast
	relay
	disconnect
	broadcastVotes

	// crypto
	verifyVote
	verifyPayload
	verifyBundle

	// ledger
	ensure
	stageDigest

	// time
	rezero

	// logical
	attest
	assemble
	repropose

	// disk
	checkpoint
)

type action interface {
	t() actionType
	persistent() bool
	do(context.Context, *Service)

	String() string
}

type nonpersistent struct{}

func (nonpersistent) persistent() bool {
	return false
}

type noopAction struct {
	nonpersistent
}

func (a noopAction) t() actionType {
	return noop
}

func (a noopAction) do(context.Context, *Service) {}

func (a noopAction) String() string {
	return a.t().String()
}

type networkAction struct {
	nonpersistent

	// ignore, broadcast, broadcastVotes, relay, disconnect
	T actionType

	Tag protocol.Tag
	h   MessageHandle // this is cleared to correctly handle ephemeral network state on recovery

	UnauthenticatedVote   unauthenticatedVote
	UnauthenticatedBundle unauthenticatedBundle
	CompoundMessage       compoundMessage

	UnauthenticatedVotes []unauthenticatedVote

	Err serializableError
}

func (a networkAction) t() actionType {
	return a.T
}

func (a networkAction) String() string {
	if a.t() == ignore || a.t() == disconnect {
		return fmt.Sprintf("%s: %5v", a.t().String(), a.Err)
	}
	if a.Tag == protocol.ProposalPayloadTag {
		return fmt.Sprintf("%s: %2v: %5v", a.t().String(), a.Tag, a.CompoundMessage.Proposal.value())
	}
	return fmt.Sprintf("%s: %2v", a.t().String(), a.Tag)
}

func (a networkAction) do(ctx context.Context, s *Service) {
	if a.T == broadcastVotes {
		tag := protocol.AgreementVoteTag
		for i, uv := range a.UnauthenticatedVotes {
			data := protocol.Encode(&uv)
			sendErr := s.Network.Broadcast(tag, data)
			if sendErr != nil {
				s.log.Warnf("Network was unable to queue votes for broadcast(%v). %d / %d votes for round %d period %d step %d were dropped.",
					sendErr,
					len(a.UnauthenticatedVotes)-i, len(a.UnauthenticatedVotes),
					uv.R.Round,
					uv.R.Period,
					uv.R.Step)
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
		return
	}

	var data []byte
	var txnData [][]byte
	var tags []protocol.Tag
	switch a.Tag {
	case protocol.AgreementVoteTag:
		data = protocol.Encode(&a.UnauthenticatedVote)
	case protocol.VoteBundleTag:
		data = protocol.Encode(&a.UnauthenticatedBundle)
	case protocol.ProposalPayloadTag:
		msg := a.CompoundMessage

		numtxns := len(msg.Proposal.Payset)
		txnData = make([][]byte, numtxns+1, numtxns+1)
		tags = make([]protocol.Tag, numtxns+1)
		for i, txib := range msg.Proposal.Payset {
			stxn := txib.SignedTxn
			txnData[i] = protocol.Encode(&stxn)
			tags[i] = protocol.TxnTag
		}
		payload := transmittedPayload{
			unauthenticatedProposal: msg.Proposal.StripSignedTxnWithAD(),
			PriorVote:               msg.Vote,
		}
		txnData[len(txnData)-1] = protocol.Encode(&payload)
		tags[len(txnData)-1] = protocol.ProposalPayloadTag
	}

	switch a.T {
	case broadcast:
		if txnData != nil {
			//protocol.TxnTag
			if a.CompoundMessage.Proposal.ctx == nil || *a.CompoundMessage.Proposal.ctx == nil { //TODO(yg) this check may be redundant
				logging.Base().Warnf("broadcast: context is nil")
				backgroundctx := context.Background()
				a.CompoundMessage.Proposal.ctx = &backgroundctx
			}

			logging.Base().Infof("broadcast: txncount %v", len(txnData))
			s.Network.BroadcastArray(*a.CompoundMessage.Proposal.ctx, tags, txnData)
		} else if data != nil {
			s.Network.Broadcast(a.Tag, data)
		}
	case relay:
		if txnData != nil {
			if a.CompoundMessage.Proposal.ctx == nil || *a.CompoundMessage.Proposal.ctx == nil { //TODO(yg) this check may be redundant
				logging.Base().Warnf("relay: context is nil")
				backgroundctx := context.Background()
				a.CompoundMessage.Proposal.ctx = &backgroundctx
			} else if a.h == nil {
				logging.Base().Infof("was proposer")
			}

			logging.Base().Infof("relay: txncount %v", len(txnData))
			s.Network.RelayArray(*a.CompoundMessage.Proposal.ctx, a.h, tags, txnData)
		} else if data != nil {
			s.Network.Relay(a.h, a.Tag, data)
		}
	case disconnect:
		s.Network.Disconnect(a.h)
	case ignore:
		// pass
	}
}

type cryptoAction struct {
	nonpersistent

	// verify{Vote,Payload,Bundle}
	T actionType

	M         message
	Proposal  proposalValue // TODO deprecate
	Round     round
	Period    period
	Step      step
	Pinned    bool
	TaskIndex int
}

func (a cryptoAction) t() actionType {
	return a.T
}

func (a cryptoAction) String() string {
	return a.t().String()
}

func (a cryptoAction) do(ctx context.Context, s *Service) {
	switch a.T {
	case verifyVote:
		s.demux.verifyVote(ctx, a.M, a.TaskIndex, a.Round, a.Period)
	case verifyPayload:
		s.demux.verifyPayload(ctx, a.M, a.Round, a.Period, a.Pinned)
	case verifyBundle:
		s.demux.verifyBundle(ctx, a.M, a.Round, a.Period, a.Step)
	}
}

type ensureAction struct {
	nonpersistent

	// the payload that we will give to the ledger
	Payload proposal
	// the certificate proving commitment
	Certificate Certificate
}

func (a ensureAction) t() actionType {
	return ensure
}

func (a ensureAction) String() string {
	return fmt.Sprintf("%s: %.5s: %v, %v, %.5s", a.t().String(), a.Payload.Digest().String(), a.Certificate.Round, a.Certificate.Period, a.Certificate.Proposal.BlockDigest.String())
}

func (a ensureAction) do(ctx context.Context, s *Service) {
	logEvent := logspec.AgreementEvent{
		Hash:   a.Certificate.Proposal.BlockDigest.String(),
		Round:  uint64(a.Certificate.Round),
		Period: uint64(a.Certificate.Period),
		Sender: a.Certificate.Proposal.OriginalProposer.String(),
	}

	if a.Payload.ve != nil {
		logEvent.Type = logspec.RoundConcluded
		s.log.with(logEvent).Infof("committed round %d with pre-validated block %v", a.Certificate.Round, a.Certificate.Proposal)
		s.log.EventWithDetails(telemetryspec.Agreement, telemetryspec.BlockAcceptedEvent, telemetryspec.BlockAcceptedEventDetails{
			Address: a.Certificate.Proposal.OriginalProposer.String(),
			Hash:    a.Certificate.Proposal.BlockDigest.String(),
			Round:   uint64(a.Certificate.Round),
		})
		s.Ledger.EnsureValidatedBlock(a.Payload.ve, a.Certificate)
	} else {
		block := a.Payload.Block
		logEvent.Type = logspec.RoundConcluded
		s.log.with(logEvent).Infof("committed round %d with block %v", a.Certificate.Round, a.Certificate.Proposal)
		s.log.EventWithDetails(telemetryspec.Agreement, telemetryspec.BlockAcceptedEvent, telemetryspec.BlockAcceptedEventDetails{
			Address: a.Certificate.Proposal.OriginalProposer.String(),
			Hash:    a.Certificate.Proposal.BlockDigest.String(),
			Round:   uint64(a.Certificate.Round),
		})
		s.Ledger.EnsureBlock(block, a.Certificate)
	}
	logEventStart := logEvent
	logEventStart.Type = logspec.RoundStart
	s.log.with(logEventStart).Infof("finished round %d", a.Certificate.Round)
	s.tracer.timeR().StartRound(a.Certificate.Round + 1)
	s.tracer.timeR().RecStep(0, propose, bottom)
}

type stageDigestAction struct {
	nonpersistent
	// Certificate identifies a block and is a proof commitment
	Certificate Certificate // a block digest is probably sufficient; keep certificate for now to match ledger interface
}

func (a stageDigestAction) t() actionType {
	return stageDigest
}

func (a stageDigestAction) String() string {
	return fmt.Sprintf("%s: %.5s. %v. %v", a.t().String(), a.Certificate.Proposal.BlockDigest.String(), a.Certificate.Round, a.Certificate.Period)
}

func (a stageDigestAction) do(ctx context.Context, service *Service) {
	logEvent := logspec.AgreementEvent{
		Hash:   a.Certificate.Proposal.BlockDigest.String(),
		Round:  uint64(a.Certificate.Round),
		Period: uint64(a.Certificate.Period),
		Sender: a.Certificate.Proposal.OriginalProposer.String(),
		Type:   logspec.RoundWaiting,
	}
	service.log.with(logEvent).Infof("round %v concluded without block for %v; (async) waiting on ledger", a.Certificate.Round, a.Certificate.Proposal)
	service.Ledger.EnsureDigest(a.Certificate, service.voteVerifier)
}

type rezeroAction struct {
	nonpersistent

	Round round
}

func (a rezeroAction) t() actionType {
	return rezero
}

func (a rezeroAction) String() string {
	return a.t().String()
}

func (a rezeroAction) do(ctx context.Context, s *Service) {
	s.Clock = s.Clock.Zero()
}

type pseudonodeAction struct {
	// assemble, repropose, attest
	T actionType

	Round    round
	Period   period
	Step     step
	Proposal proposalValue
}

func (a pseudonodeAction) t() actionType {
	return a.T
}

func (a pseudonodeAction) String() string {
	return fmt.Sprintf("%v %3v-%2v-%2v: %.5v", a.t().String(), a.Round, a.Period, a.Step, a.Proposal.BlockDigest.String())
}

func (a pseudonodeAction) persistent() bool {
	return a.T == attest
}

func (a pseudonodeAction) do(ctx context.Context, s *Service) {
	// making proposals and/or voting are opportunistic actions. If we're unable to generate the proposals/votes
	// due some internal reason, we should just drop that; the protocol would recover by using other proposers and/or
	// will go to the next period.
	switch a.T {
	// loopback
	case assemble:
		events, err := s.loopback.MakeProposals(ctx, a.Round, a.Period)
		switch err {
		case nil:
			s.demux.prioritize(events)
		case errPseudonodeNoProposals:
			// no participation keys, do nothing.
		default:
			s.log.Errorf("pseudonode.MakeProposals call failed %v", err)
		}
	case repropose:
		logEvent := logspec.AgreementEvent{
			Type:   logspec.VoteAttest,
			Round:  uint64(a.Round),
			Period: uint64(a.Period),
			Step:   uint64(propose),
			Hash:   a.Proposal.BlockDigest.String(),
		}
		s.log.with(logEvent).Infof("repropose to %v at (%v, %v, %v)", a.Proposal, a.Round, a.Period, propose)
		// create a channel that would get closed when we're done storing the persistence information to disk.
		// ( or will let us know if we failed ! )
		persistStateDone := make(chan error)
		close(persistStateDone)
		events, err := s.loopback.MakeVotes(ctx, a.Round, a.Period, propose, a.Proposal, persistStateDone)
		switch err {
		case nil:
			// no error.
			s.demux.prioritize(events)
		case errPseudonodeNoVotes:
			// do nothing
		default:
			// otherwise,
			s.log.Errorf("pseudonode.MakeVotes call failed for reproposal(%v) %v", a.T, err)
		}
	case attest:
		logEvent := logspec.AgreementEvent{
			Type:   logspec.VoteAttest,
			Round:  uint64(a.Round),
			Period: uint64(a.Period),
			Step:   uint64(a.Step),
			Hash:   a.Proposal.BlockDigest.String(),
		}
		s.log.with(logEvent).Infof("attested to %v at (%v, %v, %v)", a.Proposal, a.Round, a.Period, a.Step)
		// create a channel that would get closed when we're done storing the persistence information to disk.
		// ( or will let us know if we failed ! )
		persistStateDone := make(chan error)
		voteEvents, err := s.loopback.MakeVotes(ctx, a.Round, a.Period, a.Step, a.Proposal, persistStateDone)
		switch err {
		case nil:
			// no error.
			persistCompleteEvents := s.persistState(persistStateDone)
			// we want to place there two one after the other. That way, the second would not get executed up until the first one is complete.
			s.demux.prioritize(persistCompleteEvents)
			s.demux.prioritize(voteEvents)
		default:
			// otherwise,
			s.log.Errorf("pseudonode.MakeVotes call failed(%v) %v", a.T, err)
			fallthrough // just so that we would close the channel.
		case errPseudonodeNoVotes:
			// do nothing; we're closing the channel just to avoid leaving open channels, but it's not
			// really do anything at this point.
			close(persistStateDone)
		}
	}
}

func ignoreAction(e messageEvent, err serializableError) action {
	return networkAction{T: ignore, Err: err, h: e.Input.MessageHandle}
}

func disconnectAction(e messageEvent, err serializableError) action {
	return networkAction{T: disconnect, Err: err, h: e.Input.MessageHandle}
}

func broadcastAction(tag protocol.Tag, o interface{}) action {
	a := networkAction{T: broadcast, Tag: tag}
	// TODO would be good to have compiler check this (and related) type switch
	// by specializing one method per type
	switch tag {
	case protocol.AgreementVoteTag:
		a.UnauthenticatedVote = o.(unauthenticatedVote)
	case protocol.VoteBundleTag:
		a.UnauthenticatedBundle = o.(unauthenticatedBundle)
	case protocol.ProposalPayloadTag:
		a.CompoundMessage = o.(compoundMessage)
	}
	return a
}

func relayAction(e messageEvent, tag protocol.Tag, o interface{}) action {
	a := networkAction{T: relay, h: e.Input.MessageHandle, Tag: tag}
	// TODO would be good to have compiler check this (and related) type switch
	// by specializing one method per type
	switch tag {
	case protocol.AgreementVoteTag:
		a.UnauthenticatedVote = o.(unauthenticatedVote)
	case protocol.VoteBundleTag:
		a.UnauthenticatedBundle = o.(unauthenticatedBundle)
	case protocol.ProposalPayloadTag:
		a.CompoundMessage = o.(compoundMessage)
	}
	return a
}

func verifyVoteAction(e messageEvent, r round, p period, taskIndex int) action {
	return cryptoAction{T: verifyVote, M: e.Input, Round: r, Period: p, TaskIndex: taskIndex}
}

func verifyPayloadAction(e messageEvent, r round, p period, pinned bool) action {
	return cryptoAction{T: verifyPayload, M: e.Input, Round: r, Period: p, Pinned: pinned}
}

func verifyBundleAction(e messageEvent, r round, p period, s step) action {
	return cryptoAction{T: verifyBundle, M: e.Input, Round: r, Period: p, Step: s}
}

func zeroAction(t actionType) action {
	switch t {
	case noop:
		return noopAction{}
	case ignore, broadcast, relay, disconnect, broadcastVotes:
		return networkAction{}
	case verifyVote, verifyPayload, verifyBundle:
		return cryptoAction{}
	case ensure:
		return ensureAction{}
	case rezero:
		return rezeroAction{}
	case attest, assemble, repropose:
		return pseudonodeAction{}
	case checkpoint:
		return checkpointAction{}
	default:
		err := fmt.Errorf("bad action type: %v", t)
		panic(err)
	}
}

type checkpointAction struct {
	Round  round
	Period period
	Step   step
	Err    serializableError
	done   chan error // an output channel to let the pseudonode that we're done processing. We don't want to serialize that, since it's not needed in recovery/autopsy
}

func (c checkpointAction) t() actionType {
	return checkpoint
}

func (c checkpointAction) persistent() bool {
	return false
}

func (c checkpointAction) do(ctx context.Context, s *Service) {
	logEvent := logspec.AgreementEvent{
		Type:   logspec.Persisted,
		Round:  uint64(c.Round),
		Period: uint64(c.Period),
		Step:   uint64(c.Step),
	}
	if c.Err == nil {
		s.log.with(logEvent).Infof("checkpoint at (%v, %v, %v)", c.Round, c.Period, c.Step)
	} else {
		s.log.with(logEvent).Errorf("checkpoint at (%v, %v, %v) failed : %v", c.Round, c.Period, c.Step, c.Err)
		if c.done != nil {
			c.done <- c.Err
		}
	}
	if c.done != nil {
		close(c.done)
	} else {
		// c.done == nil
		// we don't expect this to happen in recovery
		s.log.with(logEvent).Errorf("checkpoint action for (%v, %v, %v) reached with nil completion channel", c.Round, c.Period, c.Step)
	}
	return
}

func (c checkpointAction) String() string {
	return c.t().String()
}
