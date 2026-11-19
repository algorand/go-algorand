// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// A message represents an internal message which is passed between components
// of the agreement service.
type message struct {
	_struct struct{} `codec:","`

	// explicitly unexport this field since we can't define serializers for interface{} type
	// the only implementation of this is gossip.messageMetadata which doesn't have exported fields to serialize.
	messageHandle MessageHandle

	Tag protocol.Tag

	// note: if Vote, Proposal, or Bundle is set, some logic requires unauthenticated
	// equivalents to be set
	Vote     vote
	Proposal proposal
	Bundle   bundle

	UnauthenticatedVote     unauthenticatedVote
	UnauthenticatedProposal unauthenticatedProposal
	UnauthenticatedBundle   unauthenticatedBundle

	CompoundMessage compoundMessage
}

// A compoundMessage represents the concatenation of a proposal-vote and a
// proposal payload.
//
// These messages are concatenated as an optimization which prevents proposals
// from being dropped.
type compoundMessage struct {
	_struct struct{} `codec:","`

	Vote     unauthenticatedVote
	Proposal unauthenticatedProposal
}

// streamTokenizer is a function that returns an object of some type after
// deserializing from some stream.
type streamTokenizer func([]byte) (any, error)

// clearPKSigOld zeroes the PKSigOld field of a signature received over gossip.
// No verifier reads that field, and the vote stays valid without it.
// Certificate verification does not call this, so certificates fetched during
// catchup are checked as they were encoded.
func clearPKSigOld(sig *crypto.OneTimeSignature) {
	clear(sig.PKSigOld[:])
}

// decodeVote reads a vote from the given stream.
//
// It returns an error on failure.
func decodeVote(data []byte) (any, error) {
	var uv unauthenticatedVote
	err := protocol.Decode(data, &uv)
	if err != nil {
		return nil, err
	}
	if err := uv.wellFormed(); err != nil {
		return nil, err
	}
	clearPKSigOld(&uv.Sig)
	return uv, nil
}

// decodeBundle reads a bundle from the given stream.
//
// It returns an error on failure.
func decodeBundle(data []byte) (any, error) {
	var b unauthenticatedBundle
	err := protocol.Decode(data, &b)
	if err != nil {
		return nil, err
	}
	if err := b.wellFormed(); err != nil {
		return nil, err
	}
	for i := range b.Votes {
		clearPKSigOld(&b.Votes[i].Sig)
	}
	for i := range b.EquivocationVotes {
		for j := range b.EquivocationVotes[i].Sigs {
			clearPKSigOld(&b.EquivocationVotes[i].Sigs[j])
		}
	}
	return b, nil
}

// decodeProposal reads a proposal from the given stream.
//
// It returns an error on failure.
//
// It reads only the fields before the payset, and keeps data in the proposal
// for player.decodePayloadIfWanted to decode if agreement wants the payload.
func decodeProposal(data []byte) (any, error) {
	pp, err := parsePayloadPrefix(data)
	if err != nil {
		return nil, err
	}
	if err := pp.priorVote.wellFormed(); err != nil {
		return nil, err
	}
	clearPKSigOld(&pp.priorVote.Sig)

	return compoundMessage{
		Vote: pp.priorVote,
		Proposal: unauthenticatedProposal{
			BlockHeader:      bookkeeping.BlockHeader{Round: pp.round},
			OriginalPeriod:   pp.originalPeriod,
			OriginalProposer: pp.originalProposer,
			deferredPayload:  data,
		},
	}, nil
}

func proposalCarriesInvalidTxn(up unauthenticatedProposal) bool {
	// if CurrentProtocol is wrong, it will be rejected in eval.StartEvaluator by BlockHeader.PreCheck
	allowGroupedHeartbeats := config.Consensus[up.Block.CurrentProtocol].AllowGroupedHeartbeats
	for group, err := range up.Block.PaysetGroups() {
		if err != nil || transactions.CheckPaysetGroup(group, allowGroupedHeartbeats) != nil {
			return true
		}
	}
	return false
}
