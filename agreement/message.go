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
	"github.com/algorand/go-algorand/protocol"
)

// A message represents an internal message which is passed between components
// of the agreement service.
type message struct {
	MessageHandle

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
	Vote     unauthenticatedVote
	Proposal unauthenticatedProposal
}

// streamTokenizer is a function that returns an object of some type after
// deserializing from some stream.
type streamTokenizer func([]byte) (interface{}, error)

// decodeVote reads a vote from the given stream.
//
// It returns an error on failure.
func decodeVote(data []byte) (interface{}, error) {
	var uv unauthenticatedVote
	err := protocol.Decode(data, &uv)
	if err != nil {
		return nil, err
	}
	return uv, nil
}

// decodeBundle reads a bundle from the given stream.
//
// It returns an error on failure.
func decodeBundle(data []byte) (interface{}, error) {
	var b unauthenticatedBundle
	err := protocol.Decode(data, &b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// decodeProposal reads a proposal from the given stream.
//
// It returns an error on failure.
func decodeProposal(data []byte) (interface{}, error) {
	var p transmittedPayload
	err := protocol.Decode(data, &p)
	if err != nil {
		return nil, err
	}

	return compoundMessage{
		Vote:     p.PriorVote,
		Proposal: p.unauthenticatedProposal,
	}, nil
}
