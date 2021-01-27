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

package fuzzer

import (
	"bytes"
	"encoding/json"
	"github.com/algorand/go-deadlock"

	//"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
)

type MessageDecoderStore struct {
	deadlock.Mutex
	votes     map[string]unauthenticatedVote
	proposals map[string]compoundMessage
	bundles   map[string]unauthenticatedBundle
}

type (
	// round denotes a single round of the agreement protocol
	round = basics.Round

	// step is a sequence number denoting distinct stages in Algorand
	step uint64

	// period is used to track progress with a given round in the protocol
	period uint64

	// roundPeriod represents a specific period in a specific Round of the protocol
	roundPeriod struct {
		basics.Round
		Period period
	}
	// rawVote is the inner struct which is authenticated with keys
	rawVote struct {
		_struct  struct{}       `codec:",omitempty,omitemptyarray"`
		Sender   basics.Address `codec:"snd"`
		Round    basics.Round   `codec:"rnd"`
		Period   period         `codec:"per"`
		Step     step           `codec:"step"`
		Proposal proposalValue  `codec:"prop"`
	}

	// unauthenticatedVote is a vote which has not been verified
	unauthenticatedVote struct {
		_struct struct{}                            `codec:",omitempty,omitemptyarray"`
		R       rawVote                             `codec:"r"`
		Cred    committee.UnauthenticatedCredential `codec:"cred"`
		Sig     crypto.OneTimeSignature             `codec:"sig,omitempty,omitemptycheckstruct"`
	}

	proposalValue struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		OriginalPeriod   period         `codec:"oper"`
		OriginalProposer basics.Address `codec:"oprop"`
		EntryDigest      crypto.Digest  `codec:"dig"`
		EncodingDigest   crypto.Digest  `coded:"encdig"`
	}
	// unauthenticatedBundle is a bundle which has not yet been verified.
	unauthenticatedBundle struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Round    basics.Round  `codec:"rnd"`
		Period   period        `codec:"per"`
		Step     step          `codec:"step"`
		Proposal proposalValue `codec:"prop"`

		Votes             []voteAuthenticator             `codec:"vote"`
		EquivocationVotes []equivocationVoteAuthenticator `codec:"eqv"`
	}

	// bundle is a set of votes, all from the same round, period, and step, and from distinct senders, that reaches quorum.
	//
	// It also include equivocation pairs -- pairs of votes where someone maliciously voted for two different values -- as these count as votes for *any* value.
	bundle struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		U unauthenticatedBundle `codec:"u"`

		//   Round    basics.Round `codec:"rnd"`
		//   Period   period       `codec:"per"`
		//   Step     step         `codec:"step"`
		//   Proposal proposal     `codec:"prop"`

		Votes             []vote             `codec:"vote"`
		EquivocationVotes []equivocationVote `codec:"eqv"`
	}

	// voteAuthenticators omit the Round, Period, Step, and Proposal for compression
	// and to simplify checking logic.
	voteAuthenticator struct {
		Sender basics.Address                      `codec:"snd"`
		Cred   committee.UnauthenticatedCredential `codec:"cred"`
		Sig    crypto.OneTimeSignature             `codec:"sig,omitempty,omitemptycheckstruct"`
	}

	equivocationVoteAuthenticator struct {
		Sender    basics.Address                      `codec:"snd"`
		Cred      committee.UnauthenticatedCredential `codec:"cred"`
		Sigs      [2]crypto.OneTimeSignature          `codec:"sig,omitempty,omitemptycheckstruct"`
		Proposals [2]proposalValue                    `codec:"props"`
	}

	// A vote is an endorsement of a particular proposal in Algorand
	vote struct {
		_struct struct{}                `codec:",omitempty,omitemptyarray"`
		R       rawVote                 `codec:"r"`
		Cred    committee.Credential    `codec:"cred"`
		Sig     crypto.OneTimeSignature `codec:"sig,omitempty,omitemptycheckstruct"`
	}

	// unauthenticatedEquivocationVote is a pair of votes which has not
	// been verified to be equivocating.
	unauthenticatedEquivocationVote struct {
		_struct   struct{}                            `codec:",omitempty,omitemptyarray"`
		Sender    basics.Address                      `codec:"snd"`
		Round     basics.Round                        `codec:"rnd"`
		Period    period                              `codec:"per"`
		Step      step                                `codec:"step"`
		Cred      committee.UnauthenticatedCredential `codec:"cred"`
		Proposals [2]proposalValue                    `codec:"props"`
		Sigs      [2]crypto.OneTimeSignature          `codec:"sigs"`
	}

	// An equivocationVote is a pair of votes from the same sender that
	// votes for two different hashes.
	//
	// These pairs are necessarily generated by a faulty node. However, if
	// we ever receive such a pair, we must count this as a single
	// "wildcard" vote to avoid violating vote propagation assumptions and
	// causing a fork.
	equivocationVote struct {
		_struct   struct{}                   `codec:",omitempty,omitemptyarray"`
		Sender    basics.Address             `codec:"snd"`
		Round     basics.Round               `codec:"rnd"`
		Period    period                     `codec:"per"`
		Step      step                       `codec:"step"`
		Cred      committee.Credential       `codec:"cred"`
		Proposals [2]proposalValue           `codec:"props"`
		Sigs      [2]crypto.OneTimeSignature `codec:"sigs"`
	}

	// An unauthenticatedProposal is an Entry which has not been validated yet.
	unauthenticatedProposal struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		bookkeeping.Block
		SeedProof crypto.VrfProof `codec:"sdpf"`
	}

	compoundMessage struct {
		Vote     unauthenticatedVote
		Proposal unauthenticatedProposal
	}

	// A transmittedPayload is the representation of a proposal payload on the wire.
	transmittedPayload struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		unauthenticatedProposal
		PriorVote unauthenticatedVote `codec:"pv"`
	}
)

// Algorand 2.0 steps
const (
	propose step = iota
	soft
	cert
	next
)

type MessageDecoderFilter struct {
	NetworkFilter

	upstream   UpstreamFilter
	downstream DownstreamFilter
	fuzzer     *Fuzzer

	NetworkFilterFactory
	msgStore *MessageDecoderStore
}

func (n *MessageDecoderFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	switch tag {
	case protocol.AgreementVoteTag:
		n.decodeVote(data)
	case protocol.ProposalPayloadTag:
		n.decodeProposal(data)
	case protocol.VoteBundleTag:
		n.decodeBundle(data)
	}
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *MessageDecoderFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *MessageDecoderFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *MessageDecoderFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *MessageDecoderFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *MessageDecoderFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	if n.msgStore == nil {
		n.msgStore = &MessageDecoderStore{
			votes:     make(map[string]unauthenticatedVote),
			proposals: make(map[string]compoundMessage),
			bundles:   make(map[string]unauthenticatedBundle),
		}
	}
	return &MessageDecoderFilter{
		fuzzer:   fuzzer,
		msgStore: n.msgStore,
	}
}

func (n *MessageDecoderFilter) Tick(newClockTime int) bool {
	return n.upstream.Tick(newClockTime)
}

func (n *MessageDecoderFilter) decodeVote(data []byte) {
	var uv unauthenticatedVote
	err := protocol.DecodeStream(bytes.NewBuffer(data), &uv)
	if err != nil {
		return
	}
	key := string(data)
	n.msgStore.Lock()
	defer n.msgStore.Unlock()
	n.msgStore.votes[key] = uv
}

func (n *MessageDecoderFilter) decodeProposal(data []byte) {
	var p transmittedPayload
	err := protocol.DecodeStream(bytes.NewBuffer(data), &p)
	if err != nil {
		return
	}

	c := compoundMessage{
		Vote:     p.PriorVote,
		Proposal: p.unauthenticatedProposal,
	}
	key := string(data)
	n.msgStore.Lock()
	defer n.msgStore.Unlock()
	n.msgStore.proposals[key] = c
}

func (n *MessageDecoderFilter) decodeBundle(data []byte) {
	var ub unauthenticatedBundle
	err := protocol.DecodeStream(bytes.NewBuffer(data), &ub)
	if err != nil {
		return
	}
	key := string(data)
	n.msgStore.Lock()
	defer n.msgStore.Unlock()
	n.msgStore.bundles[key] = ub
}

func (n *MessageDecoderFilter) getDecodedMessage(tag protocol.Tag, data []byte) (*unauthenticatedVote, *compoundMessage, *unauthenticatedBundle) {
	key := string(data)
	n.msgStore.Lock()
	defer n.msgStore.Unlock()
	switch tag {
	case protocol.AgreementVoteTag:
		if uv, has := n.msgStore.votes[key]; has {
			return &uv, nil, nil
		}
	case protocol.ProposalPayloadTag:
		if up, has := n.msgStore.proposals[key]; has {
			return nil, &up, nil
		}
	case protocol.VoteBundleTag:
		if ub, has := n.msgStore.bundles[key]; has {
			return nil, nil, &ub
		}
	}
	return nil, nil, nil
}

func (n *MessageDecoderFilter) getDecodedMessageCounts(tag protocol.Tag) int {
	n.msgStore.Lock()
	defer n.msgStore.Unlock()
	switch tag {
	case protocol.AgreementVoteTag:
		return len(n.msgStore.votes)
	case protocol.ProposalPayloadTag:
		return len(n.msgStore.proposals)
	case protocol.VoteBundleTag:
		return len(n.msgStore.bundles)
	}
	return -1
}

// Unmarshall MessageDecoderFilter
func (n *MessageDecoderFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type messageDecoderFilterJSON struct {
		Name string
	}

	var jsonConfig messageDecoderFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "MessageDecoderFilter" {
		return nil
	}
	return &MessageDecoderFilter{}
}

// register MessageDecoderFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &MessageDecoderFilter{})
}
