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

package protocol

// Tag represents a message type identifier.  Messages have a Tag field. Handlers can register to a given Tag.
// e.g., the agreement service can register to handle agreements with the Agreement tag.
type Tag string

// Tags, in lexicographic sort order of tag values to avoid duplicates.
// These tags must not contain a comma character because lists of tags
// are encoded using a comma separator (see network/msgOfInterest.go).
// The tags must be 2 bytes long.
const (
	AgreementVoteTag     Tag = "AV"
	MsgOfInterestTag     Tag = "MI"
	MsgDigestSkipTag     Tag = "MS"
	NetPrioResponseTag   Tag = "NP"
	NetIDVerificationTag Tag = "NI"
	PingTag              Tag = "pi"
	PingReplyTag         Tag = "pj"
	ProposalPayloadTag   Tag = "PP"
	StateProofSigTag     Tag = "SP"
	TopicMsgRespTag      Tag = "TS"
	TxnTag               Tag = "TX"
	//UniCatchupReqTag   Tag = "UC" was replaced by UniEnsBlockReqTag
	UniEnsBlockReqTag Tag = "UE"
	//UniEnsBlockResTag  Tag = "US" was used for wsfetcherservice
	//UniCatchupResTag   Tag = "UT" was used for wsfetcherservice
	VoteBundleTag Tag = "VB"
)

//AgreementVoteTagMaxSize is the maximum size of an AgreementVoteTag message
const AgreementVoteTagMaxSize = 1228

// MsgOfInterestTagMaxSize is the maximum size of a MsgOfInterestTag message
const MsgOfInterestTagMaxSize = 45

// MsgDigestSkipTagMaxSize is the maximum size of a MsgDigestSkipTag message
const MsgDigestSkipTagMaxSize = 69

// NetPrioResponseTagMaxSize is the maximum size of a NetPrioResponseTag message
const NetPrioResponseTagMaxSize = 838

// NetIDVerificationTagMaxSize is the maximum size of a NetIDVerificationTag message
const NetIDVerificationTagMaxSize = 215

// PingTagMaxSize is the maximum size of a PingTag message
const PingTagMaxSize = 8

//PingReplyTagMaxSize is the maximum size of a PingReplyTag message
const PingReplyTagMaxSize = 8

// ProposalPayloadTagMaxSize is the maximum size of a ProposalPayloadTag message
const ProposalPayloadTagMaxSize = 24964890771504913 // Wrong because of oversized stateproof

// StateProofSigTagMaxSize is the maximum size of a StateProofSigTag message
const StateProofSigTagMaxSize = 2266266 // Wrong because of oversized stateproof

// TopicMsgRespTagMaxSize is the maximum size of a TopicMsgRespTag message	:w
const TopicMsgRespTagMaxSize = 1024

// TxnTagMaxSize is the maximum size of a TxnTag message
const TxnTagMaxSize = 23286391600 // Wrong because of oversized stateproof

// UniEnsBlockReqTagMaxSize is the maximum size of a UniEnsBlockReqTag message
const UniEnsBlockReqTagMaxSize = 67

// VoteBundleTagMaxSize is the maximum size of a VoteBundleTag message:w
const VoteBundleTagMaxSize = 23754054

// MaxMessageSize returns the maximum size of a message for a given tag
func (tag Tag) MaxMessageSize() int {
	switch tag {
	case AgreementVoteTag:
		return AgreementVoteTagMaxSize
	case MsgOfInterestTag:
		return MsgOfInterestTagMaxSize
	case MsgDigestSkipTag:
		return MsgDigestSkipTagMaxSize
	case NetPrioResponseTag:
		return NetPrioResponseTagMaxSize
	case NetIDVerificationTag:
		return NetIDVerificationTagMaxSize
	case PingTag:
		return PingTagMaxSize
	case PingReplyTag:
		return PingReplyTagMaxSize
	case ProposalPayloadTag:
		return ProposalPayloadTagMaxSize
	case StateProofSigTag:
		return StateProofSigTagMaxSize
	case TopicMsgRespTag:
		return TopicMsgRespTagMaxSize
	case TxnTag:
		return TxnTagMaxSize
	case UniEnsBlockReqTag:
		return UniEnsBlockReqTagMaxSize
	case VoteBundleTag:
		return VoteBundleTagMaxSize
	default:
		return -1
	}
}

// TagList is a list of all currently used protocol tags.
var TagList = []Tag{
	AgreementVoteTag,
	MsgOfInterestTag,
	MsgDigestSkipTag,
	NetIDVerificationTag,
	NetPrioResponseTag,
	PingTag,
	PingReplyTag,
	ProposalPayloadTag,
	StateProofSigTag,
	TopicMsgRespTag,
	TxnTag,
	UniEnsBlockReqTag,
	VoteBundleTag,
}
