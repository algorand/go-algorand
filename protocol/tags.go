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

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions"
)

// Tag represents a message type identifier.  Messages have a Tag field. Handlers can register to a given Tag.
// e.g., the agreement service can register to handle agreements with the Agreement tag.
//msgp:allocbound Tag 2
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

func (t Tag) MaxMessageSize() int {
	switch t {
	case AgreementVoteTag:
		return 1024
	case MsgOfInterestTag:
		return 1024
	case MsgDigestSkipTag:
		return 1024
	case NetPrioResponseTag:
		return 1024
	case NetIDVerificationTag:
		return 1024
	case PingTag:
		return 1024
	case PingReplyTag:
		return 1024
	case ProposalPayloadTag:
		return 1024
	case StateProofSigTag:
		return 1024
	case TopicMsgRespTag:
		return 1024
	case TxnTag:
		return config.MaxTxGroupSize * transactions.SignedTxnMaxSize()
	case UniEnsBlockReqTag:
		return 1024
	case VoteBundleTag:
		return 1024
	default:
	}
	return 1024
}

// func (tag Tag) MaxMessageSizes() {
// 	wn.maxMessageSizes = make(map[protocol.Tag]int, len(protocol.TagList))
// 	for _, tag := range protocol.TagList {
// 		switch tag {
// 		case protocol.AgreementVoteTag:
// 			wn.maxMessageSizes[tag] = 1024
// 		case protocol.MsgOfInterestTag:
// 			return 1024
// 		case protocol.MsgDigestSkipTag:
// 			wn.maxMessageSizes[tag] = crypto.DigestSize
// 		case protocol.NetPrioResponseTag:
// 			wn.maxMessageSizes[tag] = node.NetPrioMaxSize()
// 		case protocol.NetIDVerificationTag:
// 			wn.maxMessageSizes[tag] = (&identityChallengeSigned{}).MaxSize()
// 		case protocol.PingTag:
// 			wn.maxMessageSizes[tag] = pingMessageSize
// 		case protocol.PingReplyTag:
// 			wn.maxMessageSizes[tag] = 1024
// 		case protocol.ProposalPayloadTag:
// 			wn.maxMessageSizes[tag] = 1024
// 		case protocol.StateProofSigTag:
// 			wn.maxMessageSizes[tag] = 1024
// 		case protocol.TopicMsgRespTag:
// 			wn.maxMessageSizes[tag] = 1024
// 		case protocol.TxnTag:
// 			wn.maxMessageSizes[tag] = config.MaxTxGroupSize * (&transactions.SignedTxn{}).MaxSize()
// 		case protocol.UniEnsBlockReqTag:
// 			wn.maxMessageSizes[tag] = 1024
// 		case protocol.VoteBundleTag:
// 			wn.maxMessageSizes[tag] = 1024
// 		default:
// 			wn.maxMessageSizes[tag] = 0
// 		}
// 		switch tag {

// 		}
// 	}
// }

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
