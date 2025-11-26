// Copyright (C) 2019-2025 Algorand, Inc.
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

// Package gossip adapts the interface of network.GossipNode to
// agreement.Network.
package gossip

import (
	"context"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/messagetracer"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

var messagesHandledTotal = metrics.MakeCounter(metrics.AgreementMessagesHandled)
var messagesHandledByType = metrics.NewTagCounter("algod_agreement_handled_{TAG}", "Number of agreement {TAG} messages handled",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)
var messagesDroppedTotal = metrics.MakeCounter(metrics.AgreementMessagesDropped)
var messagesDroppedByType = metrics.NewTagCounter("algod_agreement_dropped_{TAG}", "Number of agreement {TAG} messages dropped",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)

const (
	agreementVoteMessageType     = "vote"
	agreementProposalMessageType = "proposal"
	agreementBundleMessageType   = "bundle"
)

type messageMetadata struct {
	raw network.IncomingMessage
}

// networkImpl wraps network.GossipNode to provide a compatible interface with agreement.
type networkImpl struct {
	voteCh     chan agreement.Message
	proposalCh chan agreement.Message
	bundleCh   chan agreement.Message

	net network.GossipNode
	log logging.Logger

	trace messagetracer.MessageTracer
}

// WrapNetwork adapts a network.GossipNode into an agreement.Network.
func WrapNetwork(net network.GossipNode, log logging.Logger, cfg config.Local) agreement.Network {
	i := new(networkImpl)

	i.voteCh = make(chan agreement.Message, cfg.AgreementIncomingVotesQueueLength)
	i.proposalCh = make(chan agreement.Message, cfg.AgreementIncomingProposalsQueueLength)
	i.bundleCh = make(chan agreement.Message, cfg.AgreementIncomingBundlesQueueLength)

	i.net = net
	i.log = log

	return i
}

// SetTrace modifies the result of WrapNetwork to add network propagation tracing
func SetTrace(net agreement.Network, trace messagetracer.MessageTracer) {
	i := net.(*networkImpl)
	i.trace = trace
}

func (i *networkImpl) Start() {
	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.AgreementVoteTag, MessageHandler: network.HandlerFunc(i.processVoteMessage)},
		{Tag: protocol.ProposalPayloadTag, MessageHandler: network.HandlerFunc(i.processProposalMessage)},
		{Tag: protocol.VoteBundleTag, MessageHandler: network.HandlerFunc(i.processBundleMessage)},
	}
	i.net.RegisterHandlers(handlers)
}

func messageMetadataFromHandle(h agreement.MessageHandle) *messageMetadata {
	if msg, isMsg := h.(*messageMetadata); isMsg {
		return msg
	}
	return nil
}

func (i *networkImpl) processVoteMessage(raw network.IncomingMessage) network.OutgoingMessage {
	return i.processMessage(raw, i.voteCh, agreementVoteMessageType)
}

func (i *networkImpl) processProposalMessage(raw network.IncomingMessage) network.OutgoingMessage {
	if i.trace != nil {
		i.trace.HashTrace(messagetracer.Proposal, raw.Data)
	}
	return i.processMessage(raw, i.proposalCh, agreementProposalMessageType)
}

func (i *networkImpl) processBundleMessage(raw network.IncomingMessage) network.OutgoingMessage {
	return i.processMessage(raw, i.bundleCh, agreementBundleMessageType)
}

// i.e. process<Type>Message
func (i *networkImpl) processMessage(raw network.IncomingMessage, submit chan<- agreement.Message, msgType string) network.OutgoingMessage {
	metadata := &messageMetadata{raw: raw}

	select {
	case submit <- agreement.Message{MessageHandle: agreement.MessageHandle(metadata), Data: raw.Data}:
		// It would be slightly better to measure at de-queue
		// time, but that happens in many places in code and
		// this is much easier.
		messagesHandledTotal.Inc(nil)
		messagesHandledByType.Add(msgType, 1)
	default:
		messagesDroppedTotal.Inc(nil)
		messagesDroppedByType.Add(msgType, 1)
	}

	// Immediately ignore everything here, sometimes Relay/Broadcast/Disconnect later based on API handles saved from IncomingMessage
	return network.OutgoingMessage{Action: network.Ignore}
}

func (i *networkImpl) Messages(t protocol.Tag) <-chan agreement.Message {
	switch t {
	case protocol.AgreementVoteTag:
		return i.voteCh
	case protocol.ProposalPayloadTag:
		return i.proposalCh
	case protocol.VoteBundleTag:
		return i.bundleCh
	default:
		i.log.Panicf("bad tag! %v", t)
		return nil
	}
}

func (i *networkImpl) Broadcast(t protocol.Tag, data []byte) (err error) {
	err = i.net.Broadcast(context.Background(), t, data, false, nil)
	if err != nil {
		i.log.Infof("agreement: could not broadcast message with tag %v: %v", t, err)
	}
	return
}

func (i *networkImpl) Relay(h agreement.MessageHandle, t protocol.Tag, data []byte) (err error) {
	metadata := messageMetadataFromHandle(h)
	if metadata == nil { // synthentic loopback
		err = i.net.Broadcast(context.Background(), t, data, false, nil)
		if err != nil {
			i.log.Infof("agreement: could not (pseudo)relay message with tag %v: %v", t, err)
		}
	} else {
		err = i.net.Relay(context.Background(), t, data, false, metadata.raw.Sender)
		if err != nil {
			i.log.Infof("agreement: could not relay message from %v with tag %v: %v", metadata.raw.Sender, t, err)
		}
	}
	return
}

func (i *networkImpl) Disconnect(h agreement.MessageHandle) {
	metadata := messageMetadataFromHandle(h)

	if metadata == nil { // synthentic loopback
		// TODO warn
		return
	}

	i.net.Disconnect(metadata.raw.Sender)
}
