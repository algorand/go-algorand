// Copyright (C) 2019-2024 Algorand, Inc.
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

package p2p

import (
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/algorand/go-algorand/util/metrics"
)

var _ = pubsub.RawTracer(pubsubTracer{})

var transactionMessagesP2PRejectMessage = metrics.NewTagCounter(metrics.TransactionMessagesP2PRejectMessage.Name, metrics.TransactionMessagesP2PRejectMessage.Description)
var transactionMessagesP2PDuplicateMessage = metrics.MakeCounter(metrics.TransactionMessagesP2PDuplicateMessage)
var transactionMessagesP2PDeliverMessage = metrics.MakeCounter(metrics.TransactionMessagesP2PDeliverMessage)
var transactionMessagesP2PUnderdeliverableMessage = metrics.MakeCounter(metrics.TransactionMessagesP2PUndeliverableMessage)
var transactionMessagesP2PValidateMessage = metrics.MakeCounter(metrics.TransactionMessagesP2PValidateMessage)

// pubsubTracer is a tracer for pubsub events used to track metrics.
type pubsubTracer struct{}

// AddPeer is invoked when a new peer is added.
func (t pubsubTracer) AddPeer(p peer.ID, proto protocol.ID) {}

// RemovePeer is invoked when a peer is removed.
func (t pubsubTracer) RemovePeer(p peer.ID) {}

// Join is invoked when a new topic is joined
func (t pubsubTracer) Join(topic string) {}

// Leave is invoked when a topic is abandoned
func (t pubsubTracer) Leave(topic string) {}

// Graft is invoked when a new peer is grafted on the mesh (gossipsub)
func (t pubsubTracer) Graft(p peer.ID, topic string) {}

// Prune is invoked when a peer is pruned from the message (gossipsub)
func (t pubsubTracer) Prune(p peer.ID, topic string) {}

// ValidateMessage is invoked when a message first enters the validation pipeline.
func (t pubsubTracer) ValidateMessage(msg *pubsub.Message) {
	transactionMessagesP2PValidateMessage.Inc(nil)
}

// DeliverMessage is invoked when a message is delivered
func (t pubsubTracer) DeliverMessage(msg *pubsub.Message) {
	transactionMessagesP2PDeliverMessage.Inc(nil)
}

// RejectMessage is invoked when a message is Rejected or Ignored.
// The reason argument can be one of the named strings Reject*.
func (t pubsubTracer) RejectMessage(msg *pubsub.Message, reason string) {
	switch reason {
	case pubsub.RejectValidationThrottled, pubsub.RejectValidationQueueFull, pubsub.RejectValidationFailed, pubsub.RejectValidationIgnored:
		transactionMessagesP2PRejectMessage.Add(reason, 1)
	default:
		transactionMessagesP2PRejectMessage.Add("other", 1)
	}
}

// DuplicateMessage is invoked when a duplicate message is dropped.
func (t pubsubTracer) DuplicateMessage(msg *pubsub.Message) {
	transactionMessagesP2PDuplicateMessage.Inc(nil)
}

// ThrottlePeer is invoked when a peer is throttled by the peer gater.
func (t pubsubTracer) ThrottlePeer(p peer.ID) {}

// RecvRPC is invoked when an incoming RPC is received.
func (t pubsubTracer) RecvRPC(rpc *pubsub.RPC) {}

// SendRPC is invoked when a RPC is sent.
func (t pubsubTracer) SendRPC(rpc *pubsub.RPC, p peer.ID) {}

// DropRPC is invoked when an outbound RPC is dropped, typically because of a queue full.
func (t pubsubTracer) DropRPC(rpc *pubsub.RPC, p peer.ID) {}

// UndeliverableMessage is invoked when the consumer of Subscribe is not reading messages fast enough and
// the pressure release mechanism trigger, dropping messages.
func (t pubsubTracer) UndeliverableMessage(msg *pubsub.Message) {
	transactionMessagesP2PUnderdeliverableMessage.Inc(nil)
}
