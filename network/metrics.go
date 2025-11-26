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

package network

import (
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	p2proto "github.com/libp2p/go-libp2p/core/protocol"

	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

func init() {
	// all tags are tracked by ws net
	tagStringList := make([]string, 0, len(protocol.TagList))
	for _, t := range protocol.TagList {
		tagStringList = append(tagStringList, string(t))
	}
	networkSentBytesByTag = metrics.NewTagCounterFiltered("algod_network_sent_bytes_{TAG}", "Number of bytes that were sent over the network for {TAG} messages", tagStringList, "UNK")
	networkReceivedBytesByTag = metrics.NewTagCounterFiltered("algod_network_received_bytes_{TAG}", "Number of bytes that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkReceivedUncompressedBytesByTag = metrics.NewTagCounterFiltered("algod_network_received_uncompressed_bytes_{TAG}", "Number of bytes after decompression that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkMessageReceivedByTag = metrics.NewTagCounterFiltered("algod_network_message_received_{TAG}", "Number of complete messages that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkMessageSentByTag = metrics.NewTagCounterFiltered("algod_network_message_sent_{TAG}", "Number of complete messages that were sent to the network for {TAG} messages", tagStringList, "UNK")
	networkHandleCountByTag = metrics.NewTagCounterFiltered("algod_network_rx_handle_countbytag_{TAG}", "count of handler calls in the receive thread for {TAG} messages", tagStringList, "UNK")
	networkHandleMicrosByTag = metrics.NewTagCounterFiltered("algod_network_rx_handle_microsbytag_{TAG}", "microseconds spent by protocol handlers in the receive thread for {TAG} messages", tagStringList, "UNK")

	networkP2PSentBytesByTag = metrics.NewTagCounterFiltered("algod_network_p2p_sent_bytes_{TAG}", "Number of bytes that were sent over the network for {TAG} messages", tagStringList, "UNK")
	networkP2PReceivedBytesByTag = metrics.NewTagCounterFiltered("algod_network_p2p_received_bytes_{TAG}", "Number of bytes that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkP2PReceivedUncompressedBytesByTag = metrics.NewTagCounterFiltered("algod_network_p2p_received_uncompressed_bytes_{TAG}", "Number of bytes after decompression that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkP2PMessageReceivedByTag = metrics.NewTagCounterFiltered("algod_network_p2p_message_received_{TAG}", "Number of complete messages that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkP2PMessageSentByTag = metrics.NewTagCounterFiltered("algod_network_p2p_message_sent_{TAG}", "Number of complete messages that were sent to the network for {TAG} messages", tagStringList, "UNK")
}

var networkSentBytesTotal = metrics.MakeCounter(metrics.NetworkSentBytesTotal)
var networkP2PSentBytesTotal = metrics.MakeCounter(metrics.NetworkP2PSentBytesTotal)
var networkSentBytesByTag *metrics.TagCounter
var networkP2PSentBytesByTag *metrics.TagCounter
var networkReceivedBytesTotal = metrics.MakeCounter(metrics.NetworkReceivedBytesTotal)
var networkP2PReceivedBytesTotal = metrics.MakeCounter(metrics.NetworkP2PReceivedBytesTotal)
var networkReceivedBytesByTag *metrics.TagCounter
var networkP2PReceivedBytesByTag *metrics.TagCounter
var networkReceivedUncompressedBytesByTag *metrics.TagCounter
var networkP2PReceivedUncompressedBytesByTag *metrics.TagCounter

var networkMessageReceivedTotal = metrics.MakeCounter(metrics.NetworkMessageReceivedTotal)
var networkP2PMessageReceivedTotal = metrics.MakeCounter(metrics.NetworkP2PMessageReceivedTotal)
var networkMessageReceivedByTag *metrics.TagCounter
var networkP2PMessageReceivedByTag *metrics.TagCounter
var networkMessageSentTotal = metrics.MakeCounter(metrics.NetworkMessageSentTotal)
var networkP2PMessageSentTotal = metrics.MakeCounter(metrics.NetworkP2PMessageSentTotal)
var networkMessageSentByTag *metrics.TagCounter
var networkP2PMessageSentByTag *metrics.TagCounter

var networkHandleMicrosByTag *metrics.TagCounter
var networkHandleCountByTag *metrics.TagCounter

var networkConnectionsDroppedTotal = metrics.MakeCounter(metrics.NetworkConnectionsDroppedTotal)
var networkMessageQueueMicrosTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_message_sent_queue_micros_total", Description: "Total microseconds message spent waiting in queue to be sent"})
var networkP2PMessageQueueMicrosTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_p2p_message_sent_queue_micros_total", Description: "Total microseconds p2p message spent waiting in queue to be sent"})

var duplicateNetworkMessageReceivedTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedTotal)
var duplicateNetworkMessageReceivedBytesTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedBytesTotal)
var duplicateNetworkFilterReceivedTotal = metrics.MakeCounter(metrics.DuplicateNetworkFilterReceivedTotal)
var outgoingNetworkMessageFilteredOutTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutTotal)
var outgoingNetworkMessageFilteredOutBytesTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutBytesTotal)
var unknownProtocolTagMessagesTotal = metrics.MakeCounter(metrics.UnknownProtocolTagMessagesTotal)

var networkIncomingConnections = metrics.MakeGauge(metrics.NetworkIncomingConnections)
var networkOutgoingConnections = metrics.MakeGauge(metrics.NetworkOutgoingConnections)

var networkIncomingBufferMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_rx_buffer_micros_total", Description: "microseconds spent by incoming messages on the receive buffer"})
var networkHandleMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_rx_handle_micros_total", Description: "microseconds spent by protocol handlers in the receive thread"})

var networkBroadcasts = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcasts_total", Description: "number of broadcast operations"})
var networkBroadcastQueueFull = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcast_queue_full_total", Description: "number of messages that were drops due to full broadcast queue"})
var networkBroadcastQueueMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcast_queue_micros_total", Description: "microseconds broadcast requests sit on queue"})
var networkBroadcastSendMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcast_send_micros_total", Description: "microseconds spent broadcasting"})
var networkBroadcastsDropped = metrics.MakeCounter(metrics.MetricName{Name: "algod_broadcasts_dropped_total", Description: "number of broadcast messages not sent to any peer"})
var networkPeerBroadcastDropped = metrics.MakeCounter(metrics.MetricName{Name: "algod_peer_broadcast_dropped_total", Description: "number of broadcast messages not sent to some peer"})

var networkP2PPeerBroadcastDropped = metrics.MakeCounter(metrics.MetricName{Name: "algod_peer_p2p_broadcast_dropped_total", Description: "number of broadcast messages not sent to some p2p peer"})

var networkPeerIdentityDisconnect = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_identity_duplicate", Description: "number of times identity challenge cause us to disconnect a peer"})
var networkPeerIdentityError = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_identity_error", Description: "number of times an error occurs (besides expected) when processing identity challenges"})
var networkPeerAlreadyClosed = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_peer_already_closed", Description: "number of times a peer would be added but the peer connection is already closed"})

var networkSlowPeerDrops = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_slow_drops_total", Description: "number of peers dropped for being slow to send to"})
var networkIdlePeerDrops = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_idle_drops_total", Description: "number of peers dropped due to idle connection"})

var peers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peers", Description: "Number of active peers."})
var incomingPeers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_incoming_peers", Description: "Number of active incoming peers."})
var outgoingPeers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_outgoing_peers", Description: "Number of active outgoing peers."})

var transactionMessagesP2PRejectMessage = metrics.NewTagCounter(metrics.TransactionMessagesP2PRejectMessage.Name, metrics.TransactionMessagesP2PRejectMessage.Description)
var transactionMessagesP2PDuplicateMessage = metrics.MakeCounter(metrics.TransactionMessagesP2PDuplicateMessage)
var transactionMessagesP2PDeliverMessage = metrics.MakeCounter(metrics.TransactionMessagesP2PDeliverMessage)
var transactionMessagesP2PUnderdeliverableMessage = metrics.MakeCounter(metrics.TransactionMessagesP2PUndeliverableMessage)

var networkP2PGossipSubSentBytesTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_p2p_gs_sent_bytes_total", Description: "Total number of bytes sent through gossipsub"})
var networkP2PGossipSubReceivedBytesTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_p2p_gs_received_bytes_total", Description: "Total number of bytes received through gossipsub"})

// var networkP2PGossipSubSentMsgs = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_p2p_gs_message_sent", Description: "Number of complete messages that were sent to the network through gossipsub"})

var networkVoteBroadcastCompressedBytes = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vote_compressed_bytes_broadcast_total", Description: "Total AV message bytes broadcast after applying stateless compression"})
var networkVoteBroadcastUncompressedBytes = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vote_uncompressed_bytes_broadcast_total", Description: "Total AV message bytes broadcast before applying stateless compression"})
var networkVPCompressionErrors = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vpack_compression_errors_total", Description: "Total number of stateful vote compression errors"})
var networkVPDecompressionErrors = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vpack_decompression_errors_total", Description: "Total number of stateful vote decompression errors"})
var networkVPAbortMessagesSent = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vpack_abort_messages_sent_total", Description: "Total number of vpack abort messages sent to peers"})
var networkVPAbortMessagesReceived = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vpack_abort_messages_received_total", Description: "Total number of vpack abort messages received from peers"})
var networkVPCompressedBytesSent = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vpack_compressed_bytes_sent_total", Description: "Total VP message bytes sent, after compressing AV to VP messages"})
var networkVPUncompressedBytesSent = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_vpack_uncompressed_bytes_sent_total", Description: "Total VP message bytes sent, before compressing AV to VP messages"})

var _ = pubsub.RawTracer(pubsubMetricsTracer{})

// pubsubMetricsTracer is a tracer for pubsub events used to track metrics.
type pubsubMetricsTracer struct{}

// AddPeer is invoked when a new peer is added.
func (t pubsubMetricsTracer) AddPeer(p peer.ID, proto p2proto.ID) {}

// RemovePeer is invoked when a peer is removed.
func (t pubsubMetricsTracer) RemovePeer(p peer.ID) {}

// Join is invoked when a new topic is joined
func (t pubsubMetricsTracer) Join(topic string) {}

// Leave is invoked when a topic is abandoned
func (t pubsubMetricsTracer) Leave(topic string) {}

// Graft is invoked when a new peer is grafted on the mesh (gossipsub)
func (t pubsubMetricsTracer) Graft(p peer.ID, topic string) {}

// Prune is invoked when a peer is pruned from the message (gossipsub)
func (t pubsubMetricsTracer) Prune(p peer.ID, topic string) {}

// ValidateMessage is invoked when a message first enters the validation pipeline.
func (t pubsubMetricsTracer) ValidateMessage(msg *pubsub.Message) {
}

// DeliverMessage is invoked when a message is delivered
func (t pubsubMetricsTracer) DeliverMessage(msg *pubsub.Message) {
	transactionMessagesP2PDeliverMessage.Inc(nil)
}

// RejectMessage is invoked when a message is Rejected or Ignored.
// The reason argument can be one of the named strings Reject*.
func (t pubsubMetricsTracer) RejectMessage(msg *pubsub.Message, reason string) {
	// TagCounter cannot handle tags with spaces so pubsub.Reject* cannot be used directly.
	// Since Go's strings are immutable, char replacement is a new allocation so that stick to string literals.
	switch reason {
	case pubsub.RejectValidationThrottled:
		transactionMessagesP2PRejectMessage.Add("throttled", 1)
	case pubsub.RejectValidationQueueFull:
		transactionMessagesP2PRejectMessage.Add("full", 1)
	case pubsub.RejectValidationFailed:
		transactionMessagesP2PRejectMessage.Add("failed", 1)
	case pubsub.RejectValidationIgnored:
		transactionMessagesP2PRejectMessage.Add("ignored", 1)
	default:
		transactionMessagesP2PRejectMessage.Add("other", 1)
	}
}

// DuplicateMessage is invoked when a duplicate message is dropped.
func (t pubsubMetricsTracer) DuplicateMessage(msg *pubsub.Message) {
	transactionMessagesP2PDuplicateMessage.Inc(nil)
}

// ThrottlePeer is invoked when a peer is throttled by the peer gater.
func (t pubsubMetricsTracer) ThrottlePeer(p peer.ID) {}

// RecvRPC is invoked when an incoming RPC is received.
func (t pubsubMetricsTracer) RecvRPC(rpc *pubsub.RPC) {
	for i := range rpc.GetPublish() {
		if rpc.Publish[i] != nil && rpc.Publish[i].Topic != nil {
			switch *rpc.Publish[i].Topic {
			case p2p.TXTopicName:
				networkP2PReceivedBytesTotal.AddUint64(uint64(len(rpc.Publish[i].Data)), nil)
				networkP2PReceivedBytesByTag.Add(string(protocol.TxnTag), uint64(len(rpc.Publish[i].Data)))
				networkP2PMessageReceivedByTag.Add(string(protocol.TxnTag), 1)
			}
		}
	}
	// service gossipsub traffic = networkP2PGossipSubReceivedBytesTotal - networkP2PReceivedBytesByTag_TX
	networkP2PGossipSubReceivedBytesTotal.AddUint64(uint64(rpc.Size()), nil)
}

// SendRPC is invoked when a RPC is sent.
func (t pubsubMetricsTracer) SendRPC(rpc *pubsub.RPC, p peer.ID) {
	networkP2PGossipSubSentBytesTotal.AddUint64(uint64(rpc.Size()), nil)
	for i := range rpc.GetPublish() {
		if rpc.Publish[i] != nil && rpc.Publish[i].Topic != nil {
			switch *rpc.Publish[i].Topic {
			case p2p.TXTopicName:
				networkP2PSentBytesByTag.Add(string(protocol.TxnTag), uint64(len(rpc.Publish[i].Data)))
				networkP2PSentBytesTotal.AddUint64(uint64(len(rpc.Publish[i].Data)), nil)
				networkP2PMessageSentByTag.Add(string(protocol.TxnTag), 1)
			}
		}
	}
}

// DropRPC is invoked when an outbound RPC is dropped, typically because of a queue full.
func (t pubsubMetricsTracer) DropRPC(rpc *pubsub.RPC, p peer.ID) {
	networkP2PPeerBroadcastDropped.Inc(nil)
}

// UndeliverableMessage is invoked when the consumer of Subscribe is not reading messages fast enough and
// the pressure release mechanism trigger, dropping messages.
func (t pubsubMetricsTracer) UndeliverableMessage(msg *pubsub.Message) {
	transactionMessagesP2PUnderdeliverableMessage.Inc(nil)
}
