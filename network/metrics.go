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

package network

import (
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

func init() {
	// all tags are tracked by ws net
	tagStringListWs := make([]string, len(protocol.TagList))
	for i, t := range protocol.TagList {
		tagStringListWs[i] = string(t)
	}
	networkSentBytesByTag = metrics.NewTagCounterFiltered("algod_network_sent_bytes_{TAG}", "Number of bytes that were sent over the network for {TAG} messages", tagStringListWs, "UNK")
	networkReceivedBytesByTag = metrics.NewTagCounterFiltered("algod_network_received_bytes_{TAG}", "Number of bytes that were received from the network for {TAG} messages", tagStringListWs, "UNK")
	networkMessageReceivedByTag = metrics.NewTagCounterFiltered("algod_network_message_received_{TAG}", "Number of complete messages that were received from the network for {TAG} messages", tagStringListWs, "UNK")
	networkMessageSentByTag = metrics.NewTagCounterFiltered("algod_network_message_sent_{TAG}", "Number of complete messages that were sent to the network for {TAG} messages", tagStringListWs, "UNK")
	networkHandleCountByTag = metrics.NewTagCounterFiltered("algod_network_rx_handle_countbytag_{TAG}", "count of handler calls in the receive thread for {TAG} messages", tagStringListWs, "UNK")
	networkHandleMicrosByTag = metrics.NewTagCounterFiltered("algod_network_rx_handle_microsbytag_{TAG}", "microseconds spent by protocol handlers in the receive thread for {TAG} messages", tagStringListWs, "UNK")

	// all but gossipSub tags are tracked by p2p net
	// the remaining tags are tracked by gossipSub tracer p2p sub-package
	tagStringListP2P := make([]string, len(protocol.TagList))
	for i, t := range protocol.TagList {
		if _, ok := gossipSubTags[t]; !ok {
			tagStringListWs[i] = string(t)
		}
	}
	networkP2PSentBytesByTag = metrics.NewTagCounterFiltered("algod_network_p2p_sent_bytes_{TAG}", "Number of bytes that were sent over the network for {TAG} messages", tagStringListP2P, "UNK")
	networkP2PReceivedBytesByTag = metrics.NewTagCounterFiltered("algod_network_p2p_received_bytes_{TAG}", "Number of bytes that were received from the network for {TAG} messages", tagStringListP2P, "UNK")
	networkP2PMessageReceivedByTag = metrics.NewTagCounterFiltered("algod_network_p2p_message_received_{TAG}", "Number of complete messages that were received from the network for {TAG} messages", tagStringListP2P, "UNK")
	networkP2PMessageSentByTag = metrics.NewTagCounterFiltered("algod_network_p2p_message_sent_{TAG}", "Number of complete messages that were sent to the network for {TAG} messages", tagStringListP2P, "UNK")
}

var networkSentBytesTotal = metrics.MakeCounter(metrics.NetworkSentBytesTotal)
var networkP2PSentBytesTotal = metrics.MakeCounter(metrics.NetworkP2PSentBytesTotal)
var networkSentBytesByTag *metrics.TagCounter
var networkP2PSentBytesByTag *metrics.TagCounter
var networkReceivedBytesTotal = metrics.MakeCounter(metrics.NetworkReceivedBytesTotal)
var networkP2PReceivedBytesTotal = metrics.MakeCounter(metrics.NetworkP2PReceivedBytesTotal)
var networkReceivedBytesByTag *metrics.TagCounter
var networkP2PReceivedBytesByTag *metrics.TagCounter

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

var networkPeerIdentityDisconnect = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_identity_duplicate", Description: "number of times identity challenge cause us to disconnect a peer"})
var networkPeerIdentityError = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_identity_error", Description: "number of times an error occurs (besides expected) when processing identity challenges"})
var networkPeerAlreadyClosed = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_peer_already_closed", Description: "number of times a peer would be added but the peer connection is already closed"})

var networkSlowPeerDrops = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_slow_drops_total", Description: "number of peers dropped for being slow to send to"})
var networkIdlePeerDrops = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_idle_drops_total", Description: "number of peers dropped due to idle connection"})

var minPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_min_ping_seconds", Description: "Network round trip time to fastest peer in seconds."})
var meanPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_mean_ping_seconds", Description: "Network round trip time to average peer in seconds."})
var medianPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_median_ping_seconds", Description: "Network round trip time to median peer in seconds."})
var maxPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_max_ping_seconds", Description: "Network round trip time to slowest peer in seconds."})

var peers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peers", Description: "Number of active peers."})
var incomingPeers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_incoming_peers", Description: "Number of active incoming peers."})
var outgoingPeers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_outgoing_peers", Description: "Number of active outgoing peers."})
