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

package network

import (
	"context"
	"net"
	"net/http"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

// Peer opaque interface for referring to a neighbor in the network
type Peer interface{}

// PeerOption allows users to specify a subset of peers to query
//
//msgp:ignore PeerOption
type PeerOption int

const (
	// PeersConnectedOut specifies all peers with outgoing connections
	PeersConnectedOut PeerOption = iota
	// PeersConnectedIn specifies all peers with inbound connections
	PeersConnectedIn PeerOption = iota
	// PeersPhonebookRelays specifies all relays in the phonebook
	PeersPhonebookRelays PeerOption = iota
	// PeersPhonebookArchivalNodes specifies all archival nodes (relay or p2p)
	PeersPhonebookArchivalNodes PeerOption = iota
	// PeersPhonebookArchivers specifies all archivers in the phonebook
	PeersPhonebookArchivers PeerOption = iota
)

// GossipNode represents a node in the gossip network
type GossipNode interface {
	Address() (string, bool)
	Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	Disconnect(badnode Peer)
	DisconnectPeers() // only used by testing

	// RegisterHTTPHandler path accepts gorilla/mux path annotations
	RegisterHTTPHandler(path string, handler http.Handler)

	// RequestConnectOutgoing asks the system to actually connect to peers.
	// `replace` optionally drops existing connections before making new ones.
	// `quit` chan allows cancellation. TODO: use `context`
	RequestConnectOutgoing(replace bool, quit <-chan struct{})

	// Get a list of Peers we could potentially send a direct message to.
	GetPeers(options ...PeerOption) []Peer

	// Start threads, listen on sockets.
	Start()

	// Close sockets. Stop threads.
	Stop()

	// RegisterHandlers adds to the set of given message handlers.
	RegisterHandlers(dispatch []TaggedMessageHandler)

	// ClearHandlers deregisters all the existing message handlers.
	ClearHandlers()

	// GetRoundTripper returns a Transport that would limit the number of outgoing connections.
	GetRoundTripper() http.RoundTripper

	// OnNetworkAdvance notifies the network library that the agreement protocol was able to make a notable progress.
	// this is the only indication that we have that we haven't formed a clique, where all incoming messages
	// arrive very quickly, but might be missing some votes. The usage of this call is expected to have similar
	// characteristics as with a watchdog timer.
	OnNetworkAdvance()

	// GetHTTPRequestConnection returns the underlying connection for the given request. Note that the request must be the same
	// request that was provided to the http handler ( or provide a fallback Context() to that )
	GetHTTPRequestConnection(request *http.Request) (conn net.Conn)

	// SubstituteGenesisID substitutes the "{genesisID}" with their network-specific genesisID.
	SubstituteGenesisID(rawURL string) string

	// called from wsPeer to report that it has closed
	peerRemoteClose(peer *wsPeer, reason disconnectReason)
}

var outgoingMessagesBufferSize = int(
	max(config.Consensus[protocol.ConsensusCurrentVersion].NumProposers,
		config.Consensus[protocol.ConsensusCurrentVersion].SoftCommitteeSize,
		config.Consensus[protocol.ConsensusCurrentVersion].CertCommitteeSize,
		config.Consensus[protocol.ConsensusCurrentVersion].NextCommitteeSize) +
		max(config.Consensus[protocol.ConsensusCurrentVersion].LateCommitteeSize,
			config.Consensus[protocol.ConsensusCurrentVersion].RedoCommitteeSize,
			config.Consensus[protocol.ConsensusCurrentVersion].DownCommitteeSize),
)

// IncomingMessage represents a message arriving from some peer in our p2p network
type IncomingMessage struct {
	Sender Peer
	Tag    Tag
	Data   []byte
	Err    error
	Net    GossipNode

	// Received is time.Time.UnixNano()
	Received int64

	// processing is a channel that is used by messageHandlerThread
	// to indicate that it has started processing this message.  It
	// is used to ensure fairness across peers in terms of processing
	// messages.
	processing chan struct{}
}

// Tag is a short string (2 bytes) marking a type of message
type Tag = protocol.Tag

func highPriorityTag(tags []protocol.Tag) bool {
	for _, tag := range tags {
		if tag == protocol.AgreementVoteTag || tag == protocol.ProposalPayloadTag {
			return true
		}
	}
	return false
}

// OutgoingMessage represents a message we want to send.
type OutgoingMessage struct {
	Action  ForwardingPolicy
	Tag     Tag
	Payload []byte
	Topics  Topics
	reason  disconnectReason // used when Action == Disconnect

	// OnRelease is a function called when outgoing message, resulting from this incoming message, is released
	// either by being sent or discarded.
	OnRelease func()
}

// ForwardingPolicy is an enum indicating to whom we should send a message
//
//msgp:ignore ForwardingPolicy
type ForwardingPolicy int

const (
	// Ignore - discard (don't forward)
	Ignore ForwardingPolicy = iota

	// Disconnect - disconnect from the peer that sent this message
	Disconnect

	// Broadcast - forward to everyone (except the sender)
	Broadcast

	// Respond - reply to the sender
	Respond
)

// MessageHandler takes a IncomingMessage (e.g., vote, transaction), processes it, and returns what (if anything)
// to send to the network in response.
// The ForwardingPolicy field of the returned OutgoingMessage indicates whether to reply directly to the sender
// (unicast), propagate to everyone except the sender (broadcast), or do nothing (ignore).
type MessageHandler interface {
	Handle(message IncomingMessage) OutgoingMessage
}

// HandlerFunc represents an implemenation of the MessageHandler interface
type HandlerFunc func(message IncomingMessage) OutgoingMessage

// Handle implements MessageHandler.Handle, calling the handler with the IncomingKessage and returning the OutgoingMessage
func (f HandlerFunc) Handle(message IncomingMessage) OutgoingMessage {
	return f(message)
}

// TaggedMessageHandler receives one type of broadcast messages
type TaggedMessageHandler struct {
	Tag
	MessageHandler
}

// Propagate is a convenience function to save typing in the common case of a message handler telling us to propagate an incoming message
// "return network.Propagate(msg)" instead of "return network.OutgoingMsg{network.Broadcast, msg.Tag, msg.Data}"
func Propagate(msg IncomingMessage) OutgoingMessage {
	return OutgoingMessage{Action: Broadcast, Tag: msg.Tag, Payload: msg.Data, Topics: nil}
}

// find the max value across the given uint64 numbers.
func max(numbers ...uint64) (maxNum uint64) {
	maxNum = 0 // this is the lowest uint64 value.
	for _, num := range numbers {
		if num > maxNum {
			maxNum = num
		}
	}
	return
}
