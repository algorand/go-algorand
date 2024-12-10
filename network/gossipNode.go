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
	"context"
	"net/http"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

// Peer opaque interface for referring to a neighbor in the network
type Peer interface{}

// DisconnectablePeer is a Peer with a long-living connection to a network that can be disconnected
type DisconnectablePeer interface {
	GetNetwork() GossipNode
}

// DisconnectableAddressablePeer is a Peer with a long-living connection to a network that can be disconnected and has an IP address
type DisconnectableAddressablePeer interface {
	DisconnectablePeer
	IPAddressable
}

// IPAddressable is addressable with either IPv4 or IPv6 address
type IPAddressable interface {
	RoutingAddr() []byte
}

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
)

// GossipNode represents a node in the gossip network
type GossipNode interface {
	Address() (string, bool)
	Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	Disconnect(badnode DisconnectablePeer)
	DisconnectPeers() // only used by testing

	// RegisterHTTPHandler and RegisterHTTPHandlerFunc: path accepts gorilla/mux path annotations
	RegisterHTTPHandler(path string, handler http.Handler)
	RegisterHTTPHandlerFunc(path string, handler func(http.ResponseWriter, *http.Request))

	// RequestConnectOutgoing asks the system to actually connect to peers.
	// `replace` optionally drops existing connections before making new ones.
	// `quit` chan allows cancellation. TODO: use `context`
	RequestConnectOutgoing(replace bool, quit <-chan struct{})

	// Get a list of Peers we could potentially send a direct message to.
	GetPeers(options ...PeerOption) []Peer

	// Start threads, listen on sockets.
	Start() error

	// Close sockets. Stop threads.
	Stop()

	// RegisterHandlers adds to the set of given message handlers.
	RegisterHandlers(dispatch []TaggedMessageHandler)

	// ClearHandlers deregisters all the existing message handlers.
	ClearHandlers()

	// RegisterValidatorHandlers adds to the set of given message validation handlers.
	// A difference with regular handlers is validation ones perform synchronous validation.
	// Currently used as p2p pubsub topic validators.
	RegisterValidatorHandlers(dispatch []TaggedMessageValidatorHandler)

	// ClearValidatorHandlers deregisters all the existing message processors.
	ClearValidatorHandlers()

	// GetHTTPClient returns a http.Client with a suitable for the network Transport
	// that would also limit the number of outgoing connections.
	GetHTTPClient(address string) (*http.Client, error)

	// OnNetworkAdvance notifies the network library that the agreement protocol was able to make a notable progress.
	// this is the only indication that we have that we haven't formed a clique, where all incoming messages
	// arrive very quickly, but might be missing some votes. The usage of this call is expected to have similar
	// characteristics as with a watchdog timer.
	OnNetworkAdvance()

	// GetGenesisID returns the network-specific genesisID.
	GetGenesisID() string

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
	Sender DisconnectableAddressablePeer
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

	// Accept - accept for further processing after successful validation
	Accept
)

// MessageHandler takes a IncomingMessage (e.g., vote, transaction), processes it, and returns what (if anything)
// to send to the network in response.
// The ForwardingPolicy field of the returned OutgoingMessage indicates whether to reply directly to the sender
// (unicast), propagate to everyone except the sender (broadcast), or do nothing (ignore).
type MessageHandler interface {
	Handle(message IncomingMessage) OutgoingMessage
}

// HandlerFunc represents an implementation of the MessageHandler interface
type HandlerFunc func(message IncomingMessage) OutgoingMessage

// Handle implements MessageHandler.Handle, calling the handler with the IncomingMessage and returning the OutgoingMessage
func (f HandlerFunc) Handle(message IncomingMessage) OutgoingMessage {
	return f(message)
}

// MessageValidatorHandler takes a IncomingMessage (e.g., vote, transaction), processes it, and returns what (if anything)
// to send to the network in response.
// it supposed to perform synchronous validation and return the result of the validation
// so that network knows immediately if the message should be be broadcasted or not.
type MessageValidatorHandler interface {
	ValidateHandle(message IncomingMessage) OutgoingMessage
}

// ValidateHandleFunc represents an implementation of the MessageProcessor interface
type ValidateHandleFunc func(message IncomingMessage) OutgoingMessage

// ValidateHandle implements MessageValidatorHandler.ValidateHandle, calling the validator with the IncomingMessage and returning the action.
func (f ValidateHandleFunc) ValidateHandle(message IncomingMessage) OutgoingMessage {
	return f(message)
}

type taggedMessageDispatcher[T any] struct {
	Tag
	MessageHandler T
}

// TaggedMessageHandler receives one type of broadcast messages
type TaggedMessageHandler = taggedMessageDispatcher[MessageHandler]

// TaggedMessageValidatorHandler receives one type of broadcast messages
// and performs two stage processing: validating and handling
type TaggedMessageValidatorHandler = taggedMessageDispatcher[MessageValidatorHandler]

// Propagate is a convenience function to save typing in the common case of a message handler telling us to propagate an incoming message
// "return network.Propagate(msg)" instead of "return network.OutgoingMsg{network.Broadcast, msg.Tag, msg.Data}"
func Propagate(msg IncomingMessage) OutgoingMessage {
	return OutgoingMessage{Action: Broadcast, Tag: msg.Tag, Payload: msg.Data, Topics: nil}
}

// SubstituteGenesisID substitutes the "{genesisID}" with their network-specific genesisID.
func SubstituteGenesisID(net GossipNode, rawURL string) string {
	return strings.Replace(rawURL, "{genesisID}", net.GetGenesisID(), -1)
}
