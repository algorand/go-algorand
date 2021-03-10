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

package network

import (
	"bytes"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

func pingHandler(message IncomingMessage) OutgoingMessage {
	if len(message.Data) > 8 {
		return OutgoingMessage{}
	}
	message.Net.(*WebsocketNetwork).log.Debugf("ping from peer %#v", &(message.Sender.(*wsPeer).wsPeerCore))
	peer := message.Sender.(*wsPeer)
	tbytes := []byte(protocol.PingReplyTag)
	mbytes := make([]byte, len(tbytes)+len(message.Data))
	copy(mbytes, tbytes)
	copy(mbytes[len(tbytes):], message.Data)
	var digest crypto.Digest // leave blank, ping message too short
	peer.writeNonBlock(mbytes, false, digest, time.Now())
	return OutgoingMessage{}
}

func pingReplyHandler(message IncomingMessage) OutgoingMessage {
	log := message.Net.(*WebsocketNetwork).log
	now := time.Now()
	peer := message.Sender.(*wsPeer)
	peer.pingLock.Lock()
	defer peer.pingLock.Unlock()
	if !peer.pingInFlight {
		log.Infof("ping reply with non in flight from %s", peer.rootURL)
		return OutgoingMessage{}
	}
	if len(peer.pingData) != len(message.Data) {
		log.Infof("ping reply with wrong length want %d got %d, from %s", len(peer.pingData), len(message.Data), peer.rootURL)
		return OutgoingMessage{}
	}
	if 0 != bytes.Compare(peer.pingData, message.Data) {
		log.Infof("ping reply with wrong data from %s", peer.rootURL)
		return OutgoingMessage{}
	}
	peer.pingInFlight = false
	peer.lastPingRoundTripTime = now.Sub(peer.pingSent)
	log.Debugf("ping returned in %s from %s", peer.lastPingRoundTripTime, message.Sender.(*wsPeer).rootURL)
	return OutgoingMessage{}
}

var pingHandlers = []TaggedMessageHandler{
	{protocol.PingTag, HandlerFunc(pingHandler)},
	{protocol.PingReplyTag, HandlerFunc(pingReplyHandler)},
}
