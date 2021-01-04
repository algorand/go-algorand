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
	"crypto/sha256"
	"encoding/json"

	"github.com/algorand/go-algorand/protocol"
)

type MessageRegossipFilter struct {
	NetworkFilter
	NetworkFilterFactory

	upstream             UpstreamFilter
	downstream           DownstreamFilter
	seenIncomingMessages map[[sha256.Size]byte]bool
}

func (n *MessageRegossipFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	digest := sha256.Sum256(append([]byte(tag), data...))
	if n.seenIncomingMessages[digest] {
		return
	}
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *MessageRegossipFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *MessageRegossipFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	digest := sha256.Sum256(append([]byte(tag), data...))
	n.seenIncomingMessages[digest] = true
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *MessageRegossipFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *MessageRegossipFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *MessageRegossipFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	return &MessageRegossipFilter{
		seenIncomingMessages: make(map[[sha256.Size]byte]bool),
	}
}

func (n *MessageRegossipFilter) Tick(newClockTime int) bool {
	return n.upstream.Tick(newClockTime)
}

func (n *MessageRegossipFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type nullFilterJSON struct {
		Name string
	}
	var jsonConfig nullFilterJSON
	if json.Unmarshal(b, &jsonConfig) != nil {
		return nil
	}
	if jsonConfig.Name != "MessageRegossipFilter" {
		return nil
	}
	return &MessageRegossipFilter{}
}

func init() {
	registeredFilterFactories = append(registeredFilterFactories, &MessageRegossipFilter{})
}
