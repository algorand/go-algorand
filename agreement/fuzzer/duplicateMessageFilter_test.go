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

type DuplicateMessageFilter struct {
	NetworkFilter
	NetworkFilterFactory

	upstream             UpstreamFilter
	downstream           DownstreamFilter
	seenIncomingMessages map[[sha256.Size]byte]bool
}

func (n *DuplicateMessageFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *DuplicateMessageFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *DuplicateMessageFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	digest := sha256.Sum256(append([]byte(tag), data...))
	if n.seenIncomingMessages[digest] {
		return
	}
	n.seenIncomingMessages[digest] = true
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *DuplicateMessageFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *DuplicateMessageFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *DuplicateMessageFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	return &DuplicateMessageFilter{
		seenIncomingMessages: make(map[[sha256.Size]byte]bool),
	}
}

func (n *DuplicateMessageFilter) Tick(newClockTime int) bool {
	return n.upstream.Tick(newClockTime)
}

func (n *DuplicateMessageFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type duplicateMsgFilterJSON struct {
		Name string
	}
	var jsonConfig duplicateMsgFilterJSON
	if json.Unmarshal(b, &jsonConfig) != nil {
		return nil
	}
	if jsonConfig.Name != "DuplicateMessageFilter" {
		return nil
	}
	return &DuplicateMessageFilter{}
}

func init() {
	registeredFilterFactories = append(registeredFilterFactories, &DuplicateMessageFilter{})
}
