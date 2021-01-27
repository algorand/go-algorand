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
	"encoding/json"
	"fmt"

	"github.com/algorand/go-algorand/protocol"
)

type NodeCrashFilterConfig struct {
	Nodes []int
	Count int
}

type NodeCrashFilter struct {
	NetworkFilter
	upstream      UpstreamFilter
	downstream    DownstreamFilter
	fuzzer        *Fuzzer
	nodeID        int
	count         int
	enabled       bool
	debugMessages bool

	NetworkFilterFactory
	config *NodeCrashFilterConfig
}

func (n *NodeCrashFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *NodeCrashFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *NodeCrashFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *NodeCrashFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *NodeCrashFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *NodeCrashFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	f := &NodeCrashFilter{
		nodeID:        nodeID,
		fuzzer:        fuzzer,
		config:        n.config,
		debugMessages: false,
	}
	for _, i := range n.config.Nodes {
		if i == nodeID {
			f.enabled = true
		}
	}
	return f
}

func (n *NodeCrashFilter) Tick(newClockTime int) bool {
	changed := n.upstream.Tick(newClockTime)
	if !n.enabled {
		return changed
	}
	if n.debugMessages {
		fmt.Printf("Node %d Tick %d crashing node\n", n.nodeID, newClockTime)
	}
	n.fuzzer.CrashNode(n.nodeID)
	n.fuzzer.facades[n.nodeID].Tick(newClockTime)
	n.count++
	if n.count >= n.config.Count {
		n.enabled = false
	}
	return true
}

func MakeNodeCrashFilterFactory(config *NodeCrashFilterConfig) *NodeCrashFilter {
	return &NodeCrashFilter{
		config: config,
	}
}

// Unmarshall NodeCrashFilter
func (n *NodeCrashFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type catchupFilterJSON struct {
		Name string
		NodeCrashFilterConfig
	}

	var jsonConfig catchupFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "NodeCrashFilter" {
		return nil
	}
	return MakeNodeCrashFilterFactory(&jsonConfig.NodeCrashFilterConfig)
}

// register NodeCrashFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &NodeCrashFilter{})
}
