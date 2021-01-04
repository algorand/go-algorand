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

	"github.com/algorand/go-algorand/protocol"
)

type TopologyFilterConfig struct {
	NodesConnection map[int][]int // map each node to a list of other nodes to which it's connected.
}

type TopologyFilter struct {
	NetworkFilter
	NetworkFilterFactory

	upstream        UpstreamFilter
	downstream      DownstreamFilter
	config          *TopologyFilterConfig
	nodeConnections map[int]bool
	fuzzer          *Fuzzer
	nodeID          int
}

func (n *TopologyFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	if targetNode < 0 {
		if len(n.nodeConnections) == n.fuzzer.nodesCount {
			n.downstream.SendMessage(sourceNode, targetNode, tag, data)
			return
		}
		for target := range n.nodeConnections {
			if target != n.nodeID {
				n.downstream.SendMessage(sourceNode, target, tag, data)
			}
		}
		return
	}
	if n.nodeConnections[targetNode] {
		n.downstream.SendMessage(sourceNode, targetNode, tag, data)
	}
}

func (n *TopologyFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *TopologyFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *TopologyFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *TopologyFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *TopologyFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	filter := &TopologyFilter{
		config:          n.config,
		nodeConnections: make(map[int]bool),
		fuzzer:          fuzzer,
		nodeID:          nodeID,
	}

	// initialize the nodeConnections map.
	if conns, has := n.config.NodesConnection[nodeID]; has {
		for _, conn := range conns {
			filter.nodeConnections[conn] = true
		}
	}
	return filter
}

func (n *TopologyFilter) Tick(newClockTime int) bool {
	return n.upstream.Tick(newClockTime)
}

func MakeTopologyFilter(config TopologyFilterConfig) *TopologyFilter {
	return &TopologyFilter{
		config: &config,
	}
}

func (n *TopologyFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type topologyFilterJSON struct {
		TopologyFilterConfig
		Name string
	}
	var jsonConfig topologyFilterJSON
	if json.Unmarshal(b, &jsonConfig) != nil {
		return nil
	}
	if jsonConfig.Name != "TopologyFilter" {
		return nil
	}
	return MakeTopologyFilter(jsonConfig.TopologyFilterConfig)
}

func init() {
	registeredFilterFactories = append(registeredFilterFactories, &TopologyFilter{})
}
