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

type CatchupFilterConfig struct {
	Nodes []int
	Count int
}

type CatchupFilter struct {
	NetworkFilter
	upstream     UpstreamFilter
	downstream   DownstreamFilter
	fuzzer       *Fuzzer
	nodeID       int
	count        int
	enabled      bool
	debugMessage bool

	NetworkFilterFactory
	config *CatchupFilterConfig
}

func (n *CatchupFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *CatchupFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *CatchupFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *CatchupFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *CatchupFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *CatchupFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	f := &CatchupFilter{
		nodeID:       nodeID,
		fuzzer:       fuzzer,
		config:       n.config,
		debugMessage: false,
	}
	for _, i := range n.config.Nodes {
		if i == nodeID {
			f.enabled = true
		}
	}
	return f
}

func (n *CatchupFilter) Tick(newClockTime int) bool {
	changed := n.upstream.Tick(newClockTime)
	if !n.enabled {
		return changed
	}
	currentLedgerRound := n.fuzzer.ledgers[n.nodeID].NextRound()
	if n.debugMessage {
		fmt.Printf("Node %d catching up on clock %d\n", n.nodeID, newClockTime)
	}
	n.fuzzer.StartCatchingUp(n.nodeID)
	caughtUpLedgerRound := n.fuzzer.ledgers[n.nodeID].NextRound()
	if n.debugMessage {
		fmt.Printf("Node %d caught up from round %d to round %d\n", n.nodeID, currentLedgerRound, caughtUpLedgerRound)
	}
	n.count++
	if n.count >= n.config.Count {
		n.enabled = false
	}
	return true
}

func MakeCatchupFilterFactory(config *CatchupFilterConfig) *CatchupFilter {
	return &CatchupFilter{
		config: config,
	}
}

// Unmarshall CatchupFilter
func (n *CatchupFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type catchupFilterJSON struct {
		Name string
		CatchupFilterConfig
	}

	var jsonConfig catchupFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "CatchupFilter" {
		return nil
	}
	return &CatchupFilter{
		config: &jsonConfig.CatchupFilterConfig,
	}
}

// register CatchupFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &CatchupFilter{})
}
