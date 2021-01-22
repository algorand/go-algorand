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

type ClockedFilter struct {
	NetworkFilter

	upstream   UpstreamFilter
	downstream DownstreamFilter

	nodeID            int
	prevExternalClock int
	localClock        float32
	ratio             float32

	NetworkFilterFactory
	clockAspectRatio map[int]float32
}

func MakeClockedFilter(ratio map[int]float32) *ClockedFilter {
	return &ClockedFilter{
		clockAspectRatio: ratio,
	}
}

func (n *ClockedFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *ClockedFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *ClockedFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *ClockedFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *ClockedFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *ClockedFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	f := &ClockedFilter{
		nodeID: nodeID,
	}
	if ratio, has := n.clockAspectRatio[n.nodeID]; has {
		f.ratio = ratio
		if ratio <= 0.0 {
			panic(fmt.Errorf("Invalid ratio specified (%v)", ratio))
		}
	} else {
		f.ratio = 1.0
	}
	return f
}

func (n *ClockedFilter) Tick(newClockTime int) bool {
	delta := newClockTime - n.prevExternalClock
	n.localClock += float32(delta) * n.ratio
	n.prevExternalClock = newClockTime
	return n.upstream.Tick(int(n.localClock))
}

// Unmarshall ClockedFilter
func (n *ClockedFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type clockedFilterJSON struct {
		Name             string
		ClockAspectRatio map[int]float32
	}

	var jsonConfig clockedFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "ClockedFilter" {
		return nil
	}
	return &ClockedFilter{
		clockAspectRatio: jsonConfig.ClockAspectRatio,
	}
}

// register ClockedFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &ClockedFilter{})
}
