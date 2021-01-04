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

// Drop message filter will drop 1 out of X messages where X is the drop rate for the node.
type DropMessageFilter struct {
	NetworkFilter
	NetworkFilterFactory

	upstream   UpstreamFilter
	downstream DownstreamFilter

	nodeID              int
	upStreamDropRate    map[int]uint64
	downStreamDropRate  map[int]uint64
	receiveMessageCount uint64
	sendMessageCount    uint64
}

func MakeDropMessageFilter(upStreamDropRate map[int]uint64, downStreamDropRate map[int]uint64) *DropMessageFilter {
	return &DropMessageFilter{
		upStreamDropRate:   upStreamDropRate,
		downStreamDropRate: downStreamDropRate,
	}
}

func (n *DropMessageFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	n.sendMessageCount++
	if rate, has := n.downStreamDropRate[n.nodeID]; has {
		if rate == 0 || n.sendMessageCount%rate != 0 {
			n.downstream.SendMessage(sourceNode, targetNode, tag, data)
		}
		return
	}
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *DropMessageFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *DropMessageFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.receiveMessageCount++
	if rate, has := n.upStreamDropRate[n.nodeID]; has {
		if rate == 0 || n.receiveMessageCount%rate != 0 {
			n.upstream.ReceiveMessage(sourceNode, tag, data)
		}
		return
	}
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *DropMessageFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *DropMessageFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *DropMessageFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	return &DropMessageFilter{
		nodeID:             nodeID,
		upStreamDropRate:   n.upStreamDropRate,
		downStreamDropRate: n.downStreamDropRate,
	}
}

func (n *DropMessageFilter) Tick(newClockTime int) bool {
	return n.upstream.Tick(newClockTime)
}

func (n *DropMessageFilter) Marshal() (bytes []byte, err error) {

	bytes, err = json.Marshal(n)
	return

}

// Unmarshall DropMessageFilter
func (n *DropMessageFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type dropMessageFilterJSON struct {
		Name               string
		UpStreamDropRate   map[int]uint64
		DownStreamDropRate map[int]uint64
	}

	var jsonConfig dropMessageFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "DropMessageFilter" {
		return nil
	}
	return &DropMessageFilter{
		upStreamDropRate:   jsonConfig.UpStreamDropRate,
		downStreamDropRate: jsonConfig.DownStreamDropRate,
	}
}

// register DropMessageFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &DropMessageFilter{})
}
