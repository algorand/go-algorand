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

type NullFilter struct {
	NetworkFilter
	NetworkFilterFactory

	upstream   UpstreamFilter
	downstream DownstreamFilter
}

func (n *NullFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *NullFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *NullFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *NullFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *NullFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *NullFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	return &NullFilter{}
}

func (n *NullFilter) Tick(newClockTime int) bool {
	return n.upstream.Tick(newClockTime)
}

func (n *NullFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type nullFilterJSON struct {
		Name string
	}
	var jsonConfig nullFilterJSON
	if json.Unmarshal(b, &jsonConfig) != nil {
		return nil
	}
	if jsonConfig.Name != "NullFilter" {
		return nil
	}
	return &NullFilter{}
}

func init() {
	registeredFilterFactories = append(registeredFilterFactories, &NullFilter{})
}
