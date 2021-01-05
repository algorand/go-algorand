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
	"github.com/algorand/go-algorand/protocol"
)

// DownstreamFilter is the network filter downsteam filter interface
type DownstreamFilter interface {
	SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte)
	GetDownstreamFilter() DownstreamFilter
}

// UpstreamFilter is the network filter upstream filter interface
type UpstreamFilter interface {
	ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte)
	Tick(newClockTime int) bool // return true if a network operartion might be due; i.e. closed channel, sent message, etc.
}

// NetworkFilter is a single filter interface
type NetworkFilter interface {
	DownstreamFilter
	UpstreamFilter
	SetDownstreamFilter(f DownstreamFilter)
	SetUpstreamFilter(f UpstreamFilter)
}

type ShutdownFilter interface {
	PreShutdown()
	PostShutdown()
}

// NetworkFilterFactory interface used to create new network filters.
type NetworkFilterFactory interface {
	CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter
	Unmarshal([]byte) NetworkFilterFactory
}

var registeredFilterFactories = []NetworkFilterFactory{}
