// Copyright (C) 2019-2022 Algorand, Inc.
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

package protocol

// NodeType identifies the purpose of the node. Specified at startup via the config, this controls the
// set of services and functions that the node runs/exposes.
// Additional `NodeType`s need to be added to `config.GetNodeType`, otherwise the node startup will error.
type NodeType uint64

const (
	// NonParticipatingNode is currently the minimal set of functionality that a node can run.
	NonParticipatingNode NodeType = iota
	// ParticipatingNode runs everything `NonParticipatingNode`s do as well as the agreement service and functionality
	// for broadcasting transactions.
	ParticipatingNode
	// DataNode is a superset of `NonParticipatingNode` which additionally includes methods for controlling which
	// data is kept in the cache, and exposes methods for retrieving that data.
	DataNode
)
