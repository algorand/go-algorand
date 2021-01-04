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

package components

import "github.com/algorand/go-algorand/data/basics"

// NodeContext is an interface representing various context information regarding
// a specific node instance (per AlgorandFullNode)
type NodeContext interface {
	// IsCatchingUp returns true if our sync routine is currently running
	IsCatchingUp() bool

	// IsInitialCatchupComplete returns true if the initial sync has completed (doesn't mean it succeeded)
	IsInitialCatchupComplete() bool

	// HasCaughtUp returns true if we have completely caught up at least once
	HasCaughtUp() bool

	// SetLastLiveRound is called to record observation of a round completion
	SetLastLiveRound(round basics.Round)
}
