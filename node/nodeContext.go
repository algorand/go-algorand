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

package node

import (
	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
)

type nodeContextData struct {
	muData            deadlock.RWMutex
	lastRoundObserved basics.Round
}

// IsCatchingUp (implements NodeContext) returns true if our sync routine is currently running
func (node *AlgorandFullNode) IsCatchingUp() bool {
	// Lock not required - catchupService doesn't change
	catchingUp, _ := node.catchupService.IsSynchronizing()
	return catchingUp
}

// IsInitialCatchupComplete (implements NodeContext) returns true if the initial sync has completed (doesn't mean it succeeded)
func (node *AlgorandFullNode) IsInitialCatchupComplete() bool {
	// Lock not required - catchupService doesn't change
	_, initSyncComplete := node.catchupService.IsSynchronizing()
	return initSyncComplete
}

// HasCaughtUp (implements NodeContext) returns true if we have completely caught up at least once
func (node *AlgorandFullNode) HasCaughtUp() bool {
	node.muData.RLock()
	defer node.muData.RUnlock()

	return node.lastRoundObserved != 0
}

// SetLastLiveRound is called to record observation of a round completion
func (node *AlgorandFullNode) SetLastLiveRound(round basics.Round) {
	node.muData.Lock()
	defer node.muData.Unlock()

	node.lastRoundObserved = round
}
