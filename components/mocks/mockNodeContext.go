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

package mocks

import "github.com/algorand/go-algorand/data/basics"

// MockNodeContext implements NodeContext for testing
type MockNodeContext struct {
	CatchingUp                bool
	InitialCatchupNotComplete bool
	NotCaughtUp               bool
}

// IsCatchingUp (implements NodeContext) returns true if our sync routine is currently running
func (ctx *MockNodeContext) IsCatchingUp() bool {
	return ctx.CatchingUp
}

// IsInitialCatchupComplete (implements NodeContext) returns true if the initial sync has completed (doesn't mean it succeeded)
func (ctx *MockNodeContext) IsInitialCatchupComplete() bool {
	return !ctx.InitialCatchupNotComplete
}

// HasCaughtUp (implements NodeContext) returns true if we have completely caught up at least once
func (ctx *MockNodeContext) HasCaughtUp() bool {
	return ctx.NotCaughtUp
}

// SetLastLiveRound is called to record observation of a round completion
func (ctx *MockNodeContext) SetLastLiveRound(round basics.Round) {
}
