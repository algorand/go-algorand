// Copyright (C) 2019-2023 Algorand, Inc.
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

package simulation

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// AppKVPairs TODO
type AppKVPairs map[string]basics.TealValue

// SingleAppInitialStates gathers
type SingleAppInitialStates struct {
	AppBoxes   AppKVPairs
	AppGlobals AppKVPairs
	AppLocals  map[basics.Address]AppKVPairs
}

// AppsInitialStates TODO
type AppsInitialStates map[basics.AppIndex]SingleAppInitialStates

// ResourcesInitialStates gathers all initial states of resources that were accessed during simulation
type ResourcesInitialStates struct {
	Accounts map[basics.Address]basics.AccountData

	Assets        map[basics.AssetIndex]basics.AssetParams
	AssetHoldings map[ledgercore.AccountAsset]basics.AssetParams

	AppsInitialStates
}

func makeResourcesInitialStates(request Request) *ResourcesInitialStates {
	if !request.TraceConfig.State {
		return nil
	}
	return &ResourcesInitialStates{}
}
