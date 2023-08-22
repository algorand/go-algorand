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
	"github.com/algorand/go-algorand/data/transactions/logic"
)

// AppKVPairs constructs a KV pair between state key and state value
type AppKVPairs map[string]basics.TealValue

// SingleAppInitialStates gathers all relevant application on-chain states, including
// - Application Box states
// - Application Global states
// - Application Local states (which is tied to basics.Address)
type SingleAppInitialStates struct {
	AppBoxes   AppKVPairs
	AppGlobals AppKVPairs
	AppLocals  map[basics.Address]AppKVPairs
}

// AppsInitialStates maintains a map from basics.AppIndex to SingleAppInitialStates
type AppsInitialStates map[basics.AppIndex]*SingleAppInitialStates

// ResourcesInitialStates gathers all initial states of resources that were accessed during simulation
type ResourcesInitialStates struct {
	// AllAppsInitialStates gathers all initial states of apps that were touched (but not created) during simulation
	AllAppsInitialStates AppsInitialStates
	// CreatedApp gathers all created applications by appID, blocking initial app states in these apps being recorded
	CreatedApp map[basics.AppIndex]struct{}
}

func newResourcesInitialStates(request Request) *ResourcesInitialStates {
	if !request.TraceConfig.State {
		return nil
	}
	return &ResourcesInitialStates{
		AllAppsInitialStates: make(AppsInitialStates),
		CreatedApp:           make(map[basics.AppIndex]struct{}),
	}
}

func (appIS SingleAppInitialStates) isRecorded(state logic.AppStateEnum, key string, addr basics.Address) (exists bool) {
	switch state {
	case logic.BoxState:
		_, exists = appIS.AppBoxes[key]
	case logic.GlobalState:
		_, exists = appIS.AppGlobals[key]
	case logic.LocalState:
		if kvs, addrLocalExists := appIS.AppLocals[addr]; addrLocalExists {
			_, exists = kvs[key]
		}
	}
	return
}

func (appsIS AppsInitialStates) appendInitialStates(cx *logic.EvalContext) {
	appState, stateOp, appID, acctAddr, stateKey := cx.GetOpSpec().AppStateExplain(cx)
	// No matter read or write, once this code-path is triggered, something must be recorded into initial state
	if _, ok := appsIS[appID]; !ok {
		appsIS[appID] = &SingleAppInitialStates{
			AppLocals:  make(map[basics.Address]AppKVPairs),
			AppGlobals: make(AppKVPairs),
			AppBoxes:   make(AppKVPairs),
		}
	}

	// if the state has been recorded, pass
	if appsIS[appID].isRecorded(appState, stateKey, acctAddr) {
		return
	}

	tv := logic.AppStateQuerying(cx, appState, stateOp, appID, acctAddr, stateKey)
	switch stateOp {
	case logic.AppStateWrite:
		// if the unrecorded value to write to is nil, pass
		// this case means it is creating a state
		if tv == (basics.TealValue{}) {
			return
		}
		fallthrough
	case logic.AppStateRead:
		switch appState {
		case logic.BoxState:
			appsIS[appID].AppBoxes[stateKey] = tv
		case logic.GlobalState:
			appsIS[appID].AppGlobals[stateKey] = tv
		case logic.LocalState:
			if appsIS[appID].AppLocals[acctAddr] == nil {
				appsIS[appID].AppLocals[acctAddr] = make(AppKVPairs)
			}
			appsIS[appID].AppLocals[acctAddr][stateKey] = tv
		}
	}
}

func (is *ResourcesInitialStates) appendInitialStates(cx *logic.EvalContext) {
	// This method only applies on logic.ModeApp
	if cx.RunMode() == logic.ModeSig {
		return
	}
	// If this method triggers application state changes
	if cx.GetOpSpec().AppStateExplain != nil {
		if _, appCreated := is.CreatedApp[cx.AppID()]; appCreated {
			return
		}
		is.AllAppsInitialStates.appendInitialStates(cx)
	}
	// TODO asset?
}
