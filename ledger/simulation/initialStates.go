// Copyright (C) 2019-2024 Algorand, Inc.
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
	"github.com/algorand/go-algorand/util"
)

// AppKVPairs constructs a KV pair between state key and state value
type AppKVPairs map[string]basics.TealValue

// SingleAppInitialStates gathers all relevant application on-chain states, including
// - Application Box states
// - Application Global states
// - Application Local states (which is tied to basics.Address)
type SingleAppInitialStates struct {
	AppBoxes     AppKVPairs
	CreatedBoxes util.Set[string]

	AppGlobals     AppKVPairs
	CreatedGlobals util.Set[string]

	AppLocals     map[basics.Address]AppKVPairs
	CreatedLocals map[basics.Address]util.Set[string]
}

// AppsInitialStates maintains a map from basics.AppIndex to SingleAppInitialStates
type AppsInitialStates map[basics.AppIndex]SingleAppInitialStates

// ResourcesInitialStates gathers all initial states of resources that were accessed during simulation
type ResourcesInitialStates struct {
	// AllAppsInitialStates gathers all initial states of apps that were touched (but not created) during simulation
	AllAppsInitialStates AppsInitialStates
	// CreatedApp gathers all created applications by appID, blocking initial app states in these apps being recorded
	CreatedApp util.Set[basics.AppIndex]
}

func newResourcesInitialStates(request Request) *ResourcesInitialStates {
	if !request.TraceConfig.State {
		return nil
	}
	return &ResourcesInitialStates{
		AllAppsInitialStates: make(AppsInitialStates),
		CreatedApp:           make(util.Set[basics.AppIndex]),
	}
}

// hasBeenRecorded checks if an application state kv-pair has been recorded in SingleAppInitialStates.
func (appIS SingleAppInitialStates) hasBeenRecorded(state logic.AppStateEnum, key string, addr basics.Address) (recorded bool) {
	switch state {
	case logic.BoxState:
		_, recorded = appIS.AppBoxes[key]
	case logic.GlobalState:
		_, recorded = appIS.AppGlobals[key]
	case logic.LocalState:
		if kvs, addrLocalExists := appIS.AppLocals[addr]; addrLocalExists {
			_, recorded = kvs[key]
		}
	}
	return
}

// hasBeenCreated checks if an application state kv-pair has been created during simulation.
func (appIS SingleAppInitialStates) hasBeenCreated(state logic.AppStateEnum, key string, addr basics.Address) (created bool) {
	switch state {
	case logic.BoxState:
		created = appIS.CreatedBoxes.Contains(key)
	case logic.GlobalState:
		created = appIS.CreatedGlobals.Contains(key)
	case logic.LocalState:
		if kvs, addrLocalExists := appIS.CreatedLocals[addr]; addrLocalExists {
			created = kvs.Contains(key)
		}
	}
	return
}

// recordCreation records a newly created application state kv-pair in SingleAppInitialStates during simulation.
func (appIS SingleAppInitialStates) recordCreation(state logic.AppStateEnum, key string, addr basics.Address) {
	switch state {
	case logic.BoxState:
		appIS.CreatedBoxes.Add(key)
	case logic.GlobalState:
		appIS.CreatedGlobals.Add(key)
	case logic.LocalState:
		if _, addrLocalExists := appIS.CreatedLocals[addr]; !addrLocalExists {
			appIS.CreatedLocals[addr] = make(util.Set[string])
		}
		appIS.CreatedLocals[addr].Add(key)
	}
}

func (appsIS AppsInitialStates) increment(cx *logic.EvalContext) {
	appState, stateOp, appID, acctAddr, stateKey := cx.GetOpSpec().AppStateExplain(cx)
	// No matter read or write, once this code-path is triggered, something must be recorded into initial state
	if _, ok := appsIS[appID]; !ok {
		appsIS[appID] = SingleAppInitialStates{
			AppGlobals:     make(AppKVPairs),
			CreatedGlobals: make(util.Set[string]),

			AppBoxes:     make(AppKVPairs),
			CreatedBoxes: make(util.Set[string]),

			AppLocals:     make(map[basics.Address]AppKVPairs),
			CreatedLocals: make(map[basics.Address]util.Set[string]),
		}
	}

	// if the state has been recorded, pass
	if appsIS[appID].hasBeenRecorded(appState, stateKey, acctAddr) {
		return
	}

	// if this state is created during simulation, pass
	if appsIS[appID].hasBeenCreated(appState, stateKey, acctAddr) {
		return
	}

	tv := logic.AppStateQuerying(cx, appState, stateOp, appID, acctAddr, stateKey)
	switch stateOp {
	case logic.AppStateWrite:
		// if the unrecorded value to write to is nil, pass
		// this case means it is creating a state
		if tv == (basics.TealValue{}) {
			appsIS[appID].recordCreation(appState, stateKey, acctAddr)
			return
		}
		fallthrough
	case logic.AppStateDelete:
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

// increment is the entry point of (potentially) adding new initial states to ResourcesInitialStates during simulation.
// This method is the top entry point of simulate-initial-state, for ResourcesInitialStates captures all initial states.
// By checking if current opcode has related `Explain` function, this method dispatch incrementing initial states by:
// +- AppStateExplain exists, then dispatch to AppsInitialStates.increment.
func (is *ResourcesInitialStates) increment(cx *logic.EvalContext) {
	// This method only applies on logic.ModeApp
	if cx.RunMode() == logic.ModeSig {
		return
	}
	// If this method triggers application state changes
	if cx.GetOpSpec().AppStateExplain != nil {
		if is.CreatedApp.Contains(cx.AppID()) {
			return
		}
		is.AllAppsInitialStates.increment(cx)
	}
	// TODO asset?
}
