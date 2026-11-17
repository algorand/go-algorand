// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

// Package v2 defines models exposed by algod rest api
package v2

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

//msgp:allocbound SimulateRequestTxnGroups bounds.MaxTxGroupSize

// SimulateRequestTxnGroups is the txn-groups field of a SimulateRequest. Its
// allocbound is larger than simulation.MaxTxnGroups, so that the simulator
// reports a request with a few groups too many, as it does for a JSON request.
type SimulateRequestTxnGroups []SimulateRequestTxnGroup

// SimulateRequestTxnGroup is one transaction group of a SimulateRequest.
type SimulateRequestTxnGroup struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Txns []transactions.SignedTxn `codec:"txns,allocbound=bounds.MaxTxGroupSize"`
}

// SimulateRequest is a msgpack simulate request. It has the fields of
// model.SimulateRequest, with each transaction as a transactions.SignedTxn.
type SimulateRequest struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TxnGroups             SimulateRequestTxnGroups   `codec:"txn-groups"`
	Round                 basics.Round               `codec:"round"`
	AllowEmptySignatures  bool                       `codec:"allow-empty-signatures"`
	AllowMoreLogging      bool                       `codec:"allow-more-logging"`
	AllowUnnamedResources bool                       `codec:"allow-unnamed-resources"`
	ExtraOpcodeBudget     int64                      `codec:"extra-opcode-budget"`
	ExecTraceConfig       SimulateRequestTraceConfig `codec:"exec-trace-config"`
	FixSigners            bool                       `codec:"fix-signers"`
}

// SimulateRequestTraceConfig is the exec-trace-config field of a msgpack simulate
// request. It has the fields of simulation.ExecTraceConfig.
type SimulateRequestTraceConfig struct {
	_struct struct{} `codec:",omitempty"`

	Enable  bool `codec:"enable"`
	Stack   bool `codec:"stack-change"`
	Scratch bool `codec:"scratch-change"`
	State   bool `codec:"state-change"`
}

// AccountAssetModel is returned by AccountAssetInformation when msgpack format is specified
type AccountAssetModel struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	AssetParams  *basics.AssetParams  `codec:"asset-params"`
	AssetHolding *basics.AssetHolding `codec:"asset-holding"`
}

// AccountApplicationModel is returned by AccountApplicationInformation when msgpack format is specified
type AccountApplicationModel struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	AppLocalState *basics.AppLocalState `codec:"app-local-state"`
	AppParams     *basics.AppParams     `codec:"app-params"`
}

// AssetResourceToAccountAssetModel converts AssetResource to AccountAssetModel
func AssetResourceToAccountAssetModel(resource ledgercore.AssetResource) AccountAssetModel {
	return AccountAssetModel{
		AssetParams:  resource.AssetParams,
		AssetHolding: resource.AssetHolding,
	}
}

// AppResourceToAccountApplicationModel converts AppResource to AccountApplicationModel
func AppResourceToAccountApplicationModel(resource ledgercore.AppResource) AccountApplicationModel {
	return AccountApplicationModel{
		AppParams:     resource.AppParams,
		AppLocalState: resource.AppLocalState,
	}
}
