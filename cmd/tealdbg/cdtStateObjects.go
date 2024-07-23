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

package main

import (
	"github.com/algorand/go-algorand/cmd/tealdbg/cdt"
)

// Object IDs
const (
	localScopeObjID    = "localScopeObjId"
	globalScopeObjID   = "globalScopeObjID"
	globalsObjID       = "globalsObjID"
	txnObjID           = "txnObjID"
	gtxnObjID          = "gtxnObjID"
	stackObjID         = "stackObjID"
	scratchObjID       = "scratchObjID"
	tealErrorID        = "tealErrorID"
	appGlobalObjID     = "appGlobalObjID"
	appLocalsObjID     = "appLocalsObjID"
	txnArrayFieldObjID = "txnArrayField"
	logsObjID          = "logsObjID"
	innerTxnsObjID     = "innerTxnsObjID"
)

// Object Prefix IDs
const (
	gtxnObjIDPrefix           = gtxnObjID + "_gid_"
	logObjIDPrefix            = logsObjID + "_id"
	innerTxnObjIDPrefix       = innerTxnsObjID + "_id"
	innerNestedTxnObjIDPrefix = innerTxnsObjID + "_nested"
	appGlobalObjIDPrefix      = appGlobalObjID + "_"
	appLocalsObjIDPrefix      = appLocalsObjID + "_"
	appLocalAppIDPrefix       = appLocalsObjID + "__"
	txnArrayFieldPrefix       = txnArrayFieldObjID + "__"
)

type objectDescFn func(s *cdtState, preview bool) []cdt.RuntimePropertyDescriptor

var objectDescMap = map[string]objectDescFn{
	globalScopeObjID: makeGlobalScope,
	localScopeObjID:  makeLocalScope,
	globalsObjID:     makeGlobals,
	txnObjID:         makeTxn,
	gtxnObjID:        makeTxnGroup,
	stackObjID:       makeStack,
	scratchObjID:     makeScratch,
	tealErrorID:      makeTealError,
	appGlobalObjID:   makeAppGlobalState,
	appLocalsObjID:   makeAppLocalsState,
	logsObjID:        makeLogsState,
	innerTxnsObjID:   makeInnerTxnsState,
}
