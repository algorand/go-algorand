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
