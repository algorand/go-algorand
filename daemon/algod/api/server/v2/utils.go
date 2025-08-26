// Copyright (C) 2019-2025 Algorand, Inc.
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

package v2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/algorand/go-codec/codec"
	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

// returnError logs an internal message while returning the encoded response.
func returnError(ctx echo.Context, code int, internal error, external string, logger logging.Logger) error {
	logger.Info(internal)
	var data *map[string]any
	var se *basics.SError
	if errors.As(internal, &se) {
		data = &se.Attrs
	}
	return ctx.JSON(code, model.ErrorResponse{Message: external, Data: data})
}

func badRequest(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusBadRequest, internal, external, log)
}

func serviceUnavailable(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusServiceUnavailable, internal, external, log)
}

func timeout(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusRequestTimeout, internal, external, log)
}

func internalError(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusInternalServerError, internal, external, log)
}

func notFound(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusNotFound, internal, external, log)
}

func notImplemented(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusNotImplemented, internal, external, log)
}

func convertMap[X comparable, Y, Z any](input map[X]Y, fn func(X, Y) Z) []Z {
	output := make([]Z, len(input))
	counter := 0
	for x, y := range input {
		output[counter] = fn(x, y)
		counter++
	}
	return output
}

func stringSlice[T fmt.Stringer](s []T) []string {
	return util.Map(s, func(t T) string { return t.String() })
}

func sliceOrNil[T any](s []T) *[]T {
	if len(s) == 0 {
		return nil
	}
	return &s
}

func addrOrNil(addr basics.Address) *string {
	if addr.IsZero() {
		return nil
	}
	ret := addr.String()
	return &ret
}

func digestOrNil(digest crypto.Digest) *[]byte {
	if digest.IsZero() {
		return nil
	}
	ret := digest.ToSlice()
	return &ret
}

// omitEmpty defines a handy impl for all comparable types to convert from default value to nil ptr
func omitEmpty[T comparable](val T) *T {
	var defaultVal T
	if val == defaultVal {
		return nil
	}
	return &val
}

func nilToZero[T any](valPtr *T) T {
	if valPtr == nil {
		var defaultV T
		return defaultV
	}
	return *valPtr
}

func computeCreatableIndexInPayset(tx node.TxnWithStatus, txnCounter uint64, payset []transactions.SignedTxnWithAD) (cidx *uint64) {
	// Compute transaction index in block
	txID := tx.Txn.Txn.ID()
	offset := slices.IndexFunc(payset, func(ad transactions.SignedTxnWithAD) bool {
		return ad.Txn.ID() == txID
	})

	// Sanity check that txn was in fetched block
	if offset < 0 {
		return nil
	}

	// Count into block to get created asset index
	idx := txnCounter - uint64(len(payset)) + uint64(offset) + 1
	return &idx
}

// computeAssetIndexFromTxn returns the created asset index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAssetIndexFromTxn(tx node.TxnWithStatus, l LedgerForAPI) *basics.AssetIndex {
	// Must have ledger
	if l == nil {
		return nil
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return nil
	}
	// Transaction must be AssetConfig transaction
	if tx.Txn.Txn.AssetConfigTxnFields == (transactions.AssetConfigTxnFields{}) {
		return nil
	}
	// Transaction must be creating an asset
	if tx.Txn.Txn.AssetConfigTxnFields.ConfigAsset != 0 {
		return nil
	}

	aid := tx.ApplyData.ConfigAsset
	if aid > 0 {
		return &aid
	}
	// If there is no ConfigAsset in the ApplyData, it must be a
	// transaction before inner transactions were activated. Therefore
	// the computeCreatableIndexInPayset function will work properly
	// to deduce the aid. Proceed.

	// Look up block where transaction was confirmed
	blk, err := l.Block(tx.ConfirmedRound)
	if err != nil {
		return nil
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil
	}

	return (*basics.AssetIndex)(computeCreatableIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset))
}

// computeAppIndexFromTxn returns the created app index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAppIndexFromTxn(tx node.TxnWithStatus, l LedgerForAPI) *basics.AppIndex {
	// Must have ledger
	if l == nil {
		return nil
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return nil
	}
	// Transaction must be ApplicationCall transaction
	if tx.Txn.Txn.ApplicationCallTxnFields.Empty() {
		return nil
	}
	// Transaction must be creating an application
	if tx.Txn.Txn.ApplicationCallTxnFields.ApplicationID != 0 {
		return nil
	}

	aid := tx.ApplyData.ApplicationID
	if aid > 0 {
		return &aid
	}
	// If there is no ApplicationID in the ApplyData, it must be a
	// transaction before inner transactions were activated. Therefore
	// the computeCreatableIndexInPayset function will work properly
	// to deduce the aid. Proceed.

	// Look up block where transaction was confirmed
	blk, err := l.Block(tx.ConfirmedRound)
	if err != nil {
		return nil
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil
	}

	return (*basics.AppIndex)(computeCreatableIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset))
}

// getCodecHandle converts a format string into the encoder + content type
func getCodecHandle(formatPtr *string) (codec.Handle, string, error) {
	format := "json"
	if formatPtr != nil {
		format = strings.ToLower(*formatPtr)
	}

	switch format {
	case "json":
		return protocol.JSONStrictHandle, "application/json", nil
	case "msgpack":
		fallthrough
	case "msgp":
		return protocol.CodecHandle, "application/msgpack", nil
	default:
		return nil, "", fmt.Errorf("invalid format: %s", format)
	}
}

func encode(handle codec.Handle, obj interface{}) ([]byte, error) {
	var output []byte
	enc := codec.NewEncoderBytes(&output, handle)

	err := enc.Encode(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to encode object: %v", err)
	}
	return output, nil
}

func decode(handle codec.Handle, data []byte, v interface{}) error {
	enc := codec.NewDecoderBytes(data, handle)

	err := enc.Decode(v)
	if err != nil {
		return fmt.Errorf("failed to decode object: %v", err)
	}
	return nil
}

// globalDeltaToStateDelta converts basics.StateDelta -> model.StateDelta. It
// should only be used on globals, because locals require extra context to
// translate account indexes.
func globalDeltaToStateDelta(bsd basics.StateDelta) model.StateDelta {
	if len(bsd) == 0 {
		return nil
	}
	msd := make(model.StateDelta, 0, len(bsd))
	for k, v := range bsd {
		msd = append(msd, model.EvalDeltaKeyValue{
			Key: base64.StdEncoding.EncodeToString([]byte(k)),
			Value: model.EvalDelta{
				Action: uint64(v.Action),
				Bytes:  omitEmpty(base64.StdEncoding.EncodeToString([]byte(v.Bytes))),
				Uint:   omitEmpty(v.Uint),
			},
		})
	}
	return msd
}

func edIndexToAddress(index uint64, txn *transactions.Transaction, shared []basics.Address) string {
	// index into [Sender, txn.Accounts[0], txn.Accounts[1], ..., shared[0], shared[1], ...]
	switch {
	case index == 0:
		return txn.Sender.String()
	case int(index-1) < len(txn.Accounts):
		return txn.Accounts[index-1].String()
	case int(index-1)-len(txn.Accounts) < len(shared):
		return shared[int(index-1)-len(txn.Accounts)].String()
	default:
		return fmt.Sprintf("Invalid Account Index %d in LocalDelta", index)
	}
}

func localDeltasToLocalDeltas(ed transactions.EvalDelta, txn *transactions.Transaction) []model.AccountStateDelta {
	if len(ed.LocalDeltas) == 0 {
		return nil
	}
	lsd := make([]model.AccountStateDelta, 0, len(ed.LocalDeltas))
	shared := ed.SharedAccts

	for k, v := range ed.LocalDeltas {
		lsd = append(lsd, model.AccountStateDelta{
			Address: edIndexToAddress(k, txn, shared),
			Delta:   globalDeltaToStateDelta(v),
		})
	}

	return lsd
}

func convertLogs(txn node.TxnWithStatus) *[][]byte {
	var logItems *[][]byte
	if len(txn.ApplyData.EvalDelta.Logs) > 0 {
		l := make([][]byte, len(txn.ApplyData.EvalDelta.Logs))

		for i, log := range txn.ApplyData.EvalDelta.Logs {
			l[i] = []byte(log)
		}

		logItems = &l
	}
	return logItems
}

func convertInners(txn *node.TxnWithStatus) *[]PreEncodedTxInfo {
	inner := make([]PreEncodedTxInfo, len(txn.ApplyData.EvalDelta.InnerTxns))
	for i := range txn.ApplyData.EvalDelta.InnerTxns {
		inner[i] = ConvertInnerTxn(&txn.ApplyData.EvalDelta.InnerTxns[i])
	}
	return &inner
}

// ConvertInnerTxn converts an inner SignedTxnWithAD to PreEncodedTxInfo for the REST API
func ConvertInnerTxn(txn *transactions.SignedTxnWithAD) PreEncodedTxInfo {
	// This copies from handlers.PendingTransactionInformation, with
	// simplifications because we have a SignedTxnWithAD rather than
	// TxnWithStatus, and we know this txn has committed.

	response := PreEncodedTxInfo{Txn: txn.SignedTxn}

	response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
	response.AssetClosingAmount = &txn.ApplyData.AssetClosingAmount
	response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
	response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
	response.CloseRewards = &txn.ApplyData.CloseRewards.Raw

	// Since this is an inner txn, we know these indexes will be populated. No
	// need to search payset for IDs
	response.AssetIndex = omitEmpty(txn.ApplyData.ConfigAsset)
	response.ApplicationIndex = omitEmpty(txn.ApplyData.ApplicationID)

	response.LocalStateDelta = sliceOrNil(localDeltasToLocalDeltas(txn.ApplyData.EvalDelta, &txn.Txn))
	response.GlobalStateDelta = sliceOrNil(globalDeltaToStateDelta(txn.ApplyData.EvalDelta.GlobalDelta))
	withStatus := node.TxnWithStatus{
		Txn:       txn.SignedTxn,
		ApplyData: txn.ApplyData,
	}
	response.Logs = convertLogs(withStatus)
	response.Inners = convertInners(&withStatus)
	return response
}

func convertToAVMValue(tv basics.TealValue) model.AvmValue {
	return model.AvmValue{
		Type:  uint64(tv.Type),
		Uint:  omitEmpty(tv.Uint),
		Bytes: sliceOrNil([]byte(tv.Bytes)),
	}
}

func convertScratchChange(scratchChange simulation.ScratchChange) model.ScratchChange {
	return model.ScratchChange{
		Slot:     scratchChange.Slot,
		NewValue: convertToAVMValue(scratchChange.NewValue),
	}
}

func convertApplicationState(stateEnum logic.AppStateEnum) string {
	switch stateEnum {
	case logic.LocalState:
		return "l"
	case logic.GlobalState:
		return "g"
	case logic.BoxState:
		return "b"
	default:
		return ""
	}
}

func convertApplicationStateOperation(opEnum logic.AppStateOpEnum) string {
	switch opEnum {
	case logic.AppStateWrite:
		return "w"
	case logic.AppStateDelete:
		return "d"
	default:
		return ""
	}
}

func convertApplicationStateChange(stateChange simulation.StateOperation) model.ApplicationStateOperation {
	return model.ApplicationStateOperation{
		Key:          []byte(stateChange.Key),
		NewValue:     omitEmpty(convertToAVMValue(stateChange.NewValue)),
		Operation:    convertApplicationStateOperation(stateChange.AppStateOp),
		AppStateType: convertApplicationState(stateChange.AppState),
		Account:      addrOrNil(stateChange.Account),
	}
}

func convertOpcodeTraceUnit(opcodeTraceUnit simulation.OpcodeTraceUnit) model.SimulationOpcodeTraceUnit {
	return model.SimulationOpcodeTraceUnit{
		Pc:             opcodeTraceUnit.PC,
		SpawnedInners:  sliceOrNil(opcodeTraceUnit.SpawnedInners),
		StackAdditions: sliceOrNil(util.Map(opcodeTraceUnit.StackAdded, convertToAVMValue)),
		StackPopCount:  omitEmpty(opcodeTraceUnit.StackPopCount),
		ScratchChanges: sliceOrNil(util.Map(opcodeTraceUnit.ScratchSlotChanges, convertScratchChange)),
		StateChanges:   sliceOrNil(util.Map(opcodeTraceUnit.StateChanges, convertApplicationStateChange)),
	}
}

func convertTxnTrace(txnTrace *simulation.TransactionTrace) *model.SimulationTransactionExecTrace {
	if txnTrace == nil {
		return nil
	}
	return &model.SimulationTransactionExecTrace{
		ApprovalProgramTrace:    sliceOrNil(util.Map(txnTrace.ApprovalProgramTrace, convertOpcodeTraceUnit)),
		ApprovalProgramHash:     digestOrNil(txnTrace.ApprovalProgramHash),
		ClearStateProgramTrace:  sliceOrNil(util.Map(txnTrace.ClearStateProgramTrace, convertOpcodeTraceUnit)),
		ClearStateProgramHash:   digestOrNil(txnTrace.ClearStateProgramHash),
		ClearStateRollback:      omitEmpty(txnTrace.ClearStateRollback),
		ClearStateRollbackError: omitEmpty(txnTrace.ClearStateRollbackError),
		LogicSigTrace:           sliceOrNil(util.Map(txnTrace.LogicSigTrace, convertOpcodeTraceUnit)),
		LogicSigHash:            digestOrNil(txnTrace.LogicSigHash),
		InnerTrace: sliceOrNil(util.Map(txnTrace.InnerTraces,
			func(trace simulation.TransactionTrace) model.SimulationTransactionExecTrace {
				return *convertTxnTrace(&trace)
			}),
		),
	}
}

func convertTxnResult(txnResult simulation.TxnResult, simplify bool) PreEncodedSimulateTxnResult {
	result := PreEncodedSimulateTxnResult{
		Txn:                      ConvertInnerTxn(&txnResult.Txn),
		AppBudgetConsumed:        omitEmpty(txnResult.AppBudgetConsumed),
		LogicSigBudgetConsumed:   omitEmpty(txnResult.LogicSigBudgetConsumed),
		TransactionTrace:         convertTxnTrace(txnResult.Trace),
		UnnamedResourcesAccessed: convertUnnamedResourcesAccessed(txnResult.UnnamedResourcesAccessed, simplify),
	}

	if !txnResult.FixedSigner.IsZero() {
		fixedSigner := txnResult.FixedSigner.String()
		result.FixedSigner = &fixedSigner
	}

	return result
}

func convertUnnamedResourcesAccessed(resources *simulation.ResourceTracker, simplify bool) *model.SimulateUnnamedResourcesAccessed {
	if resources == nil {
		return nil
	}
	if simplify {
		resources.Simplify()
	}
	return &model.SimulateUnnamedResourcesAccessed{
		Accounts: sliceOrNil(stringSlice(slices.Collect(maps.Keys(resources.Accounts)))),
		Assets:   sliceOrNil(slices.Collect(maps.Keys(resources.Assets))),
		Apps:     sliceOrNil(slices.Collect(maps.Keys(resources.Apps))),
		Boxes: sliceOrNil(util.Map(slices.Collect(maps.Keys(resources.Boxes)), func(box basics.BoxRef) model.BoxReference {
			return model.BoxReference{
				App:  box.App,
				Name: []byte(box.Name),
			}
		})),
		ExtraBoxRefs: omitEmpty(resources.NumEmptyBoxRefs),
		AssetHoldings: sliceOrNil(util.Map(slices.Collect(maps.Keys(resources.AssetHoldings)), func(holding ledgercore.AccountAsset) model.AssetHoldingReference {
			return model.AssetHoldingReference{
				Account: holding.Address.String(),
				Asset:   holding.Asset,
			}
		})),
		AppLocals: sliceOrNil(util.Map(slices.Collect(maps.Keys(resources.AppLocals)), func(local ledgercore.AccountApp) model.ApplicationLocalReference {
			return model.ApplicationLocalReference{
				Account: local.Address.String(),
				App:     local.App,
			}
		})),
	}
}

func convertAppKVStorePtr(address basics.Address, appKVPairs simulation.AppKVPairs) *model.ApplicationKVStorage {
	if len(appKVPairs) == 0 && address.IsZero() {
		return nil
	}
	return &model.ApplicationKVStorage{
		Account: addrOrNil(address),
		Kvs: convertMap(appKVPairs, func(key string, value basics.TealValue) model.AvmKeyValue {
			return model.AvmKeyValue{
				Key:   []byte(key),
				Value: convertToAVMValue(value),
			}
		}),
	}
}

func convertAppKVStoreInstance(address basics.Address, appKVPairs simulation.AppKVPairs) model.ApplicationKVStorage {
	return model.ApplicationKVStorage{
		Account: addrOrNil(address),
		Kvs: convertMap(appKVPairs, func(key string, value basics.TealValue) model.AvmKeyValue {
			return model.AvmKeyValue{
				Key:   []byte(key),
				Value: convertToAVMValue(value),
			}
		}),
	}
}

func convertApplicationInitialStates(appID basics.AppIndex, states simulation.SingleAppInitialStates) model.ApplicationInitialStates {
	return model.ApplicationInitialStates{
		Id:         appID,
		AppBoxes:   convertAppKVStorePtr(basics.Address{}, states.AppBoxes),
		AppGlobals: convertAppKVStorePtr(basics.Address{}, states.AppGlobals),
		AppLocals:  sliceOrNil(convertMap(states.AppLocals, convertAppKVStoreInstance)),
	}
}

func convertSimulateInitialStates(initialStates *simulation.ResourcesInitialStates) *model.SimulateInitialStates {
	if initialStates == nil {
		return nil
	}
	return &model.SimulateInitialStates{
		AppInitialStates: sliceOrNil(convertMap(initialStates.AllAppsInitialStates, convertApplicationInitialStates)),
	}
}

func convertTxnGroupResult(txnGroupResult simulation.TxnGroupResult, simplify bool) PreEncodedSimulateTxnGroupResult {
	txnResults := make([]PreEncodedSimulateTxnResult, len(txnGroupResult.Txns))
	for i, txnResult := range txnGroupResult.Txns {
		txnResults[i] = convertTxnResult(txnResult, simplify)
	}

	encoded := PreEncodedSimulateTxnGroupResult{
		Txns:                     txnResults,
		FailureMessage:           omitEmpty(txnGroupResult.FailureMessage),
		AppBudgetAdded:           omitEmpty(txnGroupResult.AppBudgetAdded),
		AppBudgetConsumed:        omitEmpty(txnGroupResult.AppBudgetConsumed),
		UnnamedResourcesAccessed: convertUnnamedResourcesAccessed(txnGroupResult.UnnamedResourcesAccessed, simplify),
	}

	if len(txnGroupResult.FailedAt) > 0 {
		failedAt := slices.Clone[[]int, int](txnGroupResult.FailedAt)
		encoded.FailedAt = &failedAt
	}

	return encoded
}

func convertSimulationResult(result simulation.Result, simplify bool) PreEncodedSimulateResponse {
	var evalOverrides *model.SimulationEvalOverrides
	if result.EvalOverrides != (simulation.ResultEvalOverrides{}) {
		evalOverrides = &model.SimulationEvalOverrides{
			AllowEmptySignatures:  omitEmpty(result.EvalOverrides.AllowEmptySignatures),
			AllowUnnamedResources: omitEmpty(result.EvalOverrides.AllowUnnamedResources),
			MaxLogSize:            result.EvalOverrides.MaxLogSize,
			MaxLogCalls:           result.EvalOverrides.MaxLogCalls,
			ExtraOpcodeBudget:     omitEmpty(result.EvalOverrides.ExtraOpcodeBudget),
			FixSigners:            omitEmpty(result.EvalOverrides.FixSigners),
		}
	}

	return PreEncodedSimulateResponse{
		Version:   result.Version,
		LastRound: result.LastRound,
		TxnGroups: util.Map(result.TxnGroups, func(tg simulation.TxnGroupResult) PreEncodedSimulateTxnGroupResult {
			return convertTxnGroupResult(tg, simplify)
		}),
		EvalOverrides:   evalOverrides,
		ExecTraceConfig: result.TraceConfig,
		InitialStates:   convertSimulateInitialStates(result.InitialStates),
	}
}

func convertSimulationRequest(request PreEncodedSimulateRequest) simulation.Request {
	txnGroups := make([][]transactions.SignedTxn, len(request.TxnGroups))
	for i, txnGroup := range request.TxnGroups {
		txnGroups[i] = txnGroup.Txns
	}
	return simulation.Request{
		TxnGroups:             txnGroups,
		Round:                 request.Round,
		AllowEmptySignatures:  request.AllowEmptySignatures,
		AllowMoreLogging:      request.AllowMoreLogging,
		AllowUnnamedResources: request.AllowUnnamedResources,
		ExtraOpcodeBudget:     request.ExtraOpcodeBudget,
		TraceConfig:           request.ExecTraceConfig,
		FixSigners:            request.FixSigners,
	}
}

// printableUTF8OrEmpty checks to see if the entire string is a UTF8 printable string.
// If this is the case, the string is returned as is. Otherwise, the empty string is returned.
func printableUTF8OrEmpty(in string) string {
	// iterate throughout all the characters in the string to see if they are all printable.
	// when range iterating on go strings, go decode each element as a utf8 rune.
	for _, c := range in {
		// is this a printable character, or invalid rune ?
		if c == utf8.RuneError || !unicode.IsPrint(c) {
			return ""
		}
	}
	return in
}
