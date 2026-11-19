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

	"github.com/labstack/echo/v4"

	"github.com/algorand/go-codec/codec"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
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

func nilToZeroAddr(s *string) (basics.Address, error) {
	if s == nil {
		return basics.Address{}, nil
	}
	addr, err := basics.UnmarshalChecksumAddress(*s)
	if err != nil {
		return basics.Address{}, err
	}
	return addr, nil
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

func encode(handle codec.Handle, obj any) ([]byte, error) {
	var output []byte
	enc := codec.NewEncoderBytes(&output, handle)

	err := enc.Encode(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to encode object: %v", err)
	}
	return output, nil
}

func decode(handle codec.Handle, data []byte, v any) error {
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
	case index-1 < uint64(len(txn.Accounts)):
		return txn.Accounts[index-1].String()
	case index-1-uint64(len(txn.Accounts)) < uint64(len(shared)):
		return shared[index-1-uint64(len(txn.Accounts))].String()
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

func convertTxnResult(txnResult simulation.TxnResult) PreEncodedSimulateTxnResult {
	result := PreEncodedSimulateTxnResult{
		Txn:                      ConvertInnerTxn(&txnResult.Txn),
		AppBudgetConsumed:        omitEmpty(txnResult.AppBudgetConsumed),
		LogicSigBudgetConsumed:   omitEmpty(txnResult.LogicSigBudgetConsumed),
		FeesPaid:                 omitEmpty(txnResult.FeesPaid.Raw),
		TransactionTrace:         convertTxnTrace(txnResult.Trace),
		UnnamedResourcesAccessed: convertUnnamedResourcesAccessed(txnResult.UnnamedResourcesAccessed),
	}

	if !txnResult.FixedSigner.IsZero() {
		fixedSigner := txnResult.FixedSigner.String()
		result.FixedSigner = &fixedSigner
	}

	return result
}

func convertUnnamedResourcesAccessed(resources *simulation.ResourceTracker) *model.SimulateUnnamedResourcesAccessed {
	if resources == nil {
		return nil
	}
	resources.Simplify()
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

func convertTxnGroupResult(txnGroupResult simulation.TxnGroupResult) PreEncodedSimulateTxnGroupResult {
	txnResults := util.Map(txnGroupResult.Txns, convertTxnResult)

	encoded := PreEncodedSimulateTxnGroupResult{
		Txns:                     txnResults,
		FailureMessage:           omitEmpty(txnGroupResult.FailureMessage),
		AppBudgetAdded:           omitEmpty(txnGroupResult.AppBudgetAdded),
		AppBudgetConsumed:        omitEmpty(txnGroupResult.AppBudgetConsumed),
		GroupUsage:               omitEmpty(uint64(txnGroupResult.GroupUsage)),
		GroupFeesPaid:            omitEmpty(txnGroupResult.GroupFeesPaid.Raw),
		UnnamedResourcesAccessed: convertUnnamedResourcesAccessed(txnGroupResult.UnnamedResourcesAccessed),
	}

	if len(txnGroupResult.FailedAt) > 0 {
		failedAt := slices.Clone[[]int, int](txnGroupResult.FailedAt)
		encoded.FailedAt = &failedAt
	}

	return encoded
}

func convertSimulationResult(result simulation.Result) PreEncodedSimulateResponse {
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
		Version:         result.Version,
		LastRound:       result.LastRound,
		TxnGroups:       util.Map(result.TxnGroups, convertTxnGroupResult),
		EvalOverrides:   evalOverrides,
		ExecTraceConfig: result.TraceConfig,
		InitialStates:   convertSimulateInitialStates(result.InitialStates),
	}
}

func convertSimulationRequest(request PreEncodedSimulateRequest) (simulation.Request, error) {
	txnGroups := make([][]transactions.SignedTxn, len(request.TxnGroups))
	for i, txnGroup := range request.TxnGroups {
		txnGroups[i] = txnGroup.Txns
	}
	stateOverrides, err := convertStateOverrides(request.StateOverrides)
	if err != nil {
		return simulation.Request{}, err
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
		StateOverrides:        stateOverrides,
	}, nil
}

// convertOverrides converts a list of override entries into a map. kind names an entry in errors,
// key returns the map key of an entry, and convert returns its value.
func convertOverrides[E any, K comparable, V any](entries *[]E, kind string, key func(E) (K, error), convert func(E) (V, error)) (map[K]V, error) {
	if entries == nil || len(*entries) == 0 {
		return nil, nil
	}
	result := make(map[K]V, len(*entries))
	for _, entry := range *entries {
		k, err := key(entry)
		if err != nil {
			return nil, err
		}
		if _, ok := result[k]; ok {
			return nil, fmt.Errorf("duplicate %s %v", kind, k)
		}
		v, err := convert(entry)
		if err != nil {
			return nil, fmt.Errorf("%s %v: %w", kind, k, err)
		}
		result[k] = v
	}
	return result, nil
}

func convertStateOverrides(overrides *model.SimulateStateOverrides) (simulation.StateOverrides, error) {
	var result simulation.StateOverrides
	if overrides == nil {
		return result, nil
	}

	var err error
	result.Accounts, err = convertOverrides(overrides.Accounts, "account",
		func(acct model.SimulateAccountOverride) (basics.Address, error) {
			addr, addrErr := basics.UnmarshalChecksumAddress(acct.Address)
			if addrErr != nil {
				return basics.Address{}, fmt.Errorf("account address %q: %w", acct.Address, addrErr)
			}
			return addr, nil
		}, convertAccountOverride)
	if err == nil {
		result.Apps, err = convertOverrides(overrides.Apps, "app",
			func(app model.SimulateAppOverride) (basics.AppIndex, error) { return app.Id, nil }, convertAppOverride)
	}
	if err == nil {
		result.Assets, err = convertOverrides(overrides.Assets, "asset",
			func(asset model.SimulateAssetOverride) (basics.AssetIndex, error) { return asset.Id, nil }, convertAssetOverride)
	}
	if err == nil {
		result.Blocks, err = convertOverrides(overrides.Blocks, "block",
			func(block model.SimulateBlockOverride) (basics.Round, error) {
				// Round is a pointer so that an omitted round is not taken to be round 0
				if block.Round == nil {
					return 0, errors.New("block round is required")
				}
				return *block.Round, nil
			}, convertBlockOverride)
	}
	if err != nil {
		return simulation.StateOverrides{}, fmt.Errorf("invalid state override: %w", err)
	}
	return result, nil
}

// fixedBytes converts an optional byte slice into a fixed-size array. name describes the field in
// errors.
func fixedBytes[T ~[32]byte | ~[64]byte](name string, value *[]byte) (*T, error) {
	if value == nil {
		return nil, nil
	}
	var result T
	if len(*value) != len(result) {
		return nil, fmt.Errorf("%s must be %d bytes, not %d", name, len(result), len(*value))
	}
	for i, b := range *value {
		result[i] = b
	}
	return &result, nil
}

// optionalAddress is an optional checksummed address, and where its decoded value is stored.
type optionalAddress struct {
	name  string
	value *string
	dest  **basics.Address
}

// convertAddresses decodes each address that is set into its dest.
func convertAddresses(addrs ...optionalAddress) error {
	for _, a := range addrs {
		if a.value == nil {
			continue
		}
		addr, err := basics.UnmarshalChecksumAddress(*a.value)
		if err != nil {
			return fmt.Errorf("%s %q: %w", a.name, *a.value, err)
		}
		*a.dest = &addr
	}
	return nil
}

func convertBlockOverride(block model.SimulateBlockOverride) (simulation.BlockOverride, error) {
	var override simulation.BlockOverride
	var err error
	override.TimeStamp = block.Timestamp
	if override.Seed, err = fixedBytes[committee.Seed]("seed", block.Seed); err != nil {
		return simulation.BlockOverride{}, err
	}
	err = convertAddresses(
		optionalAddress{"proposer", block.Proposer, &override.Proposer},
		optionalAddress{"fee-sink", block.FeeSink, &override.FeeSink},
	)
	if err != nil {
		return simulation.BlockOverride{}, err
	}
	amounts := []struct {
		value *uint64
		dest  **basics.MicroAlgos
	}{
		{block.FeesCollected, &override.FeesCollected},
		{block.Bonus, &override.Bonus},
		{block.ProposerPayout, &override.ProposerPayout},
	}
	for _, a := range amounts {
		if a.value != nil {
			*a.dest = &basics.MicroAlgos{Raw: *a.value}
		}
	}
	return override, nil
}

func convertAccountOverride(acct model.SimulateAccountOverride) (simulation.AccountOverride, error) {
	var override simulation.AccountOverride
	if acct.Balance != nil {
		override.Balance = &basics.MicroAlgos{Raw: *acct.Balance}
	}
	if acct.AuthAddr != nil {
		authAddr, err := basics.UnmarshalChecksumAddress(*acct.AuthAddr)
		if err != nil {
			return simulation.AccountOverride{}, fmt.Errorf("auth-addr %q: %w", *acct.AuthAddr, err)
		}
		override.AuthAddr = &authAddr
	}
	if acct.Status != nil {
		var status basics.Status
		// Accept the documented NotParticipating, as well as "Not Participating", which is how
		// account status is returned
		if *acct.Status == "NotParticipating" {
			status = basics.NotParticipating
		} else {
			var err error
			status, err = basics.UnmarshalStatus(*acct.Status)
			if err != nil {
				return simulation.AccountOverride{}, err
			}
		}
		override.Status = &status
	}
	var err error
	if override.VoteID, err = fixedBytes[crypto.OneTimeSignatureVerifier]("vote participation key", acct.VoteParticipationKey); err != nil {
		return simulation.AccountOverride{}, err
	}
	if override.SelectionID, err = fixedBytes[crypto.VRFVerifier]("selection participation key", acct.SelectionParticipationKey); err != nil {
		return simulation.AccountOverride{}, err
	}
	if override.StateProofID, err = fixedBytes[merklesignature.Commitment]("state proof key", acct.StateProofKey); err != nil {
		return simulation.AccountOverride{}, err
	}
	override.VoteFirstValid = acct.VoteFirstValid
	override.VoteLastValid = acct.VoteLastValid
	override.VoteKeyDilution = acct.VoteKeyDilution
	override.IncentiveEligible = acct.IncentiveEligible
	override.LastProposed = acct.LastProposed
	override.LastHeartbeat = acct.LastHeartbeat

	override.Assets, err = convertOverrides(acct.Assets, "asset",
		func(holding model.SimulateAssetHoldingOverride) (basics.AssetIndex, error) {
			return holding.AssetID, nil
		},
		func(holding model.SimulateAssetHoldingOverride) (simulation.AssetHoldingOverride, error) {
			return simulation.AssetHoldingOverride{Amount: holding.Amount, Frozen: holding.IsFrozen}, nil
		})
	if err != nil {
		return simulation.AccountOverride{}, err
	}
	override.Apps, err = convertOverrides(acct.Apps, "app",
		func(local model.SimulateAppLocalStateOverride) (basics.AppIndex, error) { return local.AppID, nil },
		func(local model.SimulateAppLocalStateOverride) (simulation.AppLocalStateOverride, error) {
			return convertAppLocalStateOverride(local), nil
		})
	if err != nil {
		return simulation.AccountOverride{}, err
	}
	return override, nil
}

func convertAppLocalStateOverride(local model.SimulateAppLocalStateOverride) simulation.AppLocalStateOverride {
	var override simulation.AppLocalStateOverride
	if local.Schema != nil {
		schema := convertStateSchema(*local.Schema)
		override.Schema = &schema
	}
	if local.OptOut != nil {
		override.OptOut = *local.OptOut
	}
	return override
}

// convertStateDelta converts model.StateDelta -> basics.StateDelta, the inverse of
// globalDeltaToStateDelta. Errors are phrased to follow a description of the store, e.g. "global
// state".
func convertStateDelta(msd *model.StateDelta) (basics.StateDelta, error) {
	if msd == nil || len(*msd) == 0 {
		return nil, nil
	}
	bsd := make(basics.StateDelta, len(*msd))
	for _, kv := range *msd {
		key, err := base64.StdEncoding.DecodeString(kv.Key)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", kv.Key, err)
		}
		if _, ok := bsd[string(key)]; ok {
			return nil, fmt.Errorf("has duplicate key %#x", key)
		}
		vd := basics.ValueDelta{Action: basics.DeltaAction(kv.Value.Action)}
		if kv.Value.Bytes != nil {
			value, err := base64.StdEncoding.DecodeString(*kv.Value.Bytes)
			if err != nil {
				return nil, fmt.Errorf("value for key %#x: %w", key, err)
			}
			vd.Bytes = string(value)
		}
		if kv.Value.Uint != nil {
			vd.Uint = *kv.Value.Uint
		}
		bsd[string(key)] = vd
	}
	return bsd, nil
}

func convertAssetOverride(asset model.SimulateAssetOverride) (simulation.AssetOverride, error) {
	var override simulation.AssetOverride
	var err error
	if asset.Creator != nil {
		override.Creator, err = basics.UnmarshalChecksumAddress(*asset.Creator)
		if err != nil {
			return simulation.AssetOverride{}, fmt.Errorf("creator %q: %w", *asset.Creator, err)
		}
	}
	override.Total = asset.Total
	override.Decimals = asset.Decimals
	override.DefaultFrozen = asset.DefaultFrozen
	if override.UnitName, err = stringOrB64("unit-name", asset.UnitName, asset.UnitNameB64); err != nil {
		return simulation.AssetOverride{}, err
	}
	if override.AssetName, err = stringOrB64("name", asset.Name, asset.NameB64); err != nil {
		return simulation.AssetOverride{}, err
	}
	if override.URL, err = stringOrB64("url", asset.Url, asset.UrlB64); err != nil {
		return simulation.AssetOverride{}, err
	}
	if override.MetadataHash, err = fixedBytes[[32]byte]("metadata hash", asset.MetadataHash); err != nil {
		return simulation.AssetOverride{}, err
	}
	err = convertAddresses(
		optionalAddress{"manager", asset.Manager, &override.Manager},
		optionalAddress{"reserve", asset.Reserve, &override.Reserve},
		optionalAddress{"freeze", asset.Freeze, &override.Freeze},
		optionalAddress{"clawback", asset.Clawback, &override.Clawback},
	)
	if err != nil {
		return simulation.AssetOverride{}, err
	}
	return override, nil
}

// stringOrB64 returns the value of a field that may be given either as a string or as base64
// encoded bytes, but not both.
func stringOrB64(name string, str *string, b64 *[]byte) (*string, error) {
	if str != nil && b64 != nil {
		return nil, fmt.Errorf("%s and %s-b64 cannot both be set", name, name)
	}
	if b64 != nil {
		value := string(*b64)
		return &value, nil
	}
	return str, nil
}

func convertAppOverride(app model.SimulateAppOverride) (simulation.AppOverride, error) {
	var override simulation.AppOverride
	if app.Creator != nil {
		creator, err := basics.UnmarshalChecksumAddress(*app.Creator)
		if err != nil {
			return simulation.AppOverride{}, fmt.Errorf("creator %q: %w", *app.Creator, err)
		}
		override.Creator = creator
	}
	if app.ApprovalProgram != nil {
		// A nil program means the program is left unchanged, so keep empty programs non-nil
		override.ApprovalProgram = append([]byte{}, *app.ApprovalProgram...)
	}
	if app.ClearStateProgram != nil {
		override.ClearStateProgram = append([]byte{}, *app.ClearStateProgram...)
	}
	if app.GlobalStateSchema != nil {
		schema := convertStateSchema(*app.GlobalStateSchema)
		override.GlobalStateSchema = &schema
	}
	if app.LocalStateSchema != nil {
		schema := convertStateSchema(*app.LocalStateSchema)
		override.LocalStateSchema = &schema
	}
	override.ExtraProgramPages = app.ExtraProgramPages
	override.Version = app.Version
	if app.SizeSponsor != nil {
		sponsor, err := basics.UnmarshalChecksumAddress(*app.SizeSponsor)
		if err != nil {
			return simulation.AppOverride{}, fmt.Errorf("size-sponsor %q: %w", *app.SizeSponsor, err)
		}
		override.SizeSponsor = &sponsor
	}
	override.ForeignBoxReads = app.ForeignBoxReads
	override.FamilyBoxAccess = app.FamilyBoxAccess

	var err error
	if override.GlobalDelta, err = convertStateDelta(app.GlobalStateDelta); err != nil {
		return simulation.AppOverride{}, fmt.Errorf("global state delta %w", err)
	}
	if app.LocalStateDelta != nil && len(*app.LocalStateDelta) > 0 {
		override.LocalDeltas = make(map[basics.Address]basics.StateDelta, len(*app.LocalStateDelta))
		for _, local := range *app.LocalStateDelta {
			var addr basics.Address
			addr, err = basics.UnmarshalChecksumAddress(local.Address)
			if err != nil {
				return simulation.AppOverride{}, fmt.Errorf("local state delta address %q: %w", local.Address, err)
			}
			if _, ok := override.LocalDeltas[addr]; ok {
				return simulation.AppOverride{}, fmt.Errorf("local state delta has duplicate address %s", addr)
			}
			if override.LocalDeltas[addr], err = convertStateDelta(&local.Delta); err != nil {
				return simulation.AppOverride{}, fmt.Errorf("local state delta for %s %w", addr, err)
			}
		}
	}
	if override.BoxDelta, err = convertStateDelta(app.BoxDelta); err != nil {
		return simulation.AppOverride{}, fmt.Errorf("box delta %w", err)
	}

	return override, nil
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
