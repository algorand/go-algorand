// Copyright (C) 2019-2020 Algorand, Inc.
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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/cmd/tealdbg/cdt"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type cdtState struct {
	// immutable content
	disassembly string
	proto       *config.ConsensusParams
	txnGroup    []transactions.SignedTxn
	groupIndex  int
	globals     []basics.TealValue

	// mutable program state
	mu      deadlock.Mutex
	stack   []basics.TealValue
	scratch []basics.TealValue
	pc      atomicInt
	line    atomicInt
	err     atomicString
	appState

	// debugger states
	lastAction      atomicString
	pauseOnError    atomicBool
	pauseOnCompeted atomicBool
	completed       atomicBool
}

type cdtStateUpdate struct {
	stack   []basics.TealValue
	scratch []basics.TealValue
	pc      int
	line    int
	err     string

	appState
}

type typeHint int

const (
	noHint typeHint = iota
	addressHint
)

var txnFileTypeHints = map[logic.TxnField]typeHint{
	logic.Sender:              addressHint,
	logic.Receiver:            addressHint,
	logic.CloseRemainderTo:    addressHint,
	logic.AssetSender:         addressHint,
	logic.AssetReceiver:       addressHint,
	logic.AssetCloseTo:        addressHint,
	logic.Accounts:            addressHint,
	logic.RekeyTo:             addressHint,
	logic.ConfigAssetManager:  addressHint,
	logic.ConfigAssetReserve:  addressHint,
	logic.ConfigAssetFreeze:   addressHint,
	logic.ConfigAssetClawback: addressHint,
	logic.FreezeAssetAccount:  addressHint,
}

func (s *cdtState) Init(disassembly string, proto *config.ConsensusParams, txnGroup []transactions.SignedTxn, groupIndex int, globals []basics.TealValue) {
	s.disassembly = disassembly
	s.proto = proto
	s.txnGroup = txnGroup
	s.groupIndex = groupIndex
	s.globals = globals
}

func (s *cdtState) Update(state cdtStateUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pc.Store(state.pc)
	s.line.Store(state.line)
	s.err.Store(state.err)
	s.stack = state.stack
	s.scratch = state.scratch
	s.appState = state.appState
}

const localScopeObjID = "localScopeObjId"
const globalScopeObjID = "globalScopeObjID"
const globalsObjID = "globalsObjID"
const txnObjID = "txnObjID"
const gtxnObjID = "gtxnObjID"
const stackObjID = "stackObjID"
const scratchObjID = "scratchObjID"
const tealErrorID = "tealErrorID"
const appGlobalObjID = "appGlobalObjID"
const appLocalsObjID = "appLocalsObjID"
const txnArrayFieldObjID = "txnArrayField"

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
}

func (s *cdtState) getObjectDescriptor(objID string, preview bool) (desc []cdt.RuntimePropertyDescriptor, err error) {
	maker, ok := objectDescMap[objID]
	if !ok {
		if idx, ok := decodeGroupTxnID(objID); ok {
			if idx >= len(s.txnGroup) || idx < 0 {
				err = fmt.Errorf("invalid group idx: %d", idx)
				return
			}
			if len(s.txnGroup) > 0 {
				return makeTxnImpl(&s.txnGroup[idx].Txn, idx, preview), nil
			}
		} else if parentObjID, ok := decodeArrayLength(objID); ok {
			switch parentObjID {
			case stackObjID:
				return makeArrayLength(s.stack), nil
			case scratchObjID:
				return makeArrayLength(s.scratch), nil
			default:
			}
		} else if parentObjID, from, to, ok := decodeArraySlice(objID); ok {
			switch parentObjID {
			case stackObjID:
				return makeStackSlice(s, from, to, preview), nil
			case scratchObjID:
				return makeScratchSlice(s, from, to, preview), nil
			default:
			}
		} else if appID, ok := decodeAppGlobalAppID(objID); ok {
			return makeAppGlobalKV(s, appID), nil
		} else if addr, appID, ok := decodeAppLocalsAppID(objID); ok {
			return makeAppLocalsKV(s, addr, appID), nil
		} else if addr, ok := decodeAppLocalsAddr(objID); ok {
			return makeAppLocalState(s, addr), nil
		} else if idx, field, ok := decodeTxnArrayField(objID); ok {
			return makeTxnArrayField(s, idx, field), nil
		}
		// might be nested object in array, parse and call
		err = fmt.Errorf("unk object id: %s", objID)
		return
	}
	return maker(s, preview), nil
}

func convertCallArgs(argsRaw []interface{}) (args []cdt.RuntimeCallArgument) {
	for _, item := range argsRaw {
		argRaw := item.(map[string]interface{})
		value := argRaw["value"]
		args = append(args, cdt.RuntimeCallArgument{Value: value})
	}
	return
}

func (s *cdtState) packRanges(objID string, argsRaw []interface{}) (result cdt.RuntimeCallPackRangesObject) {
	if len(argsRaw) < 5 {
		return
	}

	args := convertCallArgs(argsRaw)
	fromIndex := int(args[0].Value.(float64))
	toIndex := int(args[1].Value.(float64))
	bucketThreshold := int(args[2].Value.(float64))
	// sparseIterationThreshold := args[3].Value.(float64)
	// getOwnPropertyNamesThreshold := args[4].Value.(float64)

	// based on JS code that CDT asks to execute
	count := toIndex - fromIndex + 1
	bucketSize := count
	if count > bucketThreshold {
		bucketSize = int(math.Pow(float64(bucketThreshold), math.Ceil(math.Log(float64(count))/math.Log(float64(bucketThreshold)))-1))
	}

	var ranges [][3]int

	count = 0
	groupStart := -1
	groupEnd := 0
	for i := fromIndex; i <= toIndex; i++ {
		if groupStart == -1 {
			groupStart = i
		}
		groupEnd = i
		count++
		if count == bucketSize {
			ranges = append(ranges, [3]int{groupStart, groupEnd, count})
			count = 0
			groupStart = -1
		}
	}
	if count > 0 {
		ranges = append(ranges, [3]int{groupStart, groupEnd, count})
	}

	result.Type = "object"
	result.Value = cdt.RuntimeCallPackRangesRange{
		Ranges: ranges,
	}

	return
}

func (s *cdtState) buildFragment(objID string, argsRaw []interface{}) cdt.RuntimeRemoteObject {
	var source []basics.TealValue
	switch objID {
	case stackObjID:
		source = s.stack
	case scratchObjID:
		source = s.scratch
	default:
		return cdt.RuntimeRemoteObject{}
	}

	// buildObjectFragment
	if len(argsRaw) < 3 {
		return cdt.RuntimeRemoteObject{
			Type:        "object",
			Subtype:     "array",
			ClassName:   "Array",
			Description: fmt.Sprintf("Array(%d)", len(source)),
			ObjectID:    encodeArrayLength(objID),
		}
	}

	// buildArrayFragment

	args := convertCallArgs(argsRaw)
	fromIndex := int(args[0].Value.(float64))
	toIndex := int(args[1].Value.(float64))
	// sparseIterationThreshold := args[2].Value.(float64)

	return cdt.RuntimeRemoteObject{
		Type:        "object",
		ClassName:   "Object",
		Description: "Object",
		ObjectID:    encodeArraySlice(objID, fromIndex, toIndex),
	}
}

func makeObject(name, id string) cdt.RuntimePropertyDescriptor {
	return cdt.RuntimePropertyDescriptor{
		Name:         name,
		Configurable: false,
		Writable:     false,
		Enumerable:   true,
		IsOwn:        true,
		Value: &cdt.RuntimeRemoteObject{
			Type:        "object",
			ClassName:   "Object",
			Description: "Object",
			ObjectID:    id,
		},
	}
}

func makeArray(name string, length int, id string) cdt.RuntimePropertyDescriptor {
	return cdt.RuntimePropertyDescriptor{
		Name:         name,
		Configurable: false,
		Writable:     false,
		Enumerable:   true,
		IsOwn:        true,
		Value: &cdt.RuntimeRemoteObject{
			Type:        "object",
			Subtype:     "array",
			ClassName:   "Array",
			Description: fmt.Sprintf("Array(%d)", length),
			ObjectID:    id,
		},
	}
}

func makePrimitive(field fieldDesc) cdt.RuntimePropertyDescriptor {
	return cdt.RuntimePropertyDescriptor{
		Name:         field.Name,
		Configurable: false,
		Writable:     false,
		Enumerable:   true,
		IsOwn:        true,
		Value: &cdt.RuntimeRemoteObject{
			Type:  field.Type,
			Value: field.Value,
		},
	}
}

func makeStringResult(value string) cdt.RuntimeRemoteObject {
	return cdt.RuntimeRemoteObject{
		Type:  "string",
		Value: value,
	}
}

// tealTypeMap maps TealType to JS type
var tealTypeMap = map[basics.TealType]string{
	basics.TealBytesType: "string",
	basics.TealUintType:  "number",
}

type fieldDesc struct {
	Name  string
	Value string
	Type  string
}

func prepareGlobals(globals []basics.TealValue) []fieldDesc {
	result := make([]fieldDesc, 0, len(logic.GlobalFieldNames))
	if len(globals) != len(logic.GlobalFieldNames) {
		desc := fieldDesc{
			"error",
			fmt.Sprintf("globals: invalid length %d != %d", len(globals), len(logic.GlobalFieldNames)),
			"undefined",
		}
		result = append(result, desc)
		return result
	}

	for fieldIdx, name := range logic.GlobalFieldNames {
		result = append(result, tealValueToFieldDesc(name, globals[fieldIdx]))
	}
	return result
}

func prepareTxn(txn *transactions.Transaction, groupIndex int) []fieldDesc {
	result := make([]fieldDesc, 0, len(logic.TxnFieldNames))
	for field, name := range logic.TxnFieldNames {
		if field == int(logic.FirstValidTime) ||
			field == int(logic.Accounts) ||
			field == int(logic.ApplicationArgs) {
			continue
		}
		var value string
		var valType string = "string"
		tv, err := logic.TxnFieldToTealValue(txn, groupIndex, logic.TxnField(field), 0)
		if err != nil {
			value = err.Error()
			valType = "undefined"
		} else {
			hint := txnFileTypeHints[logic.TxnField(field)]
			value = tealValueToString(&tv, hint)
			valType = tealTypeMap[tv.Type]
		}
		result = append(result, fieldDesc{name, value, valType})
	}
	return result
}

func tealValueToFieldDesc(name string, tv basics.TealValue) fieldDesc {
	var value string
	var valType string
	if tv.Type == basics.TealBytesType {
		valType = "string"
		data, err := base64.StdEncoding.DecodeString(tv.Bytes)
		if err != nil {
			value = tv.Bytes
		} else {
			printable := IsText(data)
			if printable {
				value = string(data)
			} else if len(data) < 8 {
				value = fmt.Sprintf("%q", data)
				if value[0] == '"' {
					value = value[1 : len(value)-1]
				}
			} else {
				value = hex.EncodeToString(data)
			}
		}
	} else {
		valType = "number"
		value = strconv.Itoa(int(tv.Uint))
	}
	return fieldDesc{name, value, valType}
}

func tealValueToString(tv *basics.TealValue, hint typeHint) string {
	if hint == addressHint {
		var a basics.Address
		copy(a[:], []byte(tv.Bytes))
		return a.String()
	}
	return tv.String()
}

func prepareArray(array []basics.TealValue) []fieldDesc {
	result := make([]fieldDesc, 0, len(logic.TxnFieldNames))
	for i := 0; i < len(array); i++ {
		tv := array[i]
		name := strconv.Itoa(i)
		result = append(result, tealValueToFieldDesc(name, tv))
	}
	return result
}

func makePreview(fields []fieldDesc) (prop []cdt.RuntimePropertyPreview) {
	for _, field := range fields {
		v := cdt.RuntimePropertyPreview{
			Name:  field.Name,
			Value: field.Value,
			Type:  field.Type,
		}
		prop = append(prop, v)
	}
	return
}

func makeIntPreview(n int) (prop []cdt.RuntimePropertyPreview) {
	for i := 0; i < n; i++ {
		v := cdt.RuntimePropertyPreview{
			Name:  strconv.Itoa(i),
			Value: "Object",
			Type:  "object",
		}
		prop = append(prop, v)
	}
	return
}

func makeTxnPreview(txnGroup []transactions.SignedTxn, groupIndex int) cdt.RuntimeObjectPreview {
	var prop []cdt.RuntimePropertyPreview
	if len(txnGroup) > 0 {
		fields := prepareTxn(&txnGroup[groupIndex].Txn, groupIndex)
		prop = makePreview(fields)
	}

	p := cdt.RuntimeObjectPreview{Type: "object", Overflow: true, Properties: prop}
	return p
}

func makeGtxnPreview(txnGroup []transactions.SignedTxn) cdt.RuntimeObjectPreview {
	prop := makeIntPreview(len(txnGroup))
	p := cdt.RuntimeObjectPreview{
		Type:        "object",
		Subtype:     "array",
		Description: fmt.Sprintf("Array(%d)", len(txnGroup)),
		Overflow:    false,
		Properties:  prop}
	return p
}

const maxArrayPreviewLength = 20

func makeArrayPreview(array []basics.TealValue) cdt.RuntimeObjectPreview {
	fields := prepareArray(array)

	length := len(fields)
	if length > maxArrayPreviewLength {
		length = maxArrayPreviewLength
	}
	prop := makePreview(fields[:length])

	p := cdt.RuntimeObjectPreview{
		Type:        "object",
		Subtype:     "array",
		Description: fmt.Sprintf("Array(%d)", len(array)),
		Overflow:    true,
		Properties:  prop}
	return p
}

func makeGlobalsPreview(globals []basics.TealValue) cdt.RuntimeObjectPreview {
	fields := prepareGlobals(globals)
	prop := makePreview(fields)

	p := cdt.RuntimeObjectPreview{
		Type:        "object",
		Description: "Object",
		Overflow:    true,
		Properties:  prop}
	return p
}

var gtxnObjIDPrefix = fmt.Sprintf("%s_gid_", gtxnObjID)

func encodeGroupTxnID(groupIndex int) string {
	return gtxnObjIDPrefix + strconv.Itoa(groupIndex)
}

func decodeGroupTxnID(objID string) (int, bool) {
	if strings.HasPrefix(objID, gtxnObjIDPrefix) {
		if val, err := strconv.ParseInt(objID[len(gtxnObjIDPrefix):], 10, 32); err == nil {
			return int(val), true
		}
	}
	return 0, false
}

func encodeArrayLength(objID string) string {
	return fmt.Sprintf("%s_length", objID)
}

func decodeArrayLength(objID string) (string, bool) {
	if strings.HasSuffix(objID, "_length") {
		if strings.HasPrefix(objID, stackObjID) {
			return stackObjID, true
		} else if strings.HasPrefix(objID, scratchObjID) {
			return scratchObjID, true
		}
	}
	return "", false
}

func encodeArraySlice(objID string, fromIndex int, toIndex int) string {
	return fmt.Sprintf("%s_%d_%d", objID, fromIndex, toIndex)
}

func decodeArraySlice(objID string) (string, int, int, bool) {
	if strings.HasPrefix(objID, stackObjID) || strings.HasPrefix(objID, scratchObjID) {
		parts := strings.Split(objID, "_")
		if len(parts) != 3 {
			return "", 0, 0, false
		}
		var err error
		var fromIndex, toIndex int64
		if fromIndex, err = strconv.ParseInt(parts[1], 10, 32); err != nil {
			return "", 0, 0, false
		}
		if toIndex, err = strconv.ParseInt(parts[2], 10, 32); err != nil {
			return "", 0, 0, false
		}
		return parts[0], int(fromIndex), int(toIndex), true
	}
	return "", 0, 0, false
}

var appGlobalObjIDPrefix = fmt.Sprintf("%s_", appGlobalObjID)

func encodeAppGlobalAppID(key string) string {
	return appGlobalObjIDPrefix + key
}

func decodeAppGlobalAppID(objID string) (uint64, bool) {
	if strings.HasPrefix(objID, appGlobalObjIDPrefix) {
		if val, err := strconv.ParseInt(objID[len(appGlobalObjIDPrefix):], 10, 32); err == nil {
			return uint64(val), true
		}
	}
	return 0, false
}

var appLocalsObjIDPrefix = fmt.Sprintf("%s_", appLocalsObjID)

func encodeAppLocalsAddr(addr string) string {
	return appLocalsObjIDPrefix + addr
}

func decodeAppLocalsAddr(objID string) (string, bool) {
	if strings.HasPrefix(objID, appLocalsObjIDPrefix) {
		return objID[len(appLocalsObjIDPrefix):], true
	}
	return "", false
}

var appLocalAppIDPrefix = fmt.Sprintf("%s__", appLocalsObjID)

func encodeAppLocalsAppID(addr string, appID string) string {
	return fmt.Sprintf("%s%s_%s", appLocalAppIDPrefix, addr, appID)
}

func decodeAppLocalsAppID(objID string) (string, uint64, bool) {
	if strings.HasPrefix(objID, appLocalAppIDPrefix) {
		encoded := objID[len(appLocalAppIDPrefix):]
		parts := strings.Split(encoded, "_")
		if val, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
			return parts[0], uint64(val), true
		}
	}
	return "", 0, false
}

var txnArrayFieldPrefix = fmt.Sprintf("%s__", txnArrayFieldObjID)

func encodeTxnArrayField(groupIndex int, field int) string {
	return fmt.Sprintf("%s%d_%d", txnArrayFieldPrefix, groupIndex, field)
}

func decodeTxnArrayField(objID string) (int, int, bool) {
	if strings.HasPrefix(objID, txnArrayFieldPrefix) {
		encoded := objID[len(txnArrayFieldPrefix):]
		parts := strings.Split(encoded, "_")
		var groupIndex, fieldIndex int64
		var err error
		if groupIndex, err = strconv.ParseInt(parts[0], 10, 32); err != nil {
			return 0, 0, false
		}
		if fieldIndex, err = strconv.ParseInt(parts[1], 10, 32); err != nil {
			return 0, 0, false
		}
		return int(groupIndex), int(fieldIndex), true
	}
	return 0, 0, false
}

func makeGlobalScope(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	globals := makeObject("globals", globalsObjID)
	if preview {
		globalsPreview := makeGlobalsPreview(s.globals)
		globals.Value.Preview = &globalsPreview
	}

	desc = []cdt.RuntimePropertyDescriptor{
		globals,
	}
	return desc
}

func makeLocalScope(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	txn := makeObject("txn", txnObjID)
	gtxn := makeArray("gtxn", len(s.txnGroup), gtxnObjID)
	stack := makeArray("stack", len(s.stack), stackObjID)
	scratch := makeArray("scratch", len(s.scratch), scratchObjID)
	if preview {
		txnPreview := makeTxnPreview(s.txnGroup, s.groupIndex)
		if len(txnPreview.Properties) > 0 {
			txn.Value.Preview = &txnPreview
		}
		gtxnPreview := makeGtxnPreview(s.txnGroup)
		if len(gtxnPreview.Properties) > 0 {
			gtxn.Value.Preview = &gtxnPreview
		}
		stackPreview := makeArrayPreview(s.stack)
		if len(stackPreview.Properties) > 0 {
			stack.Value.Preview = &stackPreview
		}
		scratchPreview := makeArrayPreview(s.scratch)
		if len(scratchPreview.Properties) > 0 {
			scratch.Value.Preview = &scratchPreview
		}
	}

	pc := makePrimitive(fieldDesc{
		Name:  "PC",
		Value: strconv.Itoa(s.pc.Load()),
		Type:  "number",
	})
	desc = []cdt.RuntimePropertyDescriptor{
		pc,
		txn,
		gtxn,
		stack,
		scratch,
	}

	if !s.appState.empty() {
		var global, local cdt.RuntimePropertyDescriptor
		if len(s.appState.global) > 0 {
			global = makeObject("appGlobal", appGlobalObjID)
			desc = append(desc, global)
		}
		if len(s.appState.locals) > 0 {
			local = makeObject("appLocals", appLocalsObjID)
			desc = append(desc, local)
		}
	}

	return desc
}

func makeGlobals(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	fields := prepareGlobals(s.globals)
	for _, field := range fields {
		desc = append(desc, makePrimitive(field))
	}
	return
}

func makeTxn(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	if len(s.txnGroup) > 0 && s.groupIndex < len(s.txnGroup) && s.groupIndex >= 0 {
		return makeTxnImpl(&s.txnGroup[s.groupIndex].Txn, s.groupIndex, preview)
	}
	return
}

func makeTxnImpl(txn *transactions.Transaction, groupIndex int, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	fields := prepareTxn(txn, groupIndex)
	for _, field := range fields {
		desc = append(desc, makePrimitive(field))
	}

	for _, fieldIdx := range []logic.TxnField{logic.ApplicationArgs, logic.Accounts} {
		fieldID := encodeTxnArrayField(groupIndex, int(fieldIdx))
		var length int
		switch logic.TxnField(fieldIdx) {
		case logic.Accounts:
			length = len(txn.Accounts)
		case logic.ApplicationArgs:
			length = len(txn.ApplicationArgs)
		}
		field := makeArray(logic.TxnFieldNames[fieldIdx], length, fieldID)
		if preview {
			elems := txnFieldToArrayFieldDesc(txn, groupIndex, logic.TxnField(fieldIdx), length)
			prop := makePreview(elems)
			p := cdt.RuntimeObjectPreview{
				Type:        "object",
				Subtype:     "array",
				Description: fmt.Sprintf("Array(%d)", length),
				Overflow:    true,
				Properties:  prop,
			}
			field.Value.Preview = &p
		}
		desc = append(desc, field)
	}

	return
}

func txnFieldToArrayFieldDesc(txn *transactions.Transaction, groupIndex int, field logic.TxnField, length int) (desc []fieldDesc) {
	for i := 0; i < length; i++ {
		tv, err := logic.TxnFieldToTealValue(txn, groupIndex, field, uint64(i))
		if err != nil {
			return []fieldDesc{}
		}
		name := strconv.Itoa(i)
		hint := txnFileTypeHints[field]
		value := tealValueToString(&tv, hint)
		valType := tealTypeMap[tv.Type]
		desc = append(desc, fieldDesc{name, value, valType})
	}
	return
}

func makeTxnArrayField(s *cdtState, groupIndex int, fieldIdx int) (desc []cdt.RuntimePropertyDescriptor) {
	if len(s.txnGroup) > 0 && s.groupIndex < len(s.txnGroup) && s.groupIndex >= 0 && fieldIdx >= 0 && fieldIdx < len(logic.TxnFieldNames) {
		txn := s.txnGroup[groupIndex].Txn
		var length int
		switch logic.TxnField(fieldIdx) {
		case logic.Accounts:
			length = len(txn.Accounts)
		case logic.ApplicationArgs:
			length = len(txn.ApplicationArgs)
		}

		elems := txnFieldToArrayFieldDesc(&txn, groupIndex, logic.TxnField(fieldIdx), length)
		for _, elem := range elems {
			desc = append(desc, makePrimitive(elem))
		}

		desc = append(desc, makePrimitive(fieldDesc{Name: "length", Value: strconv.Itoa(length), Type: "number"}))
	}
	return
}

func makeTxnGroup(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	if len(s.txnGroup) > 0 {
		for i := 0; i < len(s.txnGroup); i++ {
			item := makeObject(strconv.Itoa(i), encodeGroupTxnID(i))
			if preview {
				txnPreview := makeTxnPreview(s.txnGroup, i)
				item.Value.Preview = &txnPreview
			}
			desc = append(desc, item)
		}
	}
	return
}

func makeAppGlobalState(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	for key := range s.appState.global {
		s := strconv.Itoa(int(key))
		item := makeObject(s, encodeAppGlobalAppID(s))
		desc = append(desc, item)
	}
	return
}

func makeAppLocalsState(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	for addr := range s.appState.locals {
		a := addr.String()
		item := makeObject(a, encodeAppLocalsAddr(a))
		desc = append(desc, item)
	}
	return
}

func makeAppLocalState(s *cdtState, addr string) (desc []cdt.RuntimePropertyDescriptor) {
	a, err := basics.UnmarshalChecksumAddress(addr)
	if err != nil {
		return
	}

	if state, ok := s.appState.locals[a]; ok {
		for key := range state {
			s := strconv.Itoa(int(key))
			item := makeObject(s, encodeAppLocalsAppID(addr, s))
			desc = append(desc, item)
		}
	}
	return
}

func makeAppGlobalKV(s *cdtState, appID uint64) (desc []cdt.RuntimePropertyDescriptor) {
	if tkv, ok := s.appState.global[basics.AppIndex(appID)]; ok {
		return tkvToRpd(tkv)
	}
	return
}

func makeAppLocalsKV(s *cdtState, addr string, appID uint64) (desc []cdt.RuntimePropertyDescriptor) {
	a, err := basics.UnmarshalChecksumAddress(addr)
	if err != nil {
		return
	}

	state, ok := s.appState.locals[a]
	if !ok {
		return
	}

	if tkv, ok := state[basics.AppIndex(appID)]; ok {
		return tkvToRpd(tkv)
	}
	return
}

func tkvToRpd(tkv basics.TealKeyValue) (desc []cdt.RuntimePropertyDescriptor) {
	for key, value := range tkv {
		field := tealValueToFieldDesc(key, basics.TealValue{Type: value.Type, Uint: value.Uint, Bytes: value.Bytes})
		desc = append(desc, makePrimitive(field))
	}
	return
}

func makeArrayLength(array []basics.TealValue) (desc []cdt.RuntimePropertyDescriptor) {
	field := fieldDesc{Name: "length", Value: strconv.Itoa(len(array)), Type: "number"}
	desc = append(desc, makePrimitive(field))
	return
}

func makeStackSlice(s *cdtState, from int, to int, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	// temporary disable stack reversion to see if people prefer appending to the list
	// stack := make([]v2.TealValue, len(s.stack))
	// for i := 0; i < len(stack); i++ {
	// 	stack[i] = s.stack[len(s.stack)-1-i]
	// }

	stack := s.stack[from : to+1]
	fields := prepareArray(stack)
	for _, field := range fields {
		desc = append(desc, makePrimitive(field))
	}
	field := fieldDesc{Name: "length", Value: strconv.Itoa(len(s.stack)), Type: "number"}
	desc = append(desc, makePrimitive(field))
	return
}

func makeStack(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	return makeStackSlice(s, 0, len(s.stack)-1, preview)
}

func makeScratchSlice(s *cdtState, from int, to int, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	scratch := s.scratch[from : to+1]
	fields := prepareArray(scratch)
	for _, field := range fields {
		desc = append(desc, makePrimitive(field))
	}
	field := fieldDesc{Name: "length", Value: strconv.Itoa(len(scratch)), Type: "number"}
	desc = append(desc, makePrimitive(field))
	return
}

func makeScratch(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	return makeScratchSlice(s, 0, len(s.scratch)-1, preview)
}

func makeTealError(s *cdtState, preview bool) (desc []cdt.RuntimePropertyDescriptor) {
	if lastError := s.err.Load(); len(lastError) != 0 {
		field := fieldDesc{Name: "message", Value: lastError, Type: "string"}
		desc = append(desc, makePrimitive(field))
	}
	return
}
