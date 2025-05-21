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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func unB64(x string) []byte {
	out, err := base64.StdEncoding.DecodeString(x)
	if err != nil {
		panic(err)
	}
	return out
}

func tvStr(tv model.TealValue) string {
	if tv.Type == uint64(basics.TealBytesType) {
		return tv.Bytes
	} else if tv.Type == uint64(basics.TealUintType) {
		return strconv.FormatUint(tv.Uint, 10)
	}
	return "UNKNOWN TEAL VALUE"
}

func dbStack(stack []model.TealValue) string {
	parts := make([]string, len(stack))
	for i, sv := range stack {
		parts[i] = tvStr(sv)
	}
	return strings.Join(parts, " ")
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func logTrace(t *testing.T, lines []string, trace []model.DryrunState) {
	var disasm string
	for _, ds := range trace {
		var line string
		if len(lines) > 0 {
			disasm = strings.Join(lines, "\n")
			t.Log(disasm)
			line = lines[ds.Line]
		} else {
			line = ""
		}
		t.Logf("\tstack=[%s]", dbStack(ds.Stack))
		t.Logf("%s\t// line=%d pc=%d", line, ds.Line, ds.Pc)
	}
}

func logStateDelta(t *testing.T, sd model.StateDelta) {
	for _, vd := range sd {
		t.Logf("\t%s: %#v", vd.Key, vd)
	}
}

func logResponse(t *testing.T, response *model.DryrunResponse) {
	t.Log(response.Error)
	for i, rt := range response.Txns {
		t.Logf("txn[%d]", i)
		if rt.LogicSigTrace != nil && len(*rt.LogicSigTrace) > 0 {
			t.Log("Logic Sig:")
			logTrace(t, rt.Disassembly, *rt.LogicSigTrace)
			if rt.LogicSigMessages != nil && len(*rt.LogicSigMessages) > 0 {
				t.Log("Messages:")
				for _, m := range *rt.LogicSigMessages {
					t.Log(m)
				}
			}
		}
		if rt.AppCallTrace != nil && len(*rt.AppCallTrace) > 0 {
			t.Log("App Call:")
			logTrace(t, rt.Disassembly, *rt.AppCallTrace)
			if rt.AppCallMessages != nil && len(*rt.AppCallMessages) > 0 {
				t.Log("Messages:")
				for _, m := range *rt.AppCallMessages {
					t.Log(m)
				}
			}
		}
		if rt.GlobalDelta != nil && len(*rt.GlobalDelta) > 0 {
			t.Log("Global delta")
			logStateDelta(t, *rt.GlobalDelta)
		}
		if rt.LocalDeltas != nil {
			for _, ld := range *rt.LocalDeltas {
				addr := ld.Address
				delta := ld.Delta
				t.Logf("%s delta", addr)
				logStateDelta(t, delta)
			}
		}
	}
}

var dryrunProtoVersion protocol.ConsensusVersion = protocol.ConsensusFuture
var dryrunMakeLedgerProto protocol.ConsensusVersion = "dryrunMakeLedgerProto"

func TestDryrunSources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	goodSource := model.DryrunSource{
		AppIndex:  1007,
		FieldName: "approv",
		Source: `#pragma version 10
int 1`,
	}
	badSource := model.DryrunSource{
		AppIndex:  1007,
		FieldName: "approv",
		Source: `#pragma version 10
int 1
pop
fake_opcode
int not_an_int`,
	}

	dr := DryrunRequest{
		Sources: []model.DryrunSource{
			goodSource,
		},
		Apps: []model.Application{
			{
				Id: 1007,
			},
		},
	}
	var response model.DryrunResponse

	doDryrunRequest(&dr, &response)
	require.Empty(t, response.Error)

	dr.Sources[0] = badSource
	doDryrunRequest(&dr, &response)
	require.Contains(t, response.Error, "dryrun Source[0]: 2 errors")
	require.Contains(t, response.Error, "4: unknown opcode: fake_opcode")
	require.Contains(t, response.Error, "5:4: unable to parse \"not_an_int\" as integer")
}

func TestDryrunLogicSig(t *testing.T) {
	partitiontest.PartitionTest(t)
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{
		{
			Lsig: transactions.LogicSig{
				Logic: unB64("AiABASI="),
			},
		},
		// it doesn't actually care about any txn content
	}
	doDryrunRequest(&dr, &response)
	checkLogicSigPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLogicSigSource(t *testing.T) {
	partitiontest.PartitionTest(t)
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{{}}
	dr.Sources = []model.DryrunSource{
		{
			Source:    "int 1",
			FieldName: "lsig",
			TxnIndex:  0,
		},
	}
	doDryrunRequest(&dr, &response)
	checkLogicSigPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

const globalTestSource = `#pragma version 2
// This program approves all transactions whose first arg is "hello"
// Then, accounts can write "foo": "bar" to the GlobalState by
// sending a transaction whose first argument is "write". Finally,
// accounts can send the args ["check", xyz] to confirm that the
// key at "foo" is equal to the second argument, xyz

// If arg 0 is "hello"
txna ApplicationArgs 0
byte base64 aGVsbG8=
==
bnz succeed

// else

// If arg 0 is "write"
txna ApplicationArgs 0
byte base64 d3JpdGU=
==
bnz write

// else

// arg 0 must be "check"
txna ApplicationArgs 0
byte base64 Y2hlY2s=
==

// and arg 1 must be the value at "foo"
// Key "foo"
int 0
byte base64 Zm9v
app_global_get_ex

// Value must exist
int 0
==
bnz fail

// Value must equal arg
txna ApplicationArgs 1
==
&&

int 1
bnz done

write:
// Write to GlobalState

// Key "foo"
byte base64 Zm9v

// Value "bar"
byte base64 YmFy
app_global_put

int 1
bnz succeed

succeed:
int 1
int 1
bnz done

fail:
int 0

done:
`

var globalTestProgram []byte

const localStateCheckSource = `#pragma version 2
// This program approves all transactions whose first arg is "hello"
// Then, accounts can write "foo": "bar" to their LocalState by
// sending a transaction whose first argument is "write". Finally,
// accounts can send the args ["check", xyz] to confirm that the
// key at "foo" is equal to the second argument, xyz

// If arg 0 is "hello"
txna ApplicationArgs 0
byte base64 aGVsbG8=
==
bnz succeed

// else

// If arg 0 is "write"
txna ApplicationArgs 0
byte base64 d3JpdGU=
==
bnz write

// else

// arg 0 must be "check"
txna ApplicationArgs 0
byte base64 Y2hlY2s=
==

// and arg 1 must be the value at "foo"
// txn.Sender
int 0

// App ID (this app)
int 0

// Key "foo"
byte base64 Zm9v
app_local_get_ex

// Value must exist
int 0
==
bnz fail

// Value must equal arg
txna ApplicationArgs 1
==
&&

int 1
bnz done

write:
// Write to our LocalState

// txn.Sender
int 0

// Key "foo"
byte base64 Zm9v

// Value "bar"
byte base64 YmFy
app_local_put

int 1
bnz succeed

succeed:
int 1
int 1
bnz done

fail:
int 0
int 1
bnz done

done:
`

var localStateCheckProg []byte

func init() {
	ops, err := logic.AssembleString(globalTestSource)
	if err != nil {
		panic(err)
	}
	globalTestProgram = ops.Program
	ops, err = logic.AssembleString(localStateCheckSource)
	if err != nil {
		panic(err)
	}
	localStateCheckProg = ops.Program

	// legder requires proto string and proto params set
	var proto config.ConsensusParams
	proto.LogicSigVersion = 5
	proto.LogicSigMaxCost = 20000
	proto.MaxAppProgramCost = 700
	proto.MaxAppKeyLen = 64
	proto.MaxAppBytesValueLen = 64
	proto.MaxAppSumKeyValueLens = 128

	config.Consensus[dryrunMakeLedgerProto] = proto
}

func checkLogicSigPass(t *testing.T, response *model.DryrunResponse) {
	t.Helper()
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if len(response.Txns) == 0 {
		t.Error("response txns is nil")
	} else if response.Txns[0].LogicSigMessages == nil || len(*response.Txns[0].LogicSigMessages) < 1 {
		t.Error("no response lsig msg")
	} else {
		messages := *response.Txns[0].LogicSigMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
}

func checkAppCallResponse(t *testing.T, response *model.DryrunResponse, msg string) {
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if len(response.Txns) == 0 {
		t.Error("response txns is nil")
	} else if response.Txns[0].AppCallMessages == nil || len(*response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response app msg")
	} else {
		assert.NotNil(t, response.Txns[0].AppCallMessages)
		for idx := range response.Txns {
			if response.Txns[idx].AppCallMessages != nil {
				messages := *response.Txns[idx].AppCallMessages
				assert.GreaterOrEqual(t, len(messages), 1)
				assert.Contains(t, messages[len(messages)-1], msg)
			}
		}
	}
}

func checkAppCallPass(t *testing.T, response *model.DryrunResponse) {
	checkAppCallResponse(t, response, "PASS")
}

func checkAppCallReject(t *testing.T, response *model.DryrunResponse) {
	checkAppCallResponse(t, response, "REJECT")
}

type expectedSlotType struct {
	slot int
	tt   basics.TealType
}

func checkAppCallScratchType(t *testing.T, response *model.DryrunResponse, txnIdx int, expected []expectedSlotType) {
	txn := response.Txns[txnIdx]
	// We should have a trace
	assert.NotNil(t, txn.AppCallTrace)
	// The first stack entry should be nil since we haven't stored anything in scratch yet
	assert.Nil(t, (*txn.AppCallTrace)[0].Scratch)
	// Last one should be not nil, we should have some number of scratch vars
	traceLine := (*txn.AppCallTrace)[len(*txn.AppCallTrace)-1]
	assert.NotNil(t, traceLine.Scratch)
	for _, exp := range expected {
		// The TealType at the given slot index should match what we expect
		assert.Equal(t, exp.tt, basics.TealType((*traceLine.Scratch)[exp.slot].Type))
	}
}

func TestDryrunGlobal1(t *testing.T) {
	partitiontest.PartitionTest(t)
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 1,
					ApplicationArgs: [][]byte{
						[]byte("write"),
					},
				},
			},
		},
	}
	gkv := model.TealKeyValueStore{
		model.TealKeyValue{
			Key:   b64("foo"),
			Value: model.TealValue{Type: uint64(basics.TealBytesType), Bytes: b64("bar")},
		},
	}
	dr.Apps = []model.Application{
		{
			Id: 1,
			Params: model.ApplicationParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     &gkv,
				GlobalStateSchema: &model.ApplicationStateSchema{
					NumByteSlice: 10,
					NumUint:      10,
				},
			},
		},
	}
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunGlobal2(t *testing.T) {
	partitiontest.PartitionTest(t)
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 1234,
					ApplicationArgs: [][]byte{
						[]byte("check"),
						[]byte("bar"),
					},
				},
			},
		},
	}
	gkv := model.TealKeyValueStore{
		model.TealKeyValue{
			Key:   b64("foo"),
			Value: model.TealValue{Type: uint64(basics.TealBytesType), Bytes: b64("bar")},
		},
	}
	dr.Apps = []model.Application{
		{
			Id: 1234,
			Params: model.ApplicationParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     &gkv,
			},
		},
	}
	doDryrunRequest(&dr, &response)
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if response.Txns[0].AppCallMessages == nil || len(*response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response lsig msg")
	} else {
		messages := *response.Txns[0].AppCallMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocal1(t *testing.T) {
	partitiontest.PartitionTest(t)
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 1,
					ApplicationArgs: [][]byte{
						[]byte("write"),
						[]byte("foo"),
					},
				},
			},
		},
	}
	dr.Apps = []model.Application{
		{
			Id: 1,
			Params: model.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
				LocalStateSchema: &model.ApplicationStateSchema{
					NumByteSlice: 10,
					NumUint:      10,
				},
			},
		},
	}
	dr.Accounts = []model.Account{
		{
			Status:         "Online",
			Address:        basics.Address{}.String(),
			AppsLocalState: &[]model.ApplicationLocalState{{Id: 1}},
		},
	}
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if response.Txns[0].LocalDeltas == nil {
		t.Fatal("empty local delta")
	}

	// Should be a single account
	assert.Len(t, *response.Txns[0].LocalDeltas, 1)

	lds := (*response.Txns[0].LocalDeltas)[0]
	assert.Equal(t, lds.Address, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	valueFound := false
	for _, ld := range lds.Delta {
		if ld.Key == b64("foo") {
			valueFound = true
			assert.Equal(t, ld.Value.Action, uint64(basics.SetBytesAction))
			assert.Equal(t, *ld.Value.Bytes, b64("bar"))

		}
	}

	if !valueFound {
		t.Error("no local delta for value foo")
	}

	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocal1A(t *testing.T) {
	partitiontest.PartitionTest(t)
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 1,
					ApplicationArgs: [][]byte{
						[]byte("write"),
						[]byte("foo"),
					},
				},
			},
		},
	}
	dr.Apps = []model.Application{
		{
			Id: 1,
			Params: model.ApplicationParams{
				LocalStateSchema: &model.ApplicationStateSchema{
					NumByteSlice: 10,
					NumUint:      10,
				},
			},
		},
	}
	dr.Accounts = []model.Account{
		{
			Status:         "Online",
			Address:        basics.Address{}.String(),
			AppsLocalState: &[]model.ApplicationLocalState{{Id: 1}},
		},
	}

	dr.Sources = []model.DryrunSource{
		{
			Source:    localStateCheckSource,
			FieldName: "approv",
			AppIndex:  1,
		},
	}
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if response.Txns[0].LocalDeltas == nil {
		t.Fatal("empty local delta")
	}

	assert.Len(t, *response.Txns[0].LocalDeltas, 1)

	lds := (*response.Txns[0].LocalDeltas)[0]
	assert.Equal(t, lds.Address, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	valueFound := false
	for _, ld := range lds.Delta {
		if ld.Key == b64("foo") {
			valueFound = true
			assert.Equal(t, ld.Value.Action, uint64(basics.SetBytesAction))
			assert.Equal(t, *ld.Value.Bytes, b64("bar"))

		}
	}

	if !valueFound {
		t.Error("no local delta for value foo")
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocalCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()
	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 1234,
					ApplicationArgs: [][]byte{
						[]byte("check"),
						[]byte("bar"),
					},
				},
			},
		},
	}
	dr.Apps = []model.Application{
		{
			Id: 1234,
			Params: model.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	localv := make(model.TealKeyValueStore, 1234)
	localv[0] = model.TealKeyValue{
		Key: b64("foo"),
		Value: model.TealValue{
			Type:  uint64(basics.TealBytesType),
			Bytes: b64("bar"),
		},
	}

	dr.Accounts = []model.Account{
		{
			Status:  "Online",
			Address: basics.Address{}.String(),
			AppsLocalState: &[]model.ApplicationLocalState{{
				Id:       1234,
				KeyValue: &localv,
			}},
		},
	}

	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
}

func TestDryrunMultipleTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	txn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: 1,
				ApplicationArgs: [][]byte{
					[]byte("write"),
				},
			},
		},
	}

	dr.Txns = []transactions.SignedTxn{txn, txn}
	gkv := model.TealKeyValueStore{
		model.TealKeyValue{
			Key:   b64("foo"),
			Value: model.TealValue{Type: uint64(basics.TealBytesType), Bytes: b64("bar")},
		},
	}
	dr.Apps = []model.Application{
		{
			Id: 1,
			Params: model.ApplicationParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     &gkv,
				GlobalStateSchema: &model.ApplicationStateSchema{
					NumByteSlice: 10,
					NumUint:      10,
				},
			},
		},
	}
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var gdr model.DryrunRequest
	txns := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:   1,
					ApprovalProgram: []byte{1, 2, 3},
					ApplicationArgs: [][]byte{
						[]byte("check"),
						[]byte("bar"),
					},
				},
			},
		},
	}
	for i := range txns {
		enc := protocol.EncodeJSON(&txns[i])
		gdr.Txns = append(gdr.Txns, enc)
	}

	gdr.Apps = []model.Application{
		{
			Id: 1,
			Params: model.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	localv := make(model.TealKeyValueStore, 1)
	localv[0] = model.TealKeyValue{
		Key:   b64("foo"),
		Value: model.TealValue{Type: uint64(basics.TealBytesType), Bytes: b64("bar")},
	}

	gdr.Accounts = []model.Account{
		{
			Status:  "Online",
			Address: basics.Address{}.String(),
			AppsLocalState: &[]model.ApplicationLocalState{{
				Id:       1,
				KeyValue: &localv,
			}},
		},
	}

	// use protocol
	encoded := protocol.EncodeJSON(&gdr)
	var decoded model.DryrunRequest
	err := protocol.DecodeJSON(encoded, &decoded)
	require.NoError(t, err)
	require.Equal(t, gdr, decoded)

	buf := bytes.NewBuffer(encoded)
	dec := protocol.NewJSONDecoder(buf)
	decoded = model.DryrunRequest{}
	err = dec.Decode(&decoded)
	require.NoError(t, err)
	require.Equal(t, gdr, decoded)

	// use json
	data, err := json.Marshal(&gdr)
	require.NoError(t, err)
	gdr = model.DryrunRequest{}
	err = json.Unmarshal(data, &gdr)
	require.NoError(t, err)

	dr, err := DryrunRequestFromGenerated(&gdr)
	require.NoError(t, err)
	require.Equal(t, 1, len(dr.Txns))
	require.Equal(t, txns[0].Txn.ApplicationID, dr.Txns[0].Txn.ApplicationID)
	require.Equal(t, txns[0].Txn.ApprovalProgram, dr.Txns[0].Txn.ApprovalProgram)
	require.Equal(t, []byte{1, 2, 3}, dr.Txns[0].Txn.ApprovalProgram)
	require.Equal(t, txns[0].Txn.ApplicationArgs, dr.Txns[0].Txn.ApplicationArgs)

	// use protocol msgp
	dr1, err := DryrunRequestFromGenerated(&gdr)
	require.NoError(t, err)
	encoded, err = encode(protocol.CodecHandle, &dr)
	require.NoError(t, err)
	encoded2 := protocol.EncodeReflect(&dr)
	require.Equal(t, encoded, encoded2)

	buf = bytes.NewBuffer(encoded)
	dec = protocol.NewDecoder(buf)
	var dr2 DryrunRequest
	err = dec.Decode(&dr2)
	require.NoError(t, err)
	require.Equal(t, dr1, dr2)

	dr2 = DryrunRequest{}
	err = decode(protocol.CodecHandle, encoded, &dr2)
	require.NoError(t, err)
	require.Equal(t, dr1, dr2)

	dr2 = DryrunRequest{}
	err = protocol.DecodeReflect(encoded, &dr2)
	require.NoError(t, err)
	require.Equal(t, dr1, dr2)
}

func TestDryrunMakeLedger(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000
	proto.MaxAppKeyLen = 64
	proto.MaxAppBytesValueLen = 64

	sender, err := basics.UnmarshalChecksumAddress("UAPJE355K7BG7RQVMTZOW7QW4ICZJEIC3RZGYG5LSHZ65K6LCNFPJDSR7M")
	require.NoError(t, err)

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Header: transactions.Header{Sender: sender},
				Type:   protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 0,
					ApplicationArgs: [][]byte{
						[]byte("check"),
						[]byte("bar"),
					},
				},
			},
		},
	}
	dr.Apps = []model.Application{
		{
			Id: 1,
			Params: model.ApplicationParams{
				Creator:         sender.String(),
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	dl := dryrunLedger{dr: &dr}
	err = dl.init()
	require.NoError(t, err)
	_, err = makeBalancesAdapter(&dl, &dr.Txns[0].Txn, 1)
	require.NoError(t, err)
}

var dataJSON = []byte(`{
	"accounts": [
	  {
		"address": "UAPJE355K7BG7RQVMTZOW7QW4ICZJEIC3RZGYG5LSHZ65K6LCNFPJDSR7M",
		"amount": 5002280000000000,
		"amount-without-pending-rewards": 5000000000000000,
		"participation": {
		  "selection-participation-key": "tVDPagKEH1ch9q0jWwPdBIe13k2EbOw+0UTrfpKLqlU=",
		  "vote-first-valid": 0,
		  "vote-key-dilution": 10000,
		  "vote-last-valid": 3000000,
		  "vote-participation-key": "gBw6xPd3U4pLXaRkw1UC1wgvR51P5+aYQv5OADAFyOM="
		},
		"pending-rewards": 2280000000000,
		"reward-base": 456,
		"rewards": 2280000000000,
		"round": 18241,
		"status": "Online"
	  }
	],
	"apps": [
	  {
		"id": 1380011588,
		"params": {
		  "creator": "UAPJE355K7BG7RQVMTZOW7QW4ICZJEIC3RZGYG5LSHZ65K6LCNFPJDSR7M",
		  "approval-program": "AiABASI=",
		  "clear-state-program": "AiABASI=",
		  "global-state-schema": {
			"num-byte-slice": 5,
			"num-uint": 5
		  },
		  "local-state-schema": {
			"num-byte-slice": 5,
			"num-uint": 5
		  }
		}
	  }
	],
	"latest-timestamp": 1592537757,
	"protocol-version": "future",
	"round": 18241,
	"sources": null,
	"txns": [
	  {
		"txn": {
			"apap": "AiABASI=",
			"apgs": {
				"nbs": 5,
				"nui": 5
			},
			"apls": {
				"nbs": 5,
				"nui": 5
			},
			"apsu": "AiABASI=",
			"fee": 1000,
			"fv": 18242,
			"gh": "ZIkPs8pTDxbRJsFB1yJ7gvnpDu0Q85FRkl2NCkEAQLU=",
			"lv": 19242,
			"note": "tjpNge78JD8=",
			"snd": "UAPJE355K7BG7RQVMTZOW7QW4ICZJEIC3RZGYG5LSHZ65K6LCNFPJDSR7M",
			"type": "appl"
		}
  	  }
	]
}`)

func TestDryrunRequestJSON(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var gdr model.DryrunRequest
	buf := bytes.NewBuffer(dataJSON)
	dec := protocol.NewJSONDecoder(buf)
	err := dec.Decode(&gdr)
	require.NoError(t, err)

	dr, err := DryrunRequestFromGenerated(&gdr)
	require.NoError(t, err)
	require.Equal(t, 1, len(dr.Txns))
	require.Equal(t, 1, len(dr.Accounts))
	require.Equal(t, 1, len(dr.Apps))

	var response model.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestStateDeltaToStateDelta(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	sd := basics.StateDelta{
		"byteskey": {
			Action: basics.SetBytesAction,
			Bytes:  "test",
		},
		"intkey": {
			Action: basics.SetUintAction,
			Uint:   11,
		},
		"delkey": {
			Action: basics.DeleteAction,
		},
	}
	gsd := globalDeltaToStateDelta(sd)
	require.Equal(t, 3, len(gsd))

	var keys []string
	// test with a loop because sd is a map and iteration order is random
	for _, item := range gsd {
		if item.Key == b64("byteskey") {
			require.Equal(t, uint64(1), item.Value.Action)
			require.Nil(t, item.Value.Uint)
			require.NotNil(t, item.Value.Bytes)
			require.Equal(t, b64("test"), *item.Value.Bytes)
		} else if item.Key == b64("intkey") {
			require.Equal(t, uint64(2), item.Value.Action)
			require.NotNil(t, item.Value.Uint)
			require.Equal(t, uint64(11), *item.Value.Uint)
			require.Nil(t, item.Value.Bytes)
		} else if item.Key == b64("delkey") {
			require.Equal(t, uint64(3), item.Value.Action)
			require.Nil(t, item.Value.Uint)
			require.Nil(t, item.Value.Bytes)
		}
		keys = append(keys, item.Key)
	}
	require.Equal(t, 3, len(keys))
	require.Contains(t, keys, b64("intkey"))
	require.Contains(t, keys, b64("byteskey"))
	require.Contains(t, keys, b64("delkey"))
}

func randomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

func TestDryrunOptIn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ops, err := logic.AssembleString(`#pragma version 2
txn ApplicationID
bz ok
int 0
byte "key"
byte "value"
app_local_put
ok:
int 1`)
	require.NoError(t, err)
	approval := ops.Program
	ops, err = logic.AssembleString("int 1")
	require.NoError(t, err)
	clst := ops.Program
	var appIdx basics.AppIndex = 1
	creator := randomAddress()
	sender := randomAddress()
	dr := DryrunRequest{
		Txns: []transactions.SignedTxn{
			{
				Txn: transactions.Transaction{
					Header: transactions.Header{Sender: sender},
					Type:   protocol.ApplicationCallTx,
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: appIdx,
						OnCompletion:  transactions.OptInOC,
					},
				},
			},
		},
		Apps: []model.Application{
			{
				Id: uint64(appIdx),
				Params: model.ApplicationParams{
					Creator:           creator.String(),
					ApprovalProgram:   approval,
					ClearStateProgram: clst,
					LocalStateSchema:  &model.ApplicationStateSchema{NumByteSlice: 1},
				},
			},
		},
		Accounts: []model.Account{
			{
				Address: sender.String(),
				Status:  "Online",
				Amount:  10000000,
			},
		},
	}
	dr.ProtocolVersion = string(dryrunProtoVersion)

	var response model.DryrunResponse
	doDryrunRequest(&dr, &response)
	require.NoError(t, err)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLogs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ops, err := logic.AssembleString(`
#pragma version 5
byte "A"
loop:
int 0
dup2
getbyte
int 1
+
dup
int 97 //ascii code of last char
<=
bz end
setbyte
dup
log
b loop
end:
int 1
return
`)

	require.NoError(t, err)
	approval := ops.Program
	ops, err = logic.AssembleString("int 1")
	require.NoError(t, err)
	clst := ops.Program
	ops, err = logic.AssembleString("#pragma version 5 \nint 1")
	approv := ops.Program
	require.NoError(t, err)

	var appIdx basics.AppIndex = 1
	creator := randomAddress()
	sender := randomAddress()
	dr := DryrunRequest{
		Txns: []transactions.SignedTxn{
			{
				Txn: transactions.Transaction{
					Header: transactions.Header{Sender: sender},
					Type:   protocol.ApplicationCallTx,
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: appIdx,
						OnCompletion:  transactions.OptInOC,
					},
				},
			},
			{
				Txn: transactions.Transaction{
					Header: transactions.Header{Sender: sender},
					Type:   protocol.ApplicationCallTx,
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: appIdx + 1,
						OnCompletion:  transactions.OptInOC,
					},
				},
			},
		},
		Apps: []model.Application{
			{
				Id: uint64(appIdx),
				Params: model.ApplicationParams{
					Creator:           creator.String(),
					ApprovalProgram:   approval,
					ClearStateProgram: clst,
					LocalStateSchema:  &model.ApplicationStateSchema{NumByteSlice: 1},
				},
			},
			{
				Id: uint64(appIdx + 1),
				Params: model.ApplicationParams{
					Creator:           creator.String(),
					ApprovalProgram:   approv,
					ClearStateProgram: clst,
					LocalStateSchema:  &model.ApplicationStateSchema{NumByteSlice: 1},
				},
			},
		},
		Accounts: []model.Account{
			{
				Address: sender.String(),
				Status:  "Online",
				Amount:  10000000,
			},
		},
	}
	dr.ProtocolVersion = string(dryrunProtoVersion)

	var response model.DryrunResponse
	doDryrunRequest(&dr, &response)
	require.NoError(t, err)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
	logs := *response.Txns[0].Logs
	assert.Equal(t, 32, len(logs))
	for i, m := range logs {
		assert.Equal(t, []byte(string(rune('B'+i))), m)
	}
	encoded := string(protocol.EncodeJSON(response.Txns[0]))
	assert.Contains(t, encoded, "logs")

	assert.Empty(t, response.Txns[1].Logs)
	encoded = string(protocol.EncodeJSON(response.Txns[1]))
	assert.NotContains(t, encoded, "logs")

}

func TestDryrunCost(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var tests = []struct {
		msg       string
		numHashes int
	}{
		{"REJECT", 22},
		{"PASS", 16},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			expectedCosts := make([]int64, 3)
			expectedBudgetAdded := make([]uint64, 3)

			ops, err := logic.AssembleString("#pragma version 5\nbyte 0x41\n" + strings.Repeat("keccak256\n", test.numHashes) + "pop\nint 1\n")
			require.NoError(t, err)
			app1 := ops.Program
			expectedCosts[0] = 3 + int64(test.numHashes)*130
			expectedBudgetAdded[0] = 0

			ops, err = logic.AssembleString("int 1")
			require.NoError(t, err)
			clst := ops.Program

			ops, err = logic.AssembleString("#pragma version 5 \nint 1 \nint 2 \npop")
			require.NoError(t, err)
			app2 := ops.Program
			expectedCosts[1] = 3
			expectedBudgetAdded[1] = 0

			ops, err = logic.AssembleString(`#pragma version 6
itxn_begin
int appl
itxn_field TypeEnum
int DeleteApplication
itxn_field OnCompletion
byte 0x068101 // #pragma version 6; int 1;
itxn_field ApprovalProgram
byte 0x068101 // #pragma version 6; int 1;
itxn_field ClearStateProgram
itxn_submit
int 1`)
			require.NoError(t, err)
			app3 := ops.Program
			expectedCosts[2] = -687
			expectedBudgetAdded[2] = 700

			var appIdx basics.AppIndex = 1
			creator := randomAddress()
			sender := randomAddress()
			dr := DryrunRequest{
				Txns: []transactions.SignedTxn{
					{
						Txn: transactions.Transaction{
							Header: transactions.Header{Sender: sender},
							Type:   protocol.ApplicationCallTx,
							ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
								ApplicationID: appIdx,
								OnCompletion:  transactions.OptInOC,
							},
						},
					},
					{
						Txn: transactions.Transaction{
							Header: transactions.Header{Sender: sender},
							Type:   protocol.ApplicationCallTx,
							ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
								ApplicationID: appIdx + 1,
								OnCompletion:  transactions.OptInOC,
							},
						},
					},
					{
						Txn: transactions.Transaction{
							Header: transactions.Header{Sender: sender},
							Type:   protocol.ApplicationCallTx,
							ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
								ApplicationID: appIdx + 2,
								OnCompletion:  transactions.OptInOC,
							},
						},
					},
				},
				Apps: []model.Application{
					{
						Id: uint64(appIdx),
						Params: model.ApplicationParams{
							Creator:           creator.String(),
							ApprovalProgram:   app1,
							ClearStateProgram: clst,
							LocalStateSchema:  &model.ApplicationStateSchema{NumByteSlice: 1},
						},
					},
					{
						Id: uint64(appIdx + 1),
						Params: model.ApplicationParams{
							Creator:           creator.String(),
							ApprovalProgram:   app2,
							ClearStateProgram: clst,
							LocalStateSchema:  &model.ApplicationStateSchema{NumByteSlice: 1},
						},
					},
					{
						Id: uint64(appIdx + 2),
						Params: model.ApplicationParams{
							Creator:           creator.String(),
							ApprovalProgram:   app3,
							ClearStateProgram: clst,
							LocalStateSchema:  &model.ApplicationStateSchema{NumByteSlice: 1},
						},
					},
				},
				Accounts: []model.Account{
					{
						Address:                     (appIdx + 2).Address().String(),
						Status:                      "Online",
						AmountWithoutPendingRewards: 105_000,
					},
				},
			}
			dr.ProtocolVersion = string(dryrunProtoVersion)
			var response model.DryrunResponse
			doDryrunRequest(&dr, &response)
			require.Empty(t, response.Error)
			require.Len(t, response.Txns, 3)

			for i, txn := range response.Txns {
				messages := *txn.AppCallMessages
				require.Contains(t, messages, test.msg, "Wrong result") // PASS or REJECT

				if test.msg == "REJECT" {
					require.Contains(t, messages[2], "cost budget exceeded", "Failed for a surprise reason")
				}

				cost := int64(*txn.BudgetConsumed) - int64(*txn.BudgetAdded)
				require.Equal(t, expectedCosts[i], cost, "txn %d cost", i)
				require.Equal(t, expectedBudgetAdded[i], *txn.BudgetAdded, "txn %d added", i)
			}
		})
	}
}

func TestDebugTxSubmit(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	source := `#pragma version 5
itxn_begin
int acfg
itxn_field TypeEnum
int 1000000
itxn_field ConfigAssetTotal
int 3
itxn_field ConfigAssetDecimals
byte "oz"
itxn_field ConfigAssetUnitName
byte "Gold"
itxn_field ConfigAssetName
byte "https://gold.rush/"
itxn_field ConfigAssetURL
byte 0x67f0cd61653bd34316160bc3f5cd3763c85b114d50d38e1f4e72c3b994411e7b
itxn_field ConfigAssetMetadataHash
itxn_submit
int 1`

	ops, err := logic.AssembleString(source)
	require.NoError(t, err)
	approval := ops.Program

	ops, err = logic.AssembleString("int 1")
	require.NoError(t, err)
	clst := ops.Program

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	// make balance records
	appIdx := basics.AppIndex(100)
	dr := DryrunRequest{
		ProtocolVersion: string(dryrunProtoVersion),
		Txns: []transactions.SignedTxn{txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender,
			ApplicationID: appIdx,
		}.SignedTxn()},
		Apps: []model.Application{{
			Id: uint64(appIdx),
			Params: model.ApplicationParams{
				Creator:           sender.String(),
				ApprovalProgram:   approval,
				ClearStateProgram: clst,
			},
		}},
		Accounts: []model.Account{
			{
				Address:                     sender.String(),
				Status:                      "Online",
				Amount:                      10000000,
				AmountWithoutPendingRewards: 10000000,
			},
			{
				Address:                     appIdx.Address().String(),
				Status:                      "Offline",
				Amount:                      10000000,
				AmountWithoutPendingRewards: 10000000,
			},
		},
	}

	var response model.DryrunResponse
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunBalanceWithReward(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ops, err := logic.AssembleString(`#pragma version 5
int 0
balance
int 0
>`)
	require.NoError(t, err)
	approval := ops.Program
	ops, err = logic.AssembleString("int 1")
	require.NoError(t, err)
	clst := ops.Program
	var appIdx basics.AppIndex = 1
	creator := randomAddress()
	rewardBase := uint64(10000000)
	dr := DryrunRequest{
		Txns: []transactions.SignedTxn{
			{
				Txn: transactions.Transaction{
					Header: transactions.Header{Sender: creator},
					Type:   protocol.ApplicationCallTx,
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: appIdx,
					},
				},
			},
		},
		Apps: []model.Application{
			{
				Id: uint64(appIdx),
				Params: model.ApplicationParams{
					Creator:           creator.String(),
					ApprovalProgram:   approval,
					ClearStateProgram: clst,
					LocalStateSchema:  &model.ApplicationStateSchema{NumByteSlice: 1},
				},
			},
		},
		Accounts: []model.Account{
			{
				Address:                     creator.String(),
				Status:                      "Online",
				Amount:                      10000000,
				AmountWithoutPendingRewards: 10000000,
				RewardBase:                  &rewardBase,
			},
		},
	}
	dr.ProtocolVersion = string(dryrunProtoVersion)

	var response model.DryrunResponse
	doDryrunRequest(&dr, &response)
	require.NoError(t, err)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunInnerPay(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	paySender, err := logic.AssembleString(`
#pragma version 5
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 10
itxn_field Amount
itxn_submit
int 1
`)
	require.NoError(t, err)

	ops, err := logic.AssembleString("int 1")
	require.NoError(t, err)
	clst := ops.Program

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	appIdx := basics.AppIndex(7)
	dr := DryrunRequest{
		ProtocolVersion: string(dryrunProtoVersion),
		Txns: []transactions.SignedTxn{txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender,
			ApplicationID: appIdx,
		}.SignedTxn()},
		Apps: []model.Application{{
			Id: uint64(appIdx),
			Params: model.ApplicationParams{
				ApprovalProgram:   paySender.Program,
				ClearStateProgram: clst,
			},
		}},
		// Sender must exist (though no fee is ever taken)
		// AppAccount must exist and be able to pay the inner fee and the pay amount (but min balance not checked)
		Accounts: []model.Account{
			{Address: sender.String(), Status: "Offline"},                                                // sender
			{Address: appIdx.Address().String(), Status: "Offline", AmountWithoutPendingRewards: 1_010}}, // app account
	}
	var response model.DryrunResponse
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunScratchSpace(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	approvalOps, err := logic.AssembleString(`
#pragma version 5
txn GroupIndex
int 3
==
bnz checkgload
pushint 123
store 0
pushbytes "def"
store 251
pushint 123
store 252
pushbytes "abc"
store 253
txn GroupIndex
store 254
b exit
checkgload:
int 0
gloads 254
int 0
==
int 1
gloads 254
int 1
==
&&
int 2
gloads 254
int 2
==
&&
assert
exit:
int 1`)
	require.NoError(t, err)

	ops, err := logic.AssembleString("int 1")
	require.NoError(t, err)
	clst := ops.Program

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	txns := make([]transactions.SignedTxn, 0, 4)
	apps := make([]model.Application, 0, 4)
	for appIdx := basics.AppIndex(1); appIdx <= basics.AppIndex(4); appIdx++ {
		txns = append(txns, txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender,
			ApplicationID: appIdx}.SignedTxn())
		apps = append(apps, model.Application{
			Id: uint64(appIdx),
			Params: model.ApplicationParams{
				ApprovalProgram:   approvalOps.Program,
				ClearStateProgram: clst,
			},
		})
	}
	dr := DryrunRequest{
		ProtocolVersion: string(dryrunProtoVersion),
		Txns:            txns,
		Apps:            apps,
		Accounts: []model.Account{
			{Address: sender.String(), Status: "Offline", Amount: 100_000_000}, // sender
		},
	}
	var response model.DryrunResponse
	doDryrunRequest(&dr, &response)

	checkAppCallScratchType(t, &response, 1, []expectedSlotType{
		{0, basics.TealUintType},
		{1, basics.TealType(0)},
		{251, basics.TealBytesType},
		{252, basics.TealUintType},
		{253, basics.TealBytesType},
		{254, basics.TealUintType},
	})

	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func checkEvalDelta(t *testing.T,
	response model.DryrunResponse,
	expectedGlobalDelta model.StateDelta,
	expectedLocalDelta model.AccountStateDelta,
) {
	for _, rt := range response.Txns {
		if rt.GlobalDelta != nil && len(*rt.GlobalDelta) > 0 {
			assert.Equal(t, expectedGlobalDelta, *rt.GlobalDelta)
		} else {
			assert.Nil(t, expectedGlobalDelta)
		}

		if rt.LocalDeltas != nil {
			for _, ld := range *rt.LocalDeltas {
				assert.Equal(t, expectedLocalDelta.Address, ld.Address)
				assert.Equal(t, expectedLocalDelta.Delta, ld.Delta)
			}
		} else {
			assert.Nil(t, expectedLocalDelta)
		}
	}
}

func TestDryrunCheckEvalDeltasReturned(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	// Expected responses.
	expectedByte := b64("val")
	expectedUint := uint64(1)
	expectedGlobalDelta := model.StateDelta{
		{
			Key: b64("key"),
			Value: model.EvalDelta{
				Action: uint64(basics.SetBytesAction),
				Bytes:  &expectedByte,
			},
		},
	}
	expectedLocalDelta := model.AccountStateDelta{
		Address: basics.Address{}.String(),
		Delta: model.StateDelta{
			{
				Key: b64("key"),
				Value: model.EvalDelta{
					Action: uint64(basics.SetUintAction),
					Uint:   &expectedUint,
				},
			},
		},
	}

	// Test that a PASS and REJECT dryrun both return the dryrun evaldelta.
	for i := range []int{0, 1} {
		ops, err := logic.AssembleString(fmt.Sprintf(`
#pragma version 6
txna ApplicationArgs 0
txna ApplicationArgs 1
app_global_put
int 0
txna ApplicationArgs 0
int %d
app_local_put
int %d`, expectedUint, i))
		require.NoError(t, err)
		dr.ProtocolVersion = string(dryrunProtoVersion)

		dr.Txns = []transactions.SignedTxn{
			{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 1,
						ApplicationArgs: [][]byte{
							[]byte("key"),
							[]byte("val"),
						},
					},
				},
			},
		}
		dr.Apps = []model.Application{
			{
				Id: 1,
				Params: model.ApplicationParams{
					ApprovalProgram: ops.Program,
					GlobalStateSchema: &model.ApplicationStateSchema{
						NumByteSlice: 1,
						NumUint:      1,
					},
					LocalStateSchema: &model.ApplicationStateSchema{
						NumByteSlice: 1,
						NumUint:      1,
					},
				},
			},
		}
		dr.Accounts = []model.Account{
			{
				Status:         "Online",
				Address:        basics.Address{}.String(),
				AppsLocalState: &[]model.ApplicationLocalState{{Id: 1}},
			},
		}

		doDryrunRequest(&dr, &response)
		if i == 0 {
			checkAppCallReject(t, &response)
		} else {
			checkAppCallPass(t, &response)
		}
		checkEvalDelta(t, response, expectedGlobalDelta, expectedLocalDelta)
		if t.Failed() {
			logResponse(t, &response)
		}
	}
}

// TestDryrunEarlyExit is a regression test. Ensures that we no longer exit so
// early in eval() that problems are caused by the debugState being nil.
func TestDryrunEarlyExit(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var dr DryrunRequest
	var response model.DryrunResponse

	ops, err := logic.AssembleString("#pragma version 5 \n int 1")
	require.NoError(t, err)
	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{
		txntest.Txn{
			ApplicationID: 1,
			Type:          protocol.ApplicationCallTx,
		}.SignedTxn(),
	}
	dr.Apps = []model.Application{{
		Id: 1,
		Params: model.ApplicationParams{
			ApprovalProgram: ops.Program,
		},
	}}
	dr.Accounts = []model.Account{{
		Status:  "Online",
		Address: basics.Address{}.String(),
	}}
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)

	ops.Program[0] = 100 // version too high
	doDryrunRequest(&dr, &response)
	checkAppCallResponse(t, &response, "program version 100 greater than max")
}
