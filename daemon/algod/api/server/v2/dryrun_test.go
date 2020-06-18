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

package v2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

func unB64(x string) []byte {
	out, err := base64.StdEncoding.DecodeString(x)
	if err != nil {
		panic(err)
	}
	return out
}

func tvStr(tv basics.TealValue) string {
	if tv.Type == basics.TealBytesType {
		return tv.Bytes
	} else if tv.Type == basics.TealUintType {
		return strconv.FormatUint(tv.Uint, 10)
	}
	return "UNKNOWN TEAL VALUE"
}

func dbStack(stack []basics.TealValue) string {
	parts := make([]string, len(stack))
	for i, sv := range stack {
		parts[i] = tvStr(sv)
	}
	return strings.Join(parts, " ")
}

func logTrace(t *testing.T, trace []logic.DebugState) {
	var disasm string
	var lines []string
	for _, ds := range trace {
		if ds.Disassembly != "" {
			disasm = ds.Disassembly
			t.Log(disasm)
			lines = strings.Split(disasm, "\n")
		}
		var line string
		if len(lines) > 0 {
			line = lines[ds.Line]
		} else {
			line = ""
		}
		t.Logf("\tstack=[%s]", dbStack(ds.Stack))
		t.Logf("%s\t// line=%d pc=%d", line, ds.Line, ds.PC)
	}
}

func logStateDelta(t *testing.T, sd basics.StateDelta) {
	for key, vd := range sd {
		t.Logf("\t%v: %#v", key, vd)
	}
}

func logResponse(t *testing.T, response *DryrunResponse) {
	t.Log(response.Error)
	for i, rt := range response.Txns {
		t.Logf("txn[%d]", i)
		if len(rt.LogicSigTrace) > 0 {
			t.Log("Logic Sig:")
			logTrace(t, rt.LogicSigTrace)
			if len(rt.LogicSigMessages) > 0 {
				t.Log("Messages:")
			}
			for _, m := range rt.LogicSigMessages {
				t.Log(m)
			}
		}
		if len(rt.AppCallTrace) > 0 {
			t.Log("App Call:")
			logTrace(t, rt.AppCallTrace)
			if len(rt.AppCallMessages) > 0 {
				t.Log("Messages:")
			}
			for _, m := range rt.AppCallMessages {
				t.Log(m)
			}
		}
		if len(rt.GlobalDelta) > 0 {
			t.Log("Global delta")
			logStateDelta(t, rt.GlobalDelta)
		}
		for addr, ld := range rt.LocalDeltas {
			t.Logf("%s delta", addr)
			logStateDelta(t, ld)
		}
	}
}

func TestDryrunLogicSig(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		{
			Lsig: transactions.LogicSig{
				Logic: unB64("AiABASI="),
			},
		},
		// it doesn't actually care about any txn content
	}
	doDryrunRequest(&dr, &proto, &response)
	checkLogicSigPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLogicSigSource(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{{}}
	dr.Sources = []generated.DryrunSource{
		{
			Source:    "int 1",
			FieldName: "lsig",
			TxnIndex:  0,
		},
	}
	doDryrunRequest(&dr, &proto, &response)
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
	var err error
	globalTestProgram, err = logic.AssembleString(globalTestSource)
	if err != nil {
		panic(err)
	}
	localStateCheckProg, err = logic.AssembleString(localStateCheckSource)
	if err != nil {
		panic(err)
	}
}

func checkLogicSigPass(t *testing.T, response *DryrunResponse) {
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if response.Txns[0] == nil {
		t.Error("response txns is nil")
	} else if len(response.Txns[0].LogicSigMessages) < 1 {
		t.Error("no response lsig msg")
	} else {
		messages := response.Txns[0].LogicSigMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
}

func checkAppCallPass(t *testing.T, response *DryrunResponse) {
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if response.Txns[0] == nil {
		t.Error("response txns is nil")
	} else if len(response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response app msg")
	} else {
		messages := response.Txns[0].AppCallMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
}

func TestDryrunGlobal1(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

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
	gkv := generated.TealKeyValueStore{
		generated.TealKeyValue{
			Key:   "foo",
			Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: "bar"},
		},
	}
	dr.Apps = []generated.DryrunApp{
		{
			AppIndex: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     &gkv,
			},
		},
	}
	doDryrunRequest(&dr, &proto, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunGlobal2(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 1,
					ApplicationArgs: [][]byte{
						[]byte("check"),
						[]byte("bar"),
					},
				},
			},
		},
	}
	gkv := generated.TealKeyValueStore{
		generated.TealKeyValue{
			Key:   "foo",
			Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: "bar"},
		},
	}
	dr.Apps = []generated.DryrunApp{
		{
			AppIndex: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     &gkv,
			},
		},
	}
	doDryrunRequest(&dr, &proto, &response)
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if len(response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response lsig msg")
	} else {
		messages := response.Txns[0].AppCallMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocal1(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

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
	dr.Apps = []generated.DryrunApp{
		{
			AppIndex: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	dr.Accounts = []generated.Account{
		{
			Address:        basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalStates{{AppIndex: 1}},
		},
	}
	doDryrunRequest(&dr, &proto, &response)
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if len(response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response lsig msg")
	} else {
		messages := response.Txns[0].AppCallMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
	ld, ok := response.Txns[0].LocalDeltas["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"]
	if ok {
		foo, ok := ld["foo"]
		if ok {
			assert.Equal(t, foo.Action, basics.SetBytesAction)
			assert.Equal(t, foo.Bytes, "bar")
		} else {
			t.Error("no local delta for value foo")
		}
	} else {
		t.Error("no local delta for AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocal1A(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

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
	dr.Apps = []generated.DryrunApp{
		{
			AppIndex: 1,
		},
	}
	dr.Accounts = []generated.Account{
		{
			Address:        basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalStates{{AppIndex: 1}},
		},
	}

	dr.Sources = []generated.DryrunSource{
		{
			Source:    localStateCheckSource,
			FieldName: "approv",
			AppIndex:  1,
		},
	}
	doDryrunRequest(&dr, &proto, &response)
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if len(response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response lsig msg")
	} else {
		messages := response.Txns[0].AppCallMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
	ld, ok := response.Txns[0].LocalDeltas["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"]
	if ok {
		foo, ok := ld["foo"]
		if ok {
			assert.Equal(t, foo.Action, basics.SetBytesAction)
			assert.Equal(t, foo.Bytes, "bar")
		} else {
			t.Error("no local delta for value foo")
		}
	} else {
		t.Error("no local delta for AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocalCheck(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: 1,
					ApplicationArgs: [][]byte{
						[]byte("check"),
						[]byte("bar"),
					},
				},
			},
		},
	}
	dr.Apps = []generated.DryrunApp{
		{
			AppIndex: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	localv := make(generated.TealKeyValueStore, 1)
	localv[0] = generated.TealKeyValue{
		Key:   "foo",
		Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: "bar"},
	}

	dr.Accounts = []generated.Account{
		{
			Address: basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalStates{
				{
					AppIndex: 1,
					State: generated.ApplicationLocalState{
						KeyValue: localv,
					},
				},
			},
		},
	}

	doDryrunRequest(&dr, &proto, &response)
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if len(response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response lsig msg")
	} else {
		messages := response.Txns[0].AppCallMessages
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}
func TestDryrunEncodeDecode(t *testing.T) {
	t.Parallel()

	var gdr generated.DryrunRequest
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

	gdr.Apps = []generated.DryrunApp{
		{
			AppIndex: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	localv := make(generated.TealKeyValueStore, 1)
	localv[0] = generated.TealKeyValue{
		Key:   "foo",
		Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: "bar"},
	}

	gdr.Accounts = []generated.Account{
		{
			Address: basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalStates{
				{
					AppIndex: 1,
					State: generated.ApplicationLocalState{
						KeyValue: localv,
					},
				},
			},
		},
	}

	// use protocol
	encoded := protocol.EncodeJSON(&gdr)
	var decoded generated.DryrunRequest
	err := protocol.DecodeJSON(encoded, &decoded)
	require.NoError(t, err)
	require.Equal(t, gdr, decoded)

	buf := bytes.NewBuffer(encoded)
	dec := protocol.NewJSONDecoder(buf)
	decoded = generated.DryrunRequest{}
	err = dec.Decode(&decoded)
	require.NoError(t, err)
	require.Equal(t, gdr, decoded)

	// use json
	data, err := json.Marshal(&gdr)
	require.NoError(t, err)
	gdr = generated.DryrunRequest{}
	err = json.Unmarshal(data, &gdr)
	require.NoError(t, err)

	dr, err := DryrunRequestFromGenerated(&gdr)
	require.NoError(t, err)
	require.Equal(t, 1, len(dr.Txns))
	require.Equal(t, txns[0].Txn.ApplicationID, dr.Txns[0].Txn.ApplicationID)
	require.Equal(t, txns[0].Txn.ApprovalProgram, dr.Txns[0].Txn.ApprovalProgram)
	require.Equal(t, []byte{1, 2, 3}, dr.Txns[0].Txn.ApprovalProgram)
	require.Equal(t, txns[0].Txn.ApplicationArgs, dr.Txns[0].Txn.ApplicationArgs)
}

func TestDryrunMakeLedger(t *testing.T) {
	t.Parallel()

	var dr DryrunRequest
	var proto config.ConsensusParams

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

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
	dr.Apps = []generated.DryrunApp{
		{
			AppIndex: 1,
			Creator:  sender.String(),
			Params: generated.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	dl := dryrunLedger{dr: &dr, proto: &proto}
	err = dl.init()
	require.NoError(t, err)
	_, err = makeAppLedger(&dl, &dr.Txns[0].Txn, 1)
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
		"app-index": 1380011588,
		"creator": "UAPJE355K7BG7RQVMTZOW7QW4ICZJEIC3RZGYG5LSHZ65K6LCNFPJDSR7M",
		"params": {
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
	t.Parallel()

	var gdr generated.DryrunRequest
	buf := bytes.NewBuffer(dataJSON)
	dec := protocol.NewJSONDecoder(buf)
	err := dec.Decode(&gdr)
	require.NoError(t, err)

	dr, err := DryrunRequestFromGenerated(&gdr)
	require.NoError(t, err)
	require.Equal(t, 1, len(dr.Txns))
	require.Equal(t, 1, len(dr.Accounts))
	require.Equal(t, 1, len(dr.Apps))

	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	doDryrunRequest(&dr, &proto, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}
