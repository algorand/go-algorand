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
	"github.com/algorand/go-algorand/crypto"
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

func tvStr(tv generated.TealValue) string {
	if tv.Type == uint64(basics.TealBytesType) {
		return tv.Bytes
	} else if tv.Type == uint64(basics.TealUintType) {
		return strconv.FormatUint(tv.Uint, 10)
	}
	return "UNKNOWN TEAL VALUE"
}

func dbStack(stack []generated.TealValue) string {
	parts := make([]string, len(stack))
	for i, sv := range stack {
		parts[i] = tvStr(sv)
	}
	return strings.Join(parts, " ")
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func logTrace(t *testing.T, lines []string, trace []generated.DryrunState) {
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

func logStateDelta(t *testing.T, sd generated.StateDelta) {
	for _, vd := range sd {
		t.Logf("\t%s: %#v", vd.Key, vd)
	}
}

func logResponse(t *testing.T, response *generated.DryrunResponse) {
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

var dryrunProtoVersion protocol.ConsensusVersion = "dryrunTestProto"

func TestDryrunLogicSig(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response generated.DryrunResponse

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
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response generated.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

	dr.Txns = []transactions.SignedTxn{{}}
	dr.Sources = []generated.DryrunSource{
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
	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000
	proto.MaxAppKeyLen = 64
	proto.MaxAppBytesValueLen = 64

	config.Consensus[dryrunProtoVersion] = proto
}

func checkLogicSigPass(t *testing.T, response *generated.DryrunResponse) {
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

func checkAppCallPass(t *testing.T, response *generated.DryrunResponse) {
	if len(response.Txns) < 1 {
		t.Error("no response txns")
	} else if len(response.Txns) == 0 {
		t.Error("response txns is nil")
	} else if response.Txns[0].AppCallMessages == nil || len(*response.Txns[0].AppCallMessages) < 1 {
		t.Error("no response app msg")
	} else {
		messages := *response.Txns[0].AppCallMessages
		assert.GreaterOrEqual(t, len(messages), 1)
		assert.Equal(t, "PASS", messages[len(messages)-1])
	}
}

func TestDryrunGlobal1(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response generated.DryrunResponse

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
	gkv := generated.TealKeyValueStore{
		generated.TealKeyValue{
			Key:   b64("foo"),
			Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: b64("bar")},
		},
	}
	dr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     &gkv,
				GlobalStateSchema: &generated.ApplicationStateSchema{
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
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response generated.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

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
			Key:   b64("foo"),
			Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: b64("bar")},
		},
	}
	dr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
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
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response generated.DryrunResponse

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
	dr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
				LocalStateSchema: &generated.ApplicationStateSchema{
					NumByteSlice: 10,
					NumUint:      10,
				},
			},
		},
	}
	dr.Accounts = []generated.Account{
		{
			Status:         "Online",
			Address:        basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalState{{Id: 1}},
		},
	}
	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if response.Txns[0].LocalDeltas == nil {
		t.Fatal("empty local delta")
	}
	addrFound := false
	valueFound := false
	for _, lds := range *response.Txns[0].LocalDeltas {
		if lds.Address == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
			addrFound = true
			for _, ld := range lds.Delta {
				if ld.Key == b64("foo") {
					valueFound = true
					assert.Equal(t, ld.Value.Action, uint64(basics.SetBytesAction))
					assert.Equal(t, *ld.Value.Bytes, b64("bar"))

				}
			}
		}
	}
	if !addrFound {
		t.Error("no local delta for AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	}
	if !valueFound {
		t.Error("no local delta for value foo")
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocal1A(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()

	var dr DryrunRequest
	var response generated.DryrunResponse

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
	dr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
				LocalStateSchema: &generated.ApplicationStateSchema{
					NumByteSlice: 10,
					NumUint:      10,
				},
			},
		},
	}
	dr.Accounts = []generated.Account{
		{
			Status:         "Online",
			Address:        basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalState{{Id: 1}},
		},
	}

	dr.Sources = []generated.DryrunSource{
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
	addrFound := false
	valueFound := false
	for _, lds := range *response.Txns[0].LocalDeltas {
		if lds.Address == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
			addrFound = true
			for _, ld := range lds.Delta {
				if ld.Key == b64("foo") {
					valueFound = true
					assert.Equal(t, ld.Value.Action, uint64(basics.SetBytesAction))
					assert.Equal(t, *ld.Value.Bytes, b64("bar"))

				}
			}
		}
	}
	if !addrFound {
		t.Error("no local delta for AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	}
	if !valueFound {
		t.Error("no local delta for value foo")
	}
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryrunLocalCheck(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	t.Parallel()
	var dr DryrunRequest
	var response generated.DryrunResponse

	dr.ProtocolVersion = string(dryrunProtoVersion)

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
	dr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	localv := make(generated.TealKeyValueStore, 1)
	localv[0] = generated.TealKeyValue{
		Key: b64("foo"),
		Value: generated.TealValue{
			Type:  uint64(basics.TealBytesType),
			Bytes: b64("bar"),
		},
	}

	dr.Accounts = []generated.Account{
		{
			Status:  "Online",
			Address: basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalState{{
				Id:       1,
				KeyValue: &localv,
			}},
		},
	}

	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
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

	gdr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	localv := make(generated.TealKeyValueStore, 1)
	localv[0] = generated.TealKeyValue{
		Key:   b64("foo"),
		Value: generated.TealValue{Type: uint64(basics.TealBytesType), Bytes: b64("bar")},
	}

	gdr.Accounts = []generated.Account{
		{
			Status:  "Online",
			Address: basics.Address{}.String(),
			AppsLocalState: &[]generated.ApplicationLocalState{{
				Id:       1,
				KeyValue: &localv,
			}},
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

	// use protocol msgp
	dr1, err := DryrunRequestFromGenerated(&gdr)
	require.NoError(t, err)
	encoded, err = encode(protocol.CodecHandle, &dr)
	encoded2 := protocol.EncodeReflect(&dr)
	require.Equal(t, encoded, encoded2)

	buf = bytes.NewBuffer(encoded)
	dec = protocol.NewDecoder(buf)
	var dr2 DryrunRequest
	err = dec.Decode(&dr2)
	require.NoError(t, err)
	require.Equal(t, dr1, dr2)

	dec = protocol.NewDecoder(buf)
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
	dr.Apps = []generated.Application{
		{
			Id: 1,
			Params: generated.ApplicationParams{
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

	// var proto config.ConsensusParams
	var response generated.DryrunResponse

	// proto.LogicSigVersion = 2
	// proto.LogicSigMaxCost = 1000

	// config.Consensus[dryrunProtoVersion] = proto
	dr.ProtocolVersion = string(dryrunProtoVersion)

	doDryrunRequest(&dr, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestStateDeltaToStateDelta(t *testing.T) {
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
	gsd := StateDeltaToStateDelta(sd)
	require.Equal(t, 3, len(*gsd))

	var keys []string
	// test with a loop because sd is a map and iteration order is random
	for _, item := range *gsd {
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
	clst := ops.Program
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
		},
		Apps: []generated.Application{
			{
				Id: uint64(appIdx),
				Params: generated.ApplicationParams{
					Creator:           creator.String(),
					ApprovalProgram:   approval,
					ClearStateProgram: clst,
					LocalStateSchema:  &generated.ApplicationStateSchema{NumByteSlice: 1},
				},
			},
		},
		Accounts: []generated.Account{
			{
				Address: sender.String(),
				Status:  "Online",
				Amount:  10000000,
			},
		},
	}
	dr.ProtocolVersion = string(dryrunProtoVersion)

	var response generated.DryrunResponse
	doDryrunRequest(&dr, &response)
	require.NoError(t, err)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}
