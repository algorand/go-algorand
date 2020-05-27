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
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

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

func TestDryunLogicSig(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		transactions.SignedTxn{
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

func TestDryunLogicSigSource(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		transactions.SignedTxn{},
	}
	dr.Sources = []DryrunSource{
		DryrunSource{
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

const globalTestSource = `// This program approves all transactions whose first arg is "hello"
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

const localStateCheckSource = `// This program approves all transactions whose first arg is "hello"
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

func TestDryunGlobal1(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		transactions.SignedTxn{
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
	app1gs := make(map[string]basics.TealValue)
	app1gs["foo"] = basics.TealValue{Type: basics.TealBytesType, Bytes: "bar"}
	dr.Apps = []DryrunApp{
		DryrunApp{
			AppIndex: 1,
			Params: basics.AppParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     app1gs,
			},
		},
	}
	doDryrunRequest(&dr, &proto, &response)
	checkAppCallPass(t, &response)
	if t.Failed() {
		logResponse(t, &response)
	}
}

func TestDryunGlobal2(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		transactions.SignedTxn{
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
	app1gs := make(map[string]basics.TealValue)
	app1gs["foo"] = basics.TealValue{Type: basics.TealBytesType, Bytes: "bar"}
	dr.Apps = []DryrunApp{
		DryrunApp{
			AppIndex: 1,
			Params: basics.AppParams{
				ApprovalProgram: globalTestProgram,
				GlobalState:     app1gs,
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

func TestDryunLocal1(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		transactions.SignedTxn{
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
	dr.Apps = []DryrunApp{
		DryrunApp{
			AppIndex: 1,
			Params: basics.AppParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	dr.AccountAppStates = []DryrunLocalAppState{
		DryrunLocalAppState{
			// Account 0
			AppIndex: 1,
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

func TestDryunLocal1A(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		transactions.SignedTxn{
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
	dr.Apps = []DryrunApp{
		DryrunApp{
			AppIndex: 1,
		},
	}
	dr.AccountAppStates = []DryrunLocalAppState{
		DryrunLocalAppState{
			// Account 0
			AppIndex: 1,
		},
	}
	dr.Sources = []DryrunSource{
		DryrunSource{
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

func TestDryunLocalCheck(t *testing.T) {
	// {"txns":[{"lsig":{"l":"AiABASI="},"txn":{}}]}
	var dr DryrunRequest
	var proto config.ConsensusParams
	var response DryrunResponse

	proto.LogicSigVersion = 2
	proto.LogicSigMaxCost = 1000

	dr.Txns = []transactions.SignedTxn{
		transactions.SignedTxn{
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
	dr.Apps = []DryrunApp{
		DryrunApp{
			AppIndex: 1,
			Params: basics.AppParams{
				ApprovalProgram: localStateCheckProg,
			},
		},
	}
	localv := make(map[string]basics.TealValue, 1)
	localv["foo"] = basics.TealValue{Type: basics.TealBytesType, Bytes: "bar"}
	dr.AccountAppStates = []DryrunLocalAppState{
		DryrunLocalAppState{
			AppIndex: 1,
			State:    basics.AppLocalState{KeyValue: localv},
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
