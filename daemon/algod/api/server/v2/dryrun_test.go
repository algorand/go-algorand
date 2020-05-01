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
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
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

func tvStr(tv v1.TealValue) string {
	if tv.Type == "b" {
		return tv.Bytes
	} else if tv.Type == "u" {
		return strconv.FormatUint(tv.Uint, 10)
	}
	return "UNKNOWN TEAL VALUE"
}

func dbStack(stack []v1.TealValue) string {
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
	assert.Equal(t, "PASS", response.Txns[0].LogicSigMessages[0])
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
	assert.Equal(t, "PASS", response.Txns[0].LogicSigMessages[0])
	if t.Failed() {
		logResponse(t, &response)
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
				ApprovalProgram: unB64("AiACAAEmBQVoZWxsbwV3cml0ZQVjaGVjawNmb28DYmFyNhoAKBJAACY2GgApEkAAFjYaACoSIitlIhJAABY2GgESECNAAA4rJwRnI0AAACMjQAABIg=="),
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
				ApprovalProgram: unB64("AiACAAEmBQVoZWxsbwV3cml0ZQVjaGVjawNmb28DYmFyNhoAKBJAACY2GgApEkAAFjYaACoSIitlIhJAABY2GgESECNAAA4rJwRnI0AAACMjQAABIg=="),
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
