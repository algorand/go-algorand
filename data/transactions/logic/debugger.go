package logic

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
)

type Debugger struct {
	URL string
}

type PCOffset struct {
	PC     int `json:"pc"`
	Offset int `json:"offset"`
}

type DebuggerState struct {
	PC          int            `json:"pc"`
	Stack       []v1.TealValue `json:"stack"`
	Scratch     []v1.TealValue `json:"scratch"`
	Disassembly string         `json:"disasm"`
	PCOffset    []PCOffset     `json:"pctooffset"`
	ExecID      string         `json:"execid"`
	Error       string         `json:"error"`
}

func (cx *evalContext) debugState() *DebuggerState {
	ds := &cx.debuggerState

	// Generate unique execution ID if necessary
	if ds.ExecID == "" {
		var execID crypto.Digest
		crypto.RandBytes(execID[:])
		ds.ExecID = execID.String()
	}

	if ds.Disassembly == "" {
		// Disassemble if necessary
		disasm, pcOffset, err := DisassembleInstrumented(cx.program)
		if err != nil {
			// Report disassembly error as program text
			disasm = err.Error()
		}

		ds.Disassembly = disasm
		ds.PCOffset = pcOffset
	}

	// Update PC, error, stack, and scratch space
	ds.PC = cx.pc
	if cx.err != nil {
		ds.Error = cx.err.Error()
	}

	stack := make([]v1.TealValue, len(cx.stack), len(cx.stack))
	for i, sv := range cx.stack {
		tv := sv.toTealValue()
		stack[i] = v1.TealValue{
			Type:  tv.Type.String(),
			Bytes: base64.StdEncoding.EncodeToString([]byte(tv.Bytes)),
			Uint:  tv.Uint,
		}
	}

	scratch := make([]v1.TealValue, len(cx.scratch), len(cx.scratch))
	for i, sv := range cx.scratch {
		tv := sv.toTealValue()
		scratch[i] = v1.TealValue{
			Type:  tv.Type.String(),
			Bytes: base64.StdEncoding.EncodeToString([]byte(tv.Bytes)),
			Uint:  tv.Uint,
		}
	}

	ds.Stack = stack
	ds.Scratch = scratch
	return ds
}

func (dbg *Debugger) postState(cx *evalContext, endpoint string) error {
	state := cx.debugState()
	enc, err := json.Marshal(state)
	if err != nil {
		return err
	}

	body := bytes.NewBuffer(enc)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", dbg.URL, endpoint), body)
	if err != nil {
		return err
	}

	httpClient := &http.Client{}
	_, err = httpClient.Do(req)
	return err
}

func (dbg *Debugger) register(cx *evalContext) error {
	return dbg.postState(cx, "exec/register")
}

func (dbg *Debugger) update(cx *evalContext) error {
	return dbg.postState(cx, "exec/update")
}

func (dbg *Debugger) complete(cx *evalContext) error {
	return dbg.postState(cx, "exec/complete")
}
