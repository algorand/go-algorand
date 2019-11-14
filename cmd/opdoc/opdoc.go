// Copyright (C) 2019 Algorand, Inc.
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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

func opGroupMarkdownTable(og *logic.OpGroup, out io.Writer) {
	fmt.Fprint(out, `| Op | Description |
| --- | --- |
`)
	// TODO: sort by logic.OpSpecs[].Opcode
	for _, opname := range og.Ops {
		fmt.Fprintf(out, "| `%s` | %s |\n", markdownTableEscape(opname), markdownTableEscape(logic.OpDoc(opname)))
	}
}

func markdownTableEscape(x string) string {
	return strings.ReplaceAll(x, "|", "\\|")
}

func typeEnumTableMarkdown(out io.Writer) {
	fmt.Fprintf(out, "| Index | \"Type\" string | Description |\n")
	fmt.Fprintf(out, "| --- | --- | --- |\n")
	for i, name := range logic.TxnTypeNames {
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, markdownTableEscape(name), logic.TypeNameDescription(name))
	}
	out.Write([]byte("\n"))
}

func fieldTableMarkdown(out io.Writer, names []string, types []logic.StackType) {
	fmt.Fprintf(out, "| Index | Name | Type |\n")
	fmt.Fprintf(out, "| --- | --- | --- |\n")
	for i, name := range names {
		gfType := types[i]
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, markdownTableEscape(name), markdownTableEscape(gfType.String()))
	}
	out.Write([]byte("\n"))
}

func transactionFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`txn` Fields:\n\n")
	fieldTableMarkdown(out, logic.TxnFieldNames, logic.TxnFieldTypes)
}

func globalFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`global` Fields:\n\n")
	fieldTableMarkdown(out, logic.GlobalFieldNames, logic.GlobalFieldTypes)
}

func opToMarkdown(out io.Writer, op *logic.OpSpec) (err error) {

	opextra := logic.OpImmediateNote(op.Name)
	cost := logic.OpCost(op.Name)
	fmt.Fprintf(out, "\n## %s\n\n- Opcode: 0x%02x %s\n", op.Name, op.Opcode, opextra)
	if op.Args == nil {
		fmt.Fprintf(out, "- Pops: _None_\n")
	} else if len(op.Args) == 1 {
		fmt.Fprintf(out, "- Pops: *... stack*, %s\n", op.Args[0].String())
	} else {
		fmt.Fprintf(out, "- Pops: *... stack*, {%s A}", op.Args[0].String())
		for i, v := range op.Args[1:] {
			fmt.Fprintf(out, ", {%s %c}", v.String(), rune(int('B')+i))
		}
		out.Write([]byte("\n"))
	}
	if op.Returns == nil {
		fmt.Fprintf(out, "- Pushes: _None_\n")
	} else {
		fmt.Fprintf(out, "- Pushes: %s", op.Returns[0].String())
		for _, rt := range op.Returns[1:] {
			fmt.Fprintf(out, ", %s", rt.String())
		}
		fmt.Fprintf(out, "\n")
	}
	fmt.Fprintf(out, "- %s\n", logic.OpDoc(op.Name))
	if cost != 1 {
		fmt.Fprintf(out, "- **Cost**: %d\n", cost)
	}
	if op.Name == "global" {
		globalFieldsMarkdown(out)
	} else if op.Name == "txn" {
		transactionFieldsMarkdown(out)
		fmt.Fprintf(out, "\nTypeEnum mapping:\n\n")
		typeEnumTableMarkdown(out)
	}
	ode := logic.OpDocExtra(op.Name)
	if ode != "" {
		fmt.Fprintf(out, "\n%s\n", ode)
	}
	return nil
}

func opsToMarkdown(out io.Writer) (err error) {
	out.Write([]byte("# Opcodes\n\nOps have a 'cost' of 1 unless otherwise specified.\n\n"))
	for i := range logic.OpSpecs {
		err = opToMarkdown(out, &logic.OpSpecs[i])
		if err != nil {
			return
		}
	}
	return
}

// OpRecord is a consolidated record of things about an Op
type OpRecord struct {
	Opcode  byte
	Name    string
	Args    string `json:",omitempty"`
	Returns string `json:",omitempty"`
	Cost    int
	Size    int

	ArgEnum      []string `json:",omitempty"`
	ArgEnumTypes string   `json:",omitempty"`

	Doc           string
	DocExtra      string `json:",omitempty"`
	ImmediateNote string `json:",omitempty"`
	Groups        []string
}

// LanguageSpec records the ops of the language at some version
type LanguageSpec struct {
	EvalMaxVersion  int
	LogicSigVersion uint64
	Ops             []OpRecord
}

func argEnum(name string) []string {
	if name == "txn" || name == "gtxn" {
		return logic.TxnFieldNames
	}
	if name == "global" {
		return logic.GlobalFieldNames
	}
	return nil
}

func typeString(types []logic.StackType) string {
	out := make([]byte, len(types))
	for i, t := range types {
		switch t {
		case logic.StackUint64:
			out[i] = 'U'
		case logic.StackBytes:
			out[i] = 'B'
		case logic.StackAny:
			out[i] = '.'
		case logic.StackNone:
			if i == 0 && len(types) == 1 {
				return ""
			}
			panic("unexpected StackNone in opdoc typeString")
		default:
			panic("unexpected type in opdoc typeString")
		}
	}
	return string(out)
}

func argEnumTypes(name string) string {
	if name == "txn" || name == "gtxn" {
		return typeString(logic.TxnFieldTypes)
	}
	if name == "global" {
		return typeString(logic.GlobalFieldTypes)
	}
	return ""
}

func buildLanguageSpec(opGroups map[string][]string) *LanguageSpec {
	records := make([]OpRecord, len(logic.OpSpecs))
	for i, spec := range logic.OpSpecs {
		records[i].Opcode = spec.Opcode
		records[i].Name = spec.Name
		records[i].Args = typeString(spec.Args)
		records[i].Returns = typeString(spec.Returns)
		records[i].Cost = logic.OpCost(spec.Name)
		records[i].Size = logic.OpSize(spec.Name)
		records[i].ArgEnum = argEnum(spec.Name)
		records[i].ArgEnumTypes = argEnumTypes(spec.Name)
		records[i].Doc = logic.OpDoc(spec.Name)
		records[i].DocExtra = logic.OpDocExtra(spec.Name)
		records[i].ImmediateNote = logic.OpImmediateNote(spec.Name)
		records[i].Groups = opGroups[spec.Name]
	}
	return &LanguageSpec{
		EvalMaxVersion:  logic.EvalMaxVersion,
		LogicSigVersion: config.Consensus[protocol.ConsensusCurrentVersion].LogicSigVersion,
		Ops:             records,
	}
}

func main() {
	opcodesMd, _ := os.Create("TEAL_opcodes.md")
	opsToMarkdown(opcodesMd)
	opcodesMd.Close()
	opGroups := make(map[string][]string, len(logic.OpSpecs))
	for _, og := range logic.OpGroupList {
		fname := fmt.Sprintf("%s.md", og.GroupName)
		fname = strings.ReplaceAll(fname, " ", "_")
		fout, _ := os.Create(fname)
		opGroupMarkdownTable(&og, fout)
		fout.Close()
		for _, opname := range og.Ops {
			opGroups[opname] = append(opGroups[opname], og.GroupName)
		}
	}
	txnfields, _ := os.Create("txn_fields.md")
	fieldTableMarkdown(txnfields, logic.TxnFieldNames, logic.TxnFieldTypes)
	txnfields.Close()

	globalfields, _ := os.Create("global_fields.md")
	fieldTableMarkdown(globalfields, logic.GlobalFieldNames, logic.GlobalFieldTypes)
	globalfields.Close()

	langspecjs, _ := os.Create("langspec.json")
	enc := json.NewEncoder(langspecjs)
	enc.Encode(buildLanguageSpec(opGroups))
	langspecjs.Close()
}
