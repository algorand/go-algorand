// Copyright (C) 2019-2021 Algorand, Inc.
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
	opSpecs := logic.OpsByName[logic.LogicVersion]
	// TODO: sort by logic.OpSpecs[].Opcode
	for _, opname := range og.Ops {
		spec := opSpecs[opname]
		fmt.Fprintf(out, "| `%s%s` | %s |\n",
			markdownTableEscape(spec.Name), immediateMarkdown(&spec),
			markdownTableEscape(logic.OpDoc(opname)))
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

func integerConstantsTableMarkdown(out io.Writer) {
	fmt.Fprintf(out, "#### OnComplete\n\n")
	fmt.Fprintf(out, "%s\n\n", logic.OnCompletionPreamble)
	fmt.Fprintf(out, "| Value | Constant name | Description |\n")
	fmt.Fprintf(out, "| --- | --- | --- |\n")
	for i, name := range logic.OnCompletionNames {
		value := uint64(i)
		fmt.Fprintf(out, "| %d | %s | %s |\n", value, markdownTableEscape(name), logic.OnCompletionDescription(value))
	}
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "#### TypeEnum constants\n")
	fmt.Fprintf(out, "| Value | Constant name | Description |\n")
	fmt.Fprintf(out, "| --- | --- | --- |\n")
	for i, name := range logic.TxnTypeNames {
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, markdownTableEscape(name), logic.TypeNameDescription(name))
	}
	out.Write([]byte("\n"))
}

func fieldTableMarkdown(out io.Writer, names []string, types []logic.StackType, extra map[string]string) {
	fmt.Fprintf(out, "| Index | Name | Type | Notes |\n")
	fmt.Fprintf(out, "| --- | --- | --- | --- |\n")
	for i, name := range names {
		gfType := types[i]
		estr := extra[name]
		fmt.Fprintf(out, "| %d | %s | %s | %s |\n", i, markdownTableEscape(name), markdownTableEscape(gfType.String()), estr)
	}
	out.Write([]byte("\n"))
}

func transactionFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`txn` Fields (see [transaction reference](https://developer.algorand.org/docs/reference/transactions/)):\n\n")
	fieldTableMarkdown(out, logic.TxnFieldNames, logic.TxnFieldTypes, logic.TxnFieldDocs())
}

func globalFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`global` Fields:\n\n")
	fieldTableMarkdown(out, logic.GlobalFieldNames, logic.GlobalFieldTypes, logic.GlobalFieldDocs())
}

func assetHoldingFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`asset_holding_get` Fields:\n\n")
	fieldTableMarkdown(out, logic.AssetHoldingFieldNames, logic.AssetHoldingFieldTypes, logic.AssetHoldingFieldDocs)
}

func assetParamsFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`asset_params_get` Fields:\n\n")
	fieldTableMarkdown(out, logic.AssetParamsFieldNames, logic.AssetParamsFieldTypes, logic.AssetParamsFieldDocs)
}

func immediateMarkdown(op *logic.OpSpec) string {
	markdown := ""
	for _, imm := range op.Details.Immediates {
		markdown = markdown + " " + imm.Name
	}
	return markdown
}

func opToMarkdown(out io.Writer, op *logic.OpSpec) (err error) {
	ws := ""
	opextra := logic.OpImmediateNote(op.Name)
	if opextra != "" {
		ws = " "
	}
	costs := logic.OpAllCosts(op.Name)
	fmt.Fprintf(out, "\n## %s%s\n\n- Opcode: 0x%02x%s%s\n", op.Name, immediateMarkdown(op), op.Opcode, ws, opextra)
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
		if len(op.Returns) == 1 {
			fmt.Fprintf(out, "- Pushes: %s", op.Returns[0].String())
		} else {
			fmt.Fprintf(out, "- Pushes: *... stack*, %s", op.Returns[0].String())
			for _, rt := range op.Returns[1:] {
				fmt.Fprintf(out, ", %s", rt.String())
			}
		}
		fmt.Fprintf(out, "\n")
	}
	fmt.Fprintf(out, "- %s\n", logic.OpDoc(op.Name))
	// if cost changed with versions print all of them
	if len(costs) > 1 {
		fmt.Fprintf(out, "- **Cost**:\n")
		for v := 1; v < len(costs); v++ {
			fmt.Fprintf(out, "   - %d (LogicSigVersion = %d)\n", costs[v], v)
		}
	} else {
		cost := costs[0]
		if cost != 1 {
			fmt.Fprintf(out, "- **Cost**: %d\n", cost)
		}
	}
	if op.Version > 1 {
		fmt.Fprintf(out, "- LogicSigVersion >= %d\n", op.Version)
	}
	if !op.Modes.Any() {
		fmt.Fprintf(out, "- Mode: %s\n", op.Modes.String())
	}
	if op.Name == "global" {
		globalFieldsMarkdown(out)
	} else if op.Name == "txn" {
		transactionFieldsMarkdown(out)
		fmt.Fprintf(out, "\nTypeEnum mapping:\n\n")
		typeEnumTableMarkdown(out)
	} else if op.Name == "asset_holding_get" {
		assetHoldingFieldsMarkdown(out)
	} else if op.Name == "asset_params_get" {
		assetParamsFieldsMarkdown(out)
	}
	ode := logic.OpDocExtra(op.Name)
	if ode != "" {
		fmt.Fprintf(out, "\n%s\n", ode)
	}
	return nil
}

func opsToMarkdown(out io.Writer) (err error) {
	out.Write([]byte("# Opcodes\n\nOps have a 'cost' of 1 unless otherwise specified.\n\n"))
	opSpecs := logic.OpcodesByVersion(logic.LogicVersion)
	for _, spec := range opSpecs {
		err = opToMarkdown(out, &spec)
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
	if name == "txna" || name == "gtxna" {
		return logic.TxnaFieldNames
	}
	if name == "asset_holding_get" {
		return logic.AssetHoldingFieldNames
	}
	if name == "asset_params_get" {
		return logic.AssetParamsFieldNames
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
	if name == "txna" || name == "gtxna" {
		return typeString(logic.TxnaFieldTypes)
	}
	if name == "asset_holding_get" {
		return typeString(logic.AssetHoldingFieldTypes)
	}
	if name == "asset_params_get" {
		return typeString(logic.AssetParamsFieldTypes)
	}

	return ""
}

func buildLanguageSpec(opGroups map[string][]string) *LanguageSpec {
	opSpecs := logic.OpcodesByVersion(logic.LogicVersion)
	records := make([]OpRecord, len(opSpecs))
	for i, spec := range opSpecs {
		records[i].Opcode = spec.Opcode
		records[i].Name = spec.Name
		records[i].Args = typeString(spec.Args)
		records[i].Returns = typeString(spec.Returns)
		records[i].Cost = spec.Details.Cost
		records[i].Size = spec.Details.Size
		records[i].ArgEnum = argEnum(spec.Name)
		records[i].ArgEnumTypes = argEnumTypes(spec.Name)
		records[i].Doc = logic.OpDoc(spec.Name)
		records[i].DocExtra = logic.OpDocExtra(spec.Name)
		records[i].ImmediateNote = logic.OpImmediateNote(spec.Name)
		records[i].Groups = opGroups[spec.Name]
	}
	return &LanguageSpec{
		EvalMaxVersion:  logic.LogicVersion,
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
	constants, _ := os.Create("named_integer_constants.md")
	integerConstantsTableMarkdown(constants)
	constants.Close()

	txnfields, _ := os.Create("txn_fields.md")
	fieldTableMarkdown(txnfields, logic.TxnFieldNames, logic.TxnFieldTypes, logic.TxnFieldDocs())
	txnfields.Close()

	globalfields, _ := os.Create("global_fields.md")
	fieldTableMarkdown(globalfields, logic.GlobalFieldNames, logic.GlobalFieldTypes, logic.GlobalFieldDocs())
	globalfields.Close()

	assetholding, _ := os.Create("asset_holding_fields.md")
	fieldTableMarkdown(assetholding, logic.AssetHoldingFieldNames, logic.AssetHoldingFieldTypes, logic.AssetHoldingFieldDocs)
	assetholding.Close()

	assetparams, _ := os.Create("asset_params_fields.md")
	fieldTableMarkdown(assetparams, logic.AssetParamsFieldNames, logic.AssetParamsFieldTypes, logic.AssetParamsFieldDocs)
	assetparams.Close()

	langspecjs, _ := os.Create("langspec.json")
	enc := json.NewEncoder(langspecjs)
	enc.Encode(buildLanguageSpec(opGroups))
	langspecjs.Close()

	tealtm, _ := os.Create("teal.tmLanguage.json")
	enc = json.NewEncoder(tealtm)
	enc.SetIndent("", "  ")
	enc.Encode(buildSyntaxHighlight())
	tealtm.Close()
}
