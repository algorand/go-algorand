// Copyright (C) 2019-2022 Algorand, Inc.
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

func opGroupMarkdownTable(names []string, out io.Writer) {
	fmt.Fprint(out, `| Opcode | Description |
| - | -- |
`)
	opSpecs := logic.OpsByName[logic.LogicVersion]
	// TODO: sort by logic.OpSpecs[].Opcode
	for _, opname := range names {
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
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, markdownTableEscape(name), logic.TypeNameDescriptions[name])
	}
	out.Write([]byte("\n"))
}

func integerConstantsTableMarkdown(out io.Writer) {
	fmt.Fprintf(out, "#### OnComplete\n\n")
	fmt.Fprintf(out, "%s\n\n", logic.OnCompletionPreamble)
	fmt.Fprintf(out, "| Value | Name | Description |\n")
	fmt.Fprintf(out, "| - | ---- | -------- |\n")
	for i, name := range logic.OnCompletionNames {
		value := uint64(i)
		fmt.Fprintf(out, "| %d | %s | %s |\n", value, markdownTableEscape(name), logic.OnCompletionDescription(value))
	}
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "#### TypeEnum constants\n\n")
	fmt.Fprintf(out, "| Value | Name | Description |\n")
	fmt.Fprintf(out, "| - | --- | ------ |\n")
	for i, name := range logic.TxnTypeNames {
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, markdownTableEscape(name), logic.TypeNameDescriptions[name])
	}
	out.Write([]byte("\n"))
}

type speccer interface {
	SpecByName(name string) logic.FieldSpec
}

func fieldSpecsMarkdown(out io.Writer, names []string, specs speccer) {
	showTypes := false
	showVers := false
	spec0 := specs.SpecByName(names[0])
	opVer := spec0.OpVersion()
	for _, name := range names {
		if specs.SpecByName(name).Type() != logic.StackNone {
			showTypes = true
		}
		if specs.SpecByName(name).Version() != opVer {
			showVers = true
		}
	}
	headers := "| Index | Name |"
	widths := "| - | ------ |"
	if showTypes {
		headers += " Type |"
		widths += " -- |"
	}
	if showVers {
		headers += " In |"
		widths += " - |"
	}
	headers += " Notes |\n"
	widths += " --------- |\n"
	out.Write([]byte(headers + widths))
	for i, name := range names {
		spec := specs.SpecByName(name)
		str := fmt.Sprintf("| %d | %s", i, markdownTableEscape(name))
		if showTypes {
			str = fmt.Sprintf("%s | %s", str, markdownTableEscape(spec.Type().String()))
		}
		if showVers {
			if spec.Version() == spec.OpVersion() {
				str = fmt.Sprintf("%s |     ", str)
			} else {
				str = fmt.Sprintf("%s | v%d ", str, spec.Version())
			}
		}
		fmt.Fprintf(out, "%s | %s |\n", str, spec.Note())
	}
	out.Write([]byte("\n"))
}

func transactionFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`txn` Fields (see [transaction reference](https://developer.algorand.org/docs/reference/transactions/)):\n\n")
	fieldSpecsMarkdown(out, logic.TxnFieldNames, logic.TxnFieldSpecByName)
}

func globalFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`global` Fields:\n\n")
	fieldSpecsMarkdown(out, logic.GlobalFieldNames, logic.GlobalFieldSpecByName)
}

func assetHoldingFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`asset_holding_get` Fields:\n\n")
	fieldSpecsMarkdown(out, logic.AssetHoldingFieldNames, logic.AssetHoldingFieldSpecByName)
}

func assetParamsFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`asset_params_get` Fields:\n\n")
	fieldSpecsMarkdown(out, logic.AssetParamsFieldNames, logic.AssetParamsFieldSpecByName)
}

func appParamsFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`app_params_get` Fields:\n\n")
	fieldSpecsMarkdown(out, logic.AppParamsFieldNames, logic.AppParamsFieldSpecByName)
}

func ecDsaCurvesMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`ECDSA` Curves:\n\n")
	fieldSpecsMarkdown(out, logic.EcdsaCurveNames, logic.EcdsaCurveSpecByName)
}

func immediateMarkdown(op *logic.OpSpec) string {
	markdown := ""
	for _, imm := range op.Details.Immediates {
		markdown = markdown + " " + imm.Name
	}
	return markdown
}

func stackMarkdown(op *logic.OpSpec) string {
	out := "- Stack: "
	special := logic.OpStackEffects(op.Name)
	if special != "" {
		return out + special + "\n"
	}

	out += "..."
	for i, v := range op.Args {
		out += fmt.Sprintf(", %c", rune(int('A')+i))
		if v.Typed() {
			out += fmt.Sprintf(": %s", v)
		}
	}
	out += " &rarr; ..."

	for i, rt := range op.Returns {
		out += ", "
		if len(op.Returns) > 1 {
			start := int('X')
			if len(op.Returns) > 3 {
				start = int('Z') + 1 - len(op.Returns)
			}
			out += fmt.Sprintf("%c: ", rune(start+i))
		}
		out += rt.String()
	}
	return out + "\n"
}

func opToMarkdown(out io.Writer, op *logic.OpSpec) (err error) {
	ws := ""
	opextra := logic.OpImmediateNote(op.Name)
	if opextra != "" {
		ws = " "
	}
	stackEffects := stackMarkdown(op)
	fmt.Fprintf(out, "\n## %s%s\n\n- Opcode: 0x%02x%s%s\n%s",
		op.Name, immediateMarkdown(op), op.Opcode, ws, opextra, stackEffects)
	fmt.Fprintf(out, "- %s\n", logic.OpDoc(op.Name))
	// if cost changed with versions print all of them
	costs := logic.OpAllCosts(op.Name)
	if len(costs) > 1 {
		fmt.Fprintf(out, "- **Cost**:\n")
		for _, cost := range costs {
			if cost.From == cost.To {
				fmt.Fprintf(out, "    - %d (v%d)\n", cost.Cost, cost.To)
			} else {
				if cost.To < logic.LogicVersion {
					fmt.Fprintf(out, "    - %d (v%d - v%d)\n", cost.Cost, cost.From, cost.To)
				} else {
					fmt.Fprintf(out, "    - %d (since v%d)\n", cost.Cost, cost.From)
				}
			}
		}
	} else {
		cost := costs[0].Cost
		if cost != 1 {
			fmt.Fprintf(out, "- **Cost**: %d\n", cost)
		}
	}
	if op.Version > 1 {
		fmt.Fprintf(out, "- Availability: v%d\n", op.Version)
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
	} else if op.Name == "app_params_get" {
		appParamsFieldsMarkdown(out)
	} else if strings.HasPrefix(op.Name, "ecdsa") {
		ecDsaCurvesMarkdown(out)
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
	if name == "txn" || name == "gtxn" || name == "gtxns" {
		return logic.TxnFieldNames
	}
	if name == "global" {
		return logic.GlobalFieldNames
	}
	if name == "txna" || name == "gtxna" || name == "gtxnsa" || name == "txnas" || name == "gtxnas" || name == "gtxnsas" {
		return logic.TxnaFieldNames()
	}
	if name == "asset_holding_get" {
		return logic.AssetHoldingFieldNames
	}
	if name == "asset_params_get" {
		return logic.AssetParamsFieldNames
	}
	if name == "app_params_get" {
		return logic.AppParamsFieldNames
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
	if name == "txn" || name == "gtxn" || name == "gtxns" || name == "itxn" || name == "gitxn" || name == "itxn_field" {
		return typeString(logic.TxnFieldTypes)
	}
	if name == "global" {
		return typeString(logic.GlobalFieldTypes)
	}
	if name == "txna" || name == "gtxna" || name == "gtxnsa" || name == "txnas" || name == "gtxnas" || name == "gtxnsas" || name == "itxna" || name == "gitxna" {
		return typeString(logic.TxnaFieldTypes())
	}
	if name == "asset_holding_get" {
		return typeString(logic.AssetHoldingFieldTypes)
	}
	if name == "asset_params_get" {
		return typeString(logic.AssetParamsFieldTypes)
	}
	if name == "app_params_get" {
		return typeString(logic.AppParamsFieldTypes)
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
	for grp, names := range logic.OpGroups {
		fname := fmt.Sprintf("%s.md", grp)
		fname = strings.ReplaceAll(fname, " ", "_")
		fout, _ := os.Create(fname)
		opGroupMarkdownTable(names, fout)
		fout.Close()
		for _, opname := range names {
			opGroups[opname] = append(opGroups[opname], grp)
		}
	}
	constants, _ := os.Create("named_integer_constants.md")
	integerConstantsTableMarkdown(constants)
	constants.Close()

	txnfields, _ := os.Create("txn_fields.md")
	fieldSpecsMarkdown(txnfields, logic.TxnFieldNames, logic.TxnFieldSpecByName)
	txnfields.Close()

	globalfields, _ := os.Create("global_fields.md")
	fieldSpecsMarkdown(globalfields, logic.GlobalFieldNames, logic.GlobalFieldSpecByName)
	globalfields.Close()

	assetholding, _ := os.Create("asset_holding_fields.md")
	fieldSpecsMarkdown(assetholding, logic.AssetHoldingFieldNames, logic.AssetHoldingFieldSpecByName)
	assetholding.Close()

	assetparams, _ := os.Create("asset_params_fields.md")
	fieldSpecsMarkdown(assetparams, logic.AssetParamsFieldNames, logic.AssetParamsFieldSpecByName)
	assetparams.Close()

	appparams, _ := os.Create("app_params_fields.md")
	fieldSpecsMarkdown(appparams, logic.AppParamsFieldNames, logic.AppParamsFieldSpecByName)
	appparams.Close()

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
