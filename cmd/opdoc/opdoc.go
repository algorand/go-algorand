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

var docVersion = 8

func opGroupMarkdownTable(names []string, out io.Writer) {
	fmt.Fprint(out, `| Opcode | Description |
| - | -- |
`)
	opSpecs := logic.OpsByName[docVersion]
	for _, opname := range names {
		spec, ok := opSpecs[opname]
		if !ok {
			continue // Allows "future" opcodes to exist, but be omitted from spec.
		}
		fmt.Fprintf(out, "| `%s%s` | %s |\n",
			markdownTableEscape(spec.Name), immediateMarkdown(&spec),
			markdownTableEscape(logic.OpDoc(opname)))
	}
}

func markdownTableEscape(x string) string {
	return strings.ReplaceAll(x, "|", "\\|")
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

func fieldGroupMarkdown(out io.Writer, group *logic.FieldGroup) {
	showTypes := false
	showVers := false
	opVer := uint64(0)
	for _, name := range group.Names {
		spec, ok := group.SpecByName(name)
		// reminder: group.Names can be "sparse" See: logic.TxnaFields
		if !ok {
			continue
		}
		if spec.Type().Typed() {
			showTypes = true
		}
		if opVer == uint64(0) {
			opVer = spec.Version()
		} else if opVer != spec.Version() {
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
	fmt.Fprint(out, headers, widths)
	for i, name := range group.Names {
		spec, ok := group.SpecByName(name)
		if !ok {
			continue
		}
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
	fmt.Fprint(out, "\n")
}

func immediateMarkdown(op *logic.OpSpec) string {
	markdown := ""
	for _, imm := range op.OpDetails.Immediates {
		markdown = markdown + " " + imm.Name
	}
	return markdown
}

func stackMarkdown(op *logic.OpSpec) string {
	out := "- Stack: "

	out += "..."
	if op.Arg.Effects != "" {
		out += ", " + op.Arg.Effects
	} else {
		for i, v := range op.Arg.Types {
			out += fmt.Sprintf(", %c", rune(int('A')+i))
			if v.Typed() {
				out += fmt.Sprintf(": %s", v)
			}
		}
	}

	if op.AlwaysExits() {
		return out + " &rarr; _exits_\n"
	}

	out += " &rarr; ..."
	if op.Return.Effects != "" {
		out += ", " + op.Return.Effects
	} else {
		for i, rt := range op.Return.Types {
			out += ", "
			if len(op.Return.Types) > 1 {
				start := int('X')
				if len(op.Return.Types) > 3 {
					start = int('Z') + 1 - len(op.Return.Types)
				}
				out += fmt.Sprintf("%c: ", rune(start+i))
			}
			out += rt.String()
		}
	}
	return out + "\n"
}

func opToMarkdown(out io.Writer, op *logic.OpSpec, groupDocWritten map[string]bool) (err error) {
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
				fmt.Fprintf(out, "    - %s (v%d)\n", cost.Cost, cost.To)
			} else {
				if cost.To < docVersion {
					fmt.Fprintf(out, "    - %s (v%d - v%d)\n", cost.Cost, cost.From, cost.To)
				} else {
					fmt.Fprintf(out, "    - %s (since v%d)\n", cost.Cost, cost.From)
				}
			}
		}
	} else {
		cost := costs[0].Cost
		if cost != "1" {
			fmt.Fprintf(out, "- **Cost**: %s\n", cost)
		}
	}
	if op.Version > 1 {
		fmt.Fprintf(out, "- Availability: v%d\n", op.Version)
	}
	if !op.Modes.Any() {
		fmt.Fprintf(out, "- Mode: %s\n", op.Modes)
	}

	for i := range op.OpDetails.Immediates {
		group := op.OpDetails.Immediates[i].Group
		if group != nil && group.Doc != "" && !groupDocWritten[group.Name] {
			fmt.Fprintf(out, "\n`%s` %s:\n\n", group.Name, group.Doc)
			fieldGroupMarkdown(out, group)
			groupDocWritten[group.Name] = true
		}
	}
	ode := logic.OpDocExtra(op.Name)
	if ode != "" {
		fmt.Fprintf(out, "\n%s\n", ode)
	}
	return nil
}

func opsToMarkdown(out io.Writer) (err error) {
	out.Write([]byte("# Opcodes\n\nOps have a 'cost' of 1 unless otherwise specified.\n\n"))
	opSpecs := logic.OpcodesByVersion(uint64(docVersion))
	written := make(map[string]bool)
	for _, spec := range opSpecs {
		err = opToMarkdown(out, &spec, written)
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

func fieldsAndTypes(group logic.FieldGroup) ([]string, string) {
	// reminder: group.Names can be "sparse" See: logic.TxnaFields
	fields := make([]string, 0, len(group.Names))
	types := make([]logic.StackType, 0, len(group.Names))
	for _, name := range group.Names {
		if spec, ok := group.SpecByName(name); ok {
			fields = append(fields, name)
			types = append(types, spec.Type())
		}
	}
	return fields, typeString(types)
}

func argEnums(name string) ([]string, string) {
	switch name {
	case "txn", "gtxn", "gtxns", "itxn", "gitxn":
		return fieldsAndTypes(logic.TxnFields)
	case "itxn_field":
		// itxn_field does not *return* a type depending on its immediate. It *takes* it.
		// but until a consumer cares, ArgEnumTypes will be overloaded for that meaning.
		return fieldsAndTypes(logic.ItxnSettableFields)
	case "global":
		return fieldsAndTypes(logic.GlobalFields)
	case "txna", "gtxna", "gtxnsa", "txnas", "gtxnas", "gtxnsas", "itxna", "gitxna":
		return fieldsAndTypes(logic.TxnArrayFields)
	case "asset_holding_get":
		return fieldsAndTypes(logic.AssetHoldingFields)
	case "asset_params_get":
		return fieldsAndTypes(logic.AssetParamsFields)
	case "app_params_get":
		return fieldsAndTypes(logic.AppParamsFields)
	case "acct_params_get":
		return fieldsAndTypes(logic.AcctParamsFields)
	default:
		return nil, ""
	}
}

func buildLanguageSpec(opGroups map[string][]string) *LanguageSpec {
	opSpecs := logic.OpcodesByVersion(uint64(docVersion))
	records := make([]OpRecord, len(opSpecs))
	for i, spec := range opSpecs {
		records[i].Opcode = spec.Opcode
		records[i].Name = spec.Name
		records[i].Args = typeString(spec.Arg.Types)
		records[i].Returns = typeString(spec.Return.Types)
		records[i].Size = spec.OpDetails.Size
		records[i].ArgEnum, records[i].ArgEnumTypes = argEnums(spec.Name)
		records[i].Doc = strings.ReplaceAll(logic.OpDoc(spec.Name), "<br />", "\n")
		records[i].DocExtra = logic.OpDocExtra(spec.Name)
		records[i].ImmediateNote = logic.OpImmediateNote(spec.Name)
		records[i].Groups = opGroups[spec.Name]
	}
	return &LanguageSpec{
		EvalMaxVersion:  docVersion,
		LogicSigVersion: config.Consensus[protocol.ConsensusCurrentVersion].LogicSigVersion,
		Ops:             records,
	}
}

func create(file string) *os.File {
	f, err := os.Create(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create '%s': %v", file, err)
		os.Exit(1)
	}
	return f
}

func main() {
	opcodesMd := create("TEAL_opcodes.md")
	opsToMarkdown(opcodesMd)
	opcodesMd.Close()
	opGroups := make(map[string][]string, len(logic.OpSpecs))
	for grp, names := range logic.OpGroups {
		fname := fmt.Sprintf("%s.md", grp)
		fname = strings.ReplaceAll(fname, " ", "_")
		fout := create(fname)
		opGroupMarkdownTable(names, fout)
		fout.Close()
		for _, opname := range names {
			opGroups[opname] = append(opGroups[opname], grp)
		}
	}
	constants := create("named_integer_constants.md")
	integerConstantsTableMarkdown(constants)
	constants.Close()

	written := make(map[string]bool)
	opSpecs := logic.OpcodesByVersion(uint64(docVersion))
	for _, spec := range opSpecs {
		for _, imm := range spec.OpDetails.Immediates {
			if imm.Group != nil && !written[imm.Group.Name] {
				out := create(strings.ToLower(imm.Group.Name) + "_fields.md")
				fieldGroupMarkdown(out, imm.Group)
				out.Close()
				written[imm.Group.Name] = true
			}
		}
	}

	langspecjs := create("langspec.json")
	enc := json.NewEncoder(langspecjs)
	enc.SetIndent("", "  ")
	enc.Encode(buildLanguageSpec(opGroups))
	langspecjs.Close()

	tealtm := create("teal.tmLanguage.json")
	enc = json.NewEncoder(tealtm)
	enc.SetIndent("", "  ")
	enc.Encode(buildSyntaxHighlight())
	tealtm.Close()
}
