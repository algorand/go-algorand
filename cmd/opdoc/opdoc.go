// Copyright (C) 2019-2023 Algorand, Inc.
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
		if spec.StackType().Typed() {
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
			str = fmt.Sprintf("%s | %s", str, markdownTableEscape(spec.StackType().String()))
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
	Opcode  byte `json:",omitempty"`
	Name    string
	Args    []string `json:",omitempty"`
	Returns []string `json:",omitempty"`
	Size    int

	ArgEnum string `json:",omitempty"`

	Doc               string   `json:",omitempty"`
	DocExtra          string   `json:",omitempty"`
	ImmediateNote     string   `json:",omitempty"`
	IntroducedVersion uint64   `json:",omitempty"`
	Groups            []string `json:",omitempty"`
}

// StackTypeSpec type is the definition of a higher level type with
// bounds specified
type StackTypeSpec struct {
	Type        string    `json:",omitempty"`
	LengthBound [2]uint64 `json:",omitempty"`
	ValueBound  [2]uint64 `json:",omitempty"` // TODO: does this convert maxuint to a string? (no)
}

// Keyword is a keyword from the Field Groups passed to an op
type Keyword struct {
	Name    string `json:",omitempty"`
	Type    string `json:",omitempty"`
	Note    string `json:",omitempty"`
	Version uint64 `json:",omitempty"`
	Value   uint64
}

// LanguageSpec records the ops of the language at some version
type LanguageSpec struct {
	EvalMaxVersion  int
	LogicSigVersion uint64
	StackTypes      map[string]StackTypeSpec
	Fields          map[string][]Keyword
	PseudoOps       []OpRecord
	Ops             []OpRecord
}

func stackTypes(types []logic.StackType) []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = t.String()
	}
	return out
}

func typeByte(t logic.StackType) byte {
	switch t.AVMType {
	case logic.AVMUint64:
		return 'U'
	case logic.AVMBytes:
		return 'B'
	case logic.AVMAny:
		return '.'
	case logic.AVMNone:
		return '_'
	default:
		panic("unexpected type in opdoc typeString")
	}
}

func groupKeywords(group logic.FieldGroup) []Keyword {
	keywords := make([]Keyword, 0, len(group.Names))
	for _, name := range group.Names {
		if spec, ok := group.SpecByName(name); ok {
			// TODO: replace tstring with something better
			kw := Keyword{
				Name:    name,
				Value:   uint64(spec.Field()),
				Type:    spec.StackType().String(),
				Note:    spec.Note(),
				Version: spec.Version(),
			}
			keywords = append(keywords, kw)
		}
	}
	return keywords
}

func argEnums(name string) string {
	switch name {
	case "txn", "gtxn", "gtxns", "gitxn":
		return "txn"
	case "itxn_field", "itxn":
		return "itxn_field"
	case "global":
		return "global"
	case "txna", "gtxna", "gtxnsa", "txnas", "gtxnas", "gtxnsas", "itxna", "gitxna":
		return "txna"
	case "asset_holding_get":
		return "asset_holding"
	case "asset_params_get":
		return "asset_params"
	case "app_params_get":
		return "app_params"
	case "acct_params_get":
		return "acct_params"
	case "block":
		return "block"
	case "json_ref":
		return "json_ref"
	case "base64_decode":
		return "base64"
	case "vrf_verify":
		return "vrf_verify"
	case "ecdsa_pk_recover", "ecdsa_verify", "ecdsa_pk_decompress":
		return "ECDSA"
	default:
		return ""
	}
}

func fieldGroups() []logic.FieldGroup {
	return []logic.FieldGroup{
		logic.TxnFields,
		logic.TxnScalarFields,
		logic.TxnArrayFields,
		logic.ItxnSettableFields,
		logic.GlobalFields,
		logic.AssetHoldingFields,
		logic.AssetParamsFields,
		logic.AppParamsFields,
		logic.AcctParamsFields,
		logic.BlockFields,
		logic.JSONRefTypes,
		logic.Base64Encodings,
		logic.VrfStandards,
		logic.EcdsaCurves,
	}

}

func onCompleteKeywords() []Keyword {
	var ocs []Keyword
	for _, ocn := range logic.OnCompletionNames {
		// TODO: add Value/Doc
		ocs = append(ocs, Keyword{Name: ocn, Type: "uint64"})
	}
	return ocs
}

func txnTypeKeywords() []Keyword {
	var txTypes []Keyword
	for idx, n := range logic.TxnTypeNames {
		doc := logic.TypeNameDescriptions[n]
		txTypes = append(txTypes, Keyword{Name: n, Type: "uint64", Note: doc, Value: uint64(idx)})
	}
	return txTypes
}

func itxnTypeKeywords() []Keyword {
	var itxTypes []Keyword
	for idx, name := range logic.TxnTypeNames {
		version := logic.InnerTxnTypes[name]
		doc := logic.TypeNameDescriptions[name]
		itxTypes = append(itxTypes, Keyword{Name: name, Type: "uint64", Version: version, Note: doc, Value: uint64(idx)})
	}
	return itxTypes
}

func buildLanguageSpec(opGroups map[string][]string) *LanguageSpec {
	opSpecs := logic.OpcodesByVersion(uint64(docVersion))
	records := make([]OpRecord, len(opSpecs))

	keywords := map[string][]Keyword{}
	for _, fg := range fieldGroups() {
		keywords[fg.Name] = groupKeywords(fg)
	}

	allStackTypes := map[string]StackTypeSpec{}
	for _, st := range logic.AllStackTypes {
		allStackTypes[st.String()] = StackTypeSpec{
			Type:        string(typeByte(st)),
			LengthBound: st.LengthBound,
			ValueBound:  st.ValueBound,
		}
	}

	keywords["txn_type"] = txnTypeKeywords()
	keywords["itxn_type"] = itxnTypeKeywords()
	keywords["on_complete"] = onCompleteKeywords()

	for i, spec := range opSpecs {
		records[i].Opcode = spec.Opcode
		records[i].Name = spec.Name
		records[i].Args = stackTypes(spec.Arg.Types)
		records[i].Returns = stackTypes(spec.Return.Types)
		records[i].Size = spec.OpDetails.Size
		records[i].ArgEnum = argEnums(spec.Name)
		records[i].Doc = strings.ReplaceAll(logic.OpDoc(spec.Name), "<br />", "\n")
		records[i].DocExtra = logic.OpDocExtra(spec.Name)
		records[i].ImmediateNote = logic.OpImmediateNote(spec.Name)
		records[i].Groups = opGroups[spec.Name]
		records[i].IntroducedVersion = spec.Version
	}

	var pseudoOps = make([]OpRecord, len(logic.PseudoOps))
	for i, spec := range logic.PseudoOps {
		pseudoOps[i].Name = spec.Name
		pseudoOps[i].Args = stackTypes(spec.Arg.Types)
		pseudoOps[i].Returns = stackTypes(spec.Return.Types)
		pseudoOps[i].Size = spec.OpDetails.Size
		pseudoOps[i].ArgEnum = argEnums(spec.Name)
		pseudoOps[i].Doc = strings.ReplaceAll(logic.OpDoc(spec.Name), "<br />", "\n")
		pseudoOps[i].DocExtra = logic.OpDocExtra(spec.Name)
		pseudoOps[i].ImmediateNote = logic.OpImmediateNote(spec.Name)
		pseudoOps[i].Groups = opGroups[spec.Name]
		pseudoOps[i].IntroducedVersion = spec.Version
	}

	return &LanguageSpec{
		EvalMaxVersion:  docVersion,
		LogicSigVersion: config.Consensus[protocol.ConsensusCurrentVersion].LogicSigVersion,
		StackTypes:      allStackTypes,
		Fields:          keywords,
		PseudoOps:       pseudoOps,
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
