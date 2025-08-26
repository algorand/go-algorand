// Copyright (C) 2019-2025 Algorand, Inc.
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
	"math"
	"os"
	"sort"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// OpImmediateNote returns a short string about immediate data which follows the op byte
func opImmediateNoteSyntaxMarkdown(name string, oids []logic.OpImmediateDetails) string {
	if len(oids) == 0 {
		return ""
	}

	argNames := make([]string, len(oids))
	argDocs := make([]string, len(oids))
	for idx, oid := range oids {
		argNote := oid.Comment
		if oid.Reference != "" {
			argNote = fmt.Sprintf("[%s](#field-group-%s)", oid.Reference, strings.ToLower(oid.Reference))
		}
		argNames[idx] = oid.Name
		argDocs[idx] = fmt.Sprintf("%s: %s", oid.Name, argNote)
	}

	return fmt.Sprintf("`%s %s` where %s", name, strings.Join(argNames, " "), strings.Join(argDocs, ", "))
}

func opImmediateNoteEncoding(opcode byte, oids []logic.OpImmediateDetails) string {
	if len(oids) == 0 {
		return fmt.Sprintf("0x%02x", opcode)
	}

	notes := make([]string, len(oids))
	for idx, oid := range oids {
		notes[idx] = oid.Encoding
	}
	return fmt.Sprintf("0x%02x {%s}", opcode, strings.Join(notes, "}, {"))
}

func opGroupMarkdownTable(names []string, out io.Writer, version uint64) {
	fmt.Fprint(out, `| Opcode | Description |
| - | -- |
`)
	opSpecs := logic.OpsByName[version]
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

func namedStackTypesMarkdown(out io.Writer, stackTypes []namedType) {
	fmt.Fprintf(out, "#### Definitions\n\n")
	fmt.Fprintf(out, "| Name | Bound | AVM Type |\n")
	fmt.Fprintf(out, "| ---- | ---- | -------- |\n")

	for _, st := range stackTypes {
		fmt.Fprintf(out, "| %s | %s | %s |\n", st.Name, st.boundString(), st.AVMType)
	}
	fmt.Fprintf(out, "\n")
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

func fieldGroupMarkdown(out io.Writer, group *logic.FieldGroup, version uint64) {
	showTypes := false
	showVers := false
	opVer := uint64(math.MaxUint64)
	for _, name := range group.Names {
		spec, ok := group.SpecByName(name)
		// reminder: group.Names can be "sparse" See: logic.TxnaFields
		if !ok || spec.Version() > version {
			continue
		}
		if spec.Type().Typed() {
			showTypes = true
		}
		if opVer == math.MaxUint64 {
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
		if !ok || spec.Version() > version {
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

func opToMarkdown(out io.Writer, op *logic.OpSpec, groupDocWritten map[string]bool, version uint64) (err error) {

	deets := logic.OpImmediateDetailsFromSpec(*op)

	// Only need syntax line if there are immediates
	// so it carries its own newline
	syntax := ""
	if opSyntax := opImmediateNoteSyntaxMarkdown(op.Name, deets); opSyntax != "" {
		syntax = fmt.Sprintf("- Syntax: %s\n", opSyntax)
	}

	encoding := fmt.Sprintf("- Bytecode: %s", opImmediateNoteEncoding(op.Opcode, deets))

	stackEffects := stackMarkdown(op)

	fmt.Fprintf(out, "\n## %s\n\n%s%s\n%s", op.Name, syntax, encoding, stackEffects)

	fmt.Fprintf(out, "- %s\n", logic.OpDoc(op.Name))
	cost := op.DocCost(version)
	if cost != "1" {
		fmt.Fprintf(out, "- **Cost**: %s\n", cost)
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
			fmt.Fprintf(out, "\n### %s\n\n%s\n\n", group.Name, group.Doc)
			fieldGroupMarkdown(out, group, version)
			groupDocWritten[group.Name] = true
		}
	}
	ode := logic.OpDocExtra(op.Name)
	if ode != "" {
		fmt.Fprintf(out, "\n%s\n", ode)
	}
	return nil
}

func opsToMarkdown(out io.Writer, version uint64) error {
	_, err := out.Write([]byte(fmt.Sprintf("# v%d Opcodes\n\nOps have a 'cost' of 1 unless otherwise specified.\n\n", version)))
	if err != nil {
		return err
	}
	opSpecs := logic.OpcodesByVersion(version)
	written := make(map[string]bool)
	for i := range opSpecs {
		err := opToMarkdown(out, &opSpecs[i], written, version)
		if err != nil {
			return err
		}
	}
	return nil
}

// OpRecord is a consolidated record of things about an Op
type OpRecord struct {
	Opcode  byte
	Name    string
	Args    []string `json:",omitempty"`
	Returns []string `json:",omitempty"`
	Size    int

	ArgEnum      []string `json:",omitempty"`
	ArgEnumTypes []string `json:",omitempty"`

	DocCost string

	Doc               string
	DocExtra          string                     `json:",omitempty"`
	ImmediateNote     []logic.OpImmediateDetails `json:",omitempty"`
	IntroducedVersion uint64
	Groups            []string
}

type namedType struct {
	Name         string
	Abbreviation string
	Bound        []uint64
	AVMType      string
}

func (nt namedType) boundString() string {
	if nt.Bound[0] == 0 && nt.Bound[1] == 0 {
		return ""
	}

	val := "x"
	// if its bytes, the length is bounded
	if nt.AVMType == "[]byte" {
		val = "len(x)"
	}

	// If they're equal, the val should match exactly
	if nt.Bound[0] > 0 && nt.Bound[0] == nt.Bound[1] {
		return fmt.Sprintf("%s == %d", val, nt.Bound[0])
	}

	// otherwise, provide min/max bounds as lte expression
	minBound, maxBound := "", ""
	if nt.Bound[0] > 0 {
		minBound = fmt.Sprintf("%d <= ", nt.Bound[0])
	}
	if nt.Bound[1] > 0 {
		maxBound = fmt.Sprintf(" <= %d", nt.Bound[1])
	}

	return fmt.Sprintf("%s%s%s", minBound, val, maxBound)

}

// LanguageSpec records the ops of the language at some version
type LanguageSpec struct {
	Version         uint64
	LogicSigVersion uint64
	NamedTypes      []namedType
	Ops             []OpRecord
}

func typeStrings(types logic.StackTypes) []string {
	out := make([]string, len(types))
	allNones := true
	for idx, t := range types {
		out[idx] = t.String()
		if out[idx] != "none" {
			allNones = false
		}
	}

	// If all the types are none, we just return
	// an empty array, otherwise leave the nones
	// in so we don't break the indices by omitting
	// a valid none in a fields array
	if allNones {
		return nil
	}

	return out
}

func fieldsAndTypes(group logic.FieldGroup, version uint64) ([]string, []string) {
	// reminder: group.Names can be "sparse" See: logic.TxnaFields
	fields := make([]string, 0, len(group.Names))
	types := make([]logic.StackType, 0, len(group.Names))
	for _, name := range group.Names {
		if spec, ok := group.SpecByName(name); ok && spec.Version() <= version {
			fields = append(fields, name)
			types = append(types, spec.Type())
		}
	}
	return fields, typeStrings(types)
}

func argEnums(name string, version uint64) ([]string, []string) {
	// reminder: this needs to be manually updated every time
	// a new opcode is added with an associated FieldGroup
	// it'd be nice to have this auto-update
	switch name {
	case "txn", "gtxn", "gtxns", "itxn", "gitxn":
		return fieldsAndTypes(logic.TxnFields, version)
	case "itxn_field":
		// itxn_field does not *return* a type depending on its immediate. It *takes* it.
		// but until a consumer cares, ArgEnumTypes will be overloaded for that meaning.
		return fieldsAndTypes(logic.ItxnSettableFields, version)
	case "global":
		return fieldsAndTypes(logic.GlobalFields, version)
	case "txna", "gtxna", "gtxnsa", "txnas", "gtxnas", "gtxnsas", "itxna", "gitxna":
		return fieldsAndTypes(logic.TxnArrayFields, version)
	case "asset_holding_get":
		return fieldsAndTypes(logic.AssetHoldingFields, version)
	case "asset_params_get":
		return fieldsAndTypes(logic.AssetParamsFields, version)
	case "app_params_get":
		return fieldsAndTypes(logic.AppParamsFields, version)
	case "acct_params_get":
		return fieldsAndTypes(logic.AcctParamsFields, version)
	case "block":
		return fieldsAndTypes(logic.BlockFields, version)
	case "json_ref":
		return fieldsAndTypes(logic.JSONRefTypes, version)
	case "base64_decode":
		return fieldsAndTypes(logic.Base64Encodings, version)
	case "vrf_verify":
		return fieldsAndTypes(logic.VrfStandards, version)
	case "ecdsa_pk_recover", "ecdsa_verify", "ecdsa_pk_decompress":
		return fieldsAndTypes(logic.EcdsaCurves, version)
	default:
		return nil, nil
	}
}

func buildLanguageSpec(opGroups map[string][]string, namedTypes []namedType, version uint64) *LanguageSpec {
	opSpecs := logic.OpcodesByVersion(version)
	records := make([]OpRecord, len(opSpecs))
	for i, spec := range opSpecs {
		records[i].Opcode = spec.Opcode
		records[i].Name = spec.Name
		records[i].Args = typeStrings(spec.Arg.Types)
		records[i].Returns = typeStrings(spec.Return.Types)
		records[i].Size = spec.OpDetails.Size
		records[i].DocCost = spec.DocCost(version)
		records[i].ArgEnum, records[i].ArgEnumTypes = argEnums(spec.Name, version)
		records[i].Doc = strings.ReplaceAll(logic.OpDoc(spec.Name), "<br />", "\n")
		records[i].DocExtra = logic.OpDocExtra(spec.Name)
		records[i].ImmediateNote = logic.OpImmediateDetailsFromSpec(spec)
		records[i].Groups = opGroups[spec.Name]
		records[i].IntroducedVersion = spec.Version
	}

	return &LanguageSpec{
		Version:         version,
		LogicSigVersion: config.Consensus[protocol.ConsensusCurrentVersion].LogicSigVersion,
		NamedTypes:      namedTypes,
		Ops:             records,
	}
}

func create(file string) *os.File {
	f, err := os.Create(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create '%s': %v\n", file, err)
		os.Exit(1)
	}
	return f
}

func main() {
	const docVersion = uint64(12)

	opGroups := make(map[string][]string, len(logic.OpSpecs))
	for grp, names := range logic.OpGroups {
		fname := fmt.Sprintf("%s.md", grp)
		fname = strings.ReplaceAll(fname, " ", "_")
		fout := create(fname)
		opGroupMarkdownTable(names, fout, docVersion)
		fout.Close()
		for _, opname := range names {
			opGroups[opname] = append(opGroups[opname], grp)
		}
	}

	named := make([]namedType, 0, len(logic.AllStackTypes))
	for abbr, t := range logic.AllStackTypes {
		named = append(named, namedType{
			Name:         t.String(),
			Bound:        []uint64{t.Bound[0], t.Bound[1]},
			Abbreviation: string(abbr),
			AVMType:      t.AVMType.String(),
		})
	}
	sort.Slice(named, func(i, j int) bool { return named[i].Name < named[j].Name })

	constants := create("named_integer_constants.md")
	integerConstantsTableMarkdown(constants)
	constants.Close()

	namedStackTypes := create("named_stack_types.md")
	namedStackTypesMarkdown(namedStackTypes, named)
	namedStackTypes.Close()

	written := make(map[string]bool)
	opSpecs := logic.OpcodesByVersion(uint64(docVersion))
	for _, spec := range opSpecs {
		for _, imm := range spec.OpDetails.Immediates {
			if imm.Group != nil && !written[imm.Group.Name] {
				out := create(strings.ToLower(imm.Group.Name) + "_fields.md")
				fieldGroupMarkdown(out, imm.Group, docVersion)
				out.Close()
				written[imm.Group.Name] = true
			}
		}
	}

	tealtm := create("teal.tmLanguage.json")
	enc := json.NewEncoder(tealtm)
	enc.SetIndent("", "  ")
	if err := enc.Encode(buildSyntaxHighlight(docVersion)); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding teal.tmLanguage.json: % v\n", err)
		os.Exit(1)
	}
	tealtm.Close()

	for v := uint64(1); v <= docVersion; v++ {
		langspecjs := create(fmt.Sprintf("langspec_v%d.json", v))
		enc := json.NewEncoder(langspecjs)
		enc.SetIndent("", "  ")
		if err := enc.Encode(buildLanguageSpec(opGroups, named, v)); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding langspec JSON for version %d: %v\n", v, err)
			os.Exit(1)
		}
		langspecjs.Close()

		opcodesMd := create(fmt.Sprintf("TEAL_opcodes_v%d.md", v))
		if err := opsToMarkdown(opcodesMd, v); err != nil {
			fmt.Fprintf(os.Stderr, "error creating markdown for version %d: %v\n", v, err)
			os.Exit(1)
		}
		opcodesMd.Close()
	}
}
