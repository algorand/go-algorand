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

//go:build ignore

package main

import (
	"fmt"
	"go/format"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/algorand/go-algorand/agreement"
)

// staticItem represents one entry in the static table.
type staticItem struct {
	ConstName string // e.g. "staticIdxPsField"
	Index     uint8
	Data      []byte
	Comment   string
}

// specialPattern is used to generate code snippets in createGeneratedStaticTable()
// that do more complex expansions (like all-zero or numeric-value appends).
type specialPattern struct {
	Code string // e.g. "zeroField := append(...) ; t[staticIdxAllZeroPsField] = zeroField"
}

// codeGenerator is our main driver for reflection + generating code via templates.
type codeGenerator struct {
	baseMapIndex    uint8
	nextIndex       uint8
	items           []staticItem
	specialPatterns []specialPattern

	parseFns         map[reflect.Type]bool
	parseFuncDataMap map[reflect.Type]parseFuncData
}

// parseFuncData is used to render one parse function from the parseFuncTemplate.
type parseFuncData struct {
	TypeName      string
	CodecName     string
	MaxFieldCount int
	FixedSize     int // If > 0, indicates a fixed size from vpack_assert_size tag
	Fields        []fieldData
}

// fieldData describes one field in the struct for parse code generation.
type fieldData struct {
	CodecName      string // e.g. "ps", "step", "data"
	FieldNameConst string // e.g. "staticIdxPsField"

	IsSubStruct   bool
	SubStructName string

	ArrayLen     int
	IsLiteral    bool
	IsZeroCheck  bool   // e.g. "0" special for a binary field
	ZeroConst    string // e.g. "staticIdxAllZeroDataField"
	VpackSpecial string // e.g. "1,2,3" for numeric

	IsUint64Alias bool
}

// fileHeaderTemplate sets up createGeneratedStaticTable and includes expansions
// from specialPatterns.
const fileHeaderTemplate = `
// createGeneratedStaticTable initializes the static table with common msgpack patterns
func createGeneratedStaticTable() [][]byte {
	t := make([][]byte, 256)

	// Basic entries
{{- range .Items}}
	t[{{.ConstName}}] = []byte{
  {{- range $i, $b := .Data}}
  {{- if $i}},{{end}}
  {{- if eq $i 0 -}}
    0x{{printf "%02x" $b}}
  {{- else -}}
    '{{printf "%c" $b}}'
  {{- end}}
{{- end -}} }
{{- if .Comment}} // {{.Comment}}{{end}}
{{- end}}

	// Special expansions
{{- range .SpecialPatterns}}
	{{.Code}}
{{- end}}

	return t
}
`

// constBlockTemplate emits the "const (...)" block for all static indices
const constBlockTemplate = `
const (
{{- range .Items}}
	{{.ConstName}} uint8 = 0x{{printf "%02x" .Index}}
{{- end}}

	// Constants for static index range bounds
	staticIdxStart uint8 = 0x{{printf "%02x" .StaticIdxStart}}
	staticIdxEnd uint8 = 0x{{printf "%02x" .StaticIdxEnd}}
)

var staticTable = createGeneratedStaticTable()
`

const parseFuncHeader = `
func parseVote(data []byte, c compressWriter) error {
    p := newParser(data)
`

const parseFuncFooter = `
	// Check for trailing bytes
	if p.pos < len(p.data) {
		return fmt.Errorf("unexpected trailing data: %d bytes remain unprocessed", len(p.data) - p.pos)
	}

	return nil
}
`

// parseFuncTemplate decodes a struct encoded as a map.
// It calls `makeNumericConst` for special integer values in a top-level FuncMap.
const parseFuncTemplate = `{{if gt .FixedSize 0}}
	// Fixed size struct with {{.FixedSize}} fields
	cnt, err := p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for {{.TypeName}}: %w", err)
	}
	if cnt != {{.FixedSize}} {
		return fmt.Errorf("expected fixed map size {{.FixedSize}} for {{.TypeName}}, got %d", cnt)
	}
	c.writeStatic(staticIdxMapMarker{{.FixedSize}})

	for range {{.FixedSize}} {
{{else}}
	// Variable size struct
	cnt, err := p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for {{.TypeName}}: %w", err)
	}
	if cnt < 1 || cnt > {{.MaxFieldCount}} {
		return fmt.Errorf("expected fixmap size for {{.TypeName}} 1 <= cnt <= {{.MaxFieldCount}}, got %d", cnt)
	}
	c.writeStatic(staticIdxMapMarker0+cnt)

	for range cnt {
{{end}}
		key, err := p.readString()
		if err != nil {
			return fmt.Errorf("reading key for {{.TypeName}}: %w", err)
		}

		switch string(key) {
{{- /* We define a field-level range, then a nested range if .VpackSpecial is non-empty. */}}
{{- range $fd := .Fields}}
		case "{{$fd.CodecName}}":
  {{- if $fd.IsSubStruct}}
			c.writeStatic({{$fd.FieldNameConst}})
			{{renderParseFunction $fd.SubStructName}}
  {{- else if $fd.IsUint64Alias}}
			valBytes, err := p.readUintBytes()
			if err != nil {
				return fmt.Errorf("reading {{$fd.CodecName}}: %w", err)
			}
	{{- if $fd.VpackSpecial}}
			// If we have special single-byte numeric values
			if len(valBytes) == 1 {
				switch valBytes[0] {
				{{- $vals := split $fd.VpackSpecial ","}}
	  {{- range $v := $vals}}
				case {{.}}:
					c.writeStatic({{makeNumericConst $fd.CodecName .}})
					continue
	  {{- end}}
				}
			}
	{{end}}
			if err := c.writeDynamicVaruint({{$fd.FieldNameConst}}, valBytes); err != nil {
				return fmt.Errorf("writing {{$fd.CodecName}}: %w", err)
			}
  {{- else if gt $fd.ArrayLen 0}}
			val, err := p.readBin{{$fd.ArrayLen}}()
			if err != nil {
				return fmt.Errorf("reading {{$fd.CodecName}}: %w", err)
			}
	{{- if $fd.IsZeroCheck}}
			if val == [{{$fd.ArrayLen}}]byte{} {
				c.writeStatic({{$fd.ZeroConst}})
			} else {
				c.writeLiteralBin{{$fd.ArrayLen}}({{$fd.FieldNameConst}}, val)
			}
	{{- else if $fd.IsLiteral}}
			c.writeLiteralBin{{$fd.ArrayLen}}({{$fd.FieldNameConst}}, val)
	{{- else}}
			c.writeDynamicBin{{$fd.ArrayLen}}({{$fd.FieldNameConst}}, val)
	{{- end}}
  {{- else}}
			// this means the struct has a field not supported by this code generator
			return fmt.Errorf("unhandled field type for {{$fd.CodecName}} in {{$.TypeName}}")
  {{- end}}
{{- end}}
		default:
			return fmt.Errorf("unexpected field in {{.TypeName}}: %q", key)
		}
	}
`

func main() {
	gen := newCodeGenerator(0xd0, 0xc0)
	err := gen.generate(reflect.TypeOf(agreement.UnauthenticatedVote{}))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newCodeGenerator sets up a generator with a chosen starting index.
func newCodeGenerator(startIdx, baseMapIdx uint8) *codeGenerator {
	return &codeGenerator{
		baseMapIndex:     baseMapIdx,
		nextIndex:        startIdx,
		parseFns:         make(map[reflect.Type]bool),
		parseFuncDataMap: make(map[reflect.Type]parseFuncData),
	}
}

// generate orchestrates the reflection + template usage
func (g *codeGenerator) generate(root reflect.Type) error {
	// Recursively gather parse logic for root
	if err := g.analyzeType(root); err != nil {
		return err
	}

	// Also define map-marker constants for 1..6
	// We don't need more than this, and an error will be thrown if a
	// field grows beyond 6 items.
	for i := 0; i <= 6; i++ {
		g.getOrCreateMapMarkerIndex(i)
	}

	// Render the const block
	constCode, err := g.renderConstBlock()
	if err != nil {
		return fmt.Errorf("rendering const block: %w", err)
	}

	// Render parse functions
	parseCode, err := g.renderParseFunction("unauthenticatedVote")
	if err != nil {
		return fmt.Errorf("rendering parse functions: %w", err)
	}

	// Render file header (the createGeneratedStaticTable + expansions)
	fileHeader, err := g.renderFileHeader()
	if err != nil {
		return fmt.Errorf("rendering file header: %w", err)
	}

	const hdr = `
// Code generated by gen.go; DO NOT EDIT.

package vpack
`
	const importFmt = `
import (
    "fmt"
)
`
	// Write static table to file
	formatted, err := format.Source([]byte(hdr + constCode + fileHeader))
	if err != nil {
		return fmt.Errorf("formatting static table: %w", err)
	}
	if err := os.WriteFile("static_table.go", formatted, 0644); err != nil {
		return err
	}

	formatted, err = format.Source(
		[]byte(hdr + importFmt + parseFuncHeader + parseCode + parseFuncFooter))
	if err != nil {
		return fmt.Errorf("formatting parser: %w", err)
	}
	if err := os.WriteFile("parse.go", formatted, 0644); err != nil {
		return err
	}

	return nil
}

// findStructField looks for a field by name within a struct type, regardless of export status
func findStructField(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Name == name {
			return field, true
		}
	}
	return reflect.StructField{}, false
}

// analyzeType collects parse-function data (fields, etc.) for type t.
// Then we store it in parseFuncDataMap[t], recursing into sub-structs as needed.
func (g *codeGenerator) analyzeType(t reflect.Type) error {
	if t.Kind() != reflect.Struct {
		return nil
	}
	if g.parseFns[t] {
		return nil
	}
	g.parseFns[t] = true

	fields := exportedCodecFields(t)
	sort.Slice(fields, func(i, j int) bool {
		return getCodecTagName(fields[i]) < getCodecTagName(fields[j])
	})

	// Check for fixed-size structs using the vpack_assert_size tag on _struct field
	fixedSize := 0
	if structField, found := findStructField(t, "_struct"); found {
		vpackSizeTag := structField.Tag.Get("vpack_assert_size")
		if vpackSizeTag != "" {
			if size, err := strconv.Atoi(vpackSizeTag); err == nil {
				fixedSize = size
			}
		}
	}

	pf := parseFuncData{
		TypeName:      t.Name(),
		MaxFieldCount: len(fields),
		FixedSize:     fixedSize,
	}

	for _, f := range fields {
		fd := fieldData{
			CodecName:      getCodecTagName(f),
			FieldNameConst: g.getOrCreateStaticIndexForField(getCodecTagName(f)),
		}
		ft := f.Type
		if ft.Kind() == reflect.Struct {
			fd.IsSubStruct = true
			fd.SubStructName = ft.Name()
			if err := g.analyzeType(ft); err != nil {
				return err
			}
		} else {
			if ft.Kind() == reflect.Array {
				fd.ArrayLen = ft.Len()
				// If there's "0" in vpack_special_values, define an all-zero pattern
				vsp := f.Tag.Get("vpack_special_values")
				if strings.Contains(vsp, "0") {
					fd.IsZeroCheck = true
					fd.ZeroConst = g.defineSpecialZeroBinary(fd.CodecName, fd.ArrayLen)
				}
				// If literal, mark it
				vpackTag := f.Tag.Get("vpack")
				if strings.Contains(vpackTag, "literal") {
					fd.IsLiteral = true
				}
			}
			if isUint64Alias(ft) {
				fd.IsUint64Alias = true
				if sp := f.Tag.Get("vpack_special_values"); sp != "" {
					fd.VpackSpecial = sp
					g.defineSpecialValuesNumeric(fd.CodecName, sp)
				}
			}
		}
		pf.Fields = append(pf.Fields, fd)
	}

	g.parseFuncDataMap[t] = pf
	return nil
}

// defineSpecialZeroBinary is a generic helper for any fixed-length binary type
// with "vpack_special_values:'0'". We produce e.g. "staticIdxAllZeroDataField"
// and a snippet in specialPatterns that appends the bin8 marker + zero bytes.
func (g *codeGenerator) defineSpecialZeroBinary(codecName string, length int) string {
	allZeroConst := "staticIdxAllZero" + strings.Title(codecName) + "Field"
	if g.findItemIndexByConstName(allZeroConst) >= 0 {
		return allZeroConst
	}
	// Create the static index for the "all-zero" variant
	idx := g.nextIndex
	g.nextIndex++
	g.items = append(g.items, staticItem{
		ConstName: allZeroConst,
		Index:     idx,
		Data:      nil,
		Comment:   fmt.Sprintf("All-zero %s field for length %d", codecName, length),
	})

	baseField := g.getOrCreateStaticIndexForField(codecName) // e.g. "staticIdxDataField"

	//   zeroVal := append(t[<baseField>], <bin8Const>...)
	//   zeroVal = append(zeroVal, make([]byte, <length>)...)
	//   t[<allZeroConst>] = zeroVal
	code := fmt.Sprintf(`zeroVal := append(t[%s], msgpBin8Len%d...)
zeroVal = append(zeroVal, make([]byte, %d)...)
t[%s] = zeroVal`,
		baseField, length, length, allZeroConst)

	g.specialPatterns = append(g.specialPatterns, specialPattern{Code: code})
	return allZeroConst
}

// defineSpecialValuesNumeric handles integer fields with vpack_special_values="1,2,3,...".
func (g *codeGenerator) defineSpecialValuesNumeric(codecName, specialValues string) {
	// For each special value, we create e.g. "staticIdxStepVal1Field" and a snippet
	//   t[staticIdxStepVal1Field] = append(t[staticIdxStepField], []byte{0x01}...)
	baseField := g.getOrCreateStaticIndexForField(codecName) // e.g. "staticIdxStepField"

	vals := strings.Split(specialValues, ",")
	for _, v := range vals {
		v = strings.TrimSpace(v)
		cn := fmt.Sprintf("staticIdx%sVal%sField", strings.Title(codecName), v)
		if g.findItemIndexByConstName(cn) >= 0 {
			continue
		}
		idx := g.nextIndex
		g.nextIndex++
		g.items = append(g.items, staticItem{
			ConstName: cn,
			Index:     idx,
			Data:      nil,
			Comment:   fmt.Sprintf("%s = %s special", codecName, v),
		})
		bVal := parseByteValue(v) // 0x01, 0x02, etc.
		code := fmt.Sprintf(`t[%s] = append(t[%s], []byte{0x%02x}...)`,
			cn, baseField, bVal)
		g.specialPatterns = append(g.specialPatterns, specialPattern{Code: code})
	}
}

// parseByteValue converts a string like "1", "42" to a byte, panic on error.
func parseByteValue(s string) byte {
	var b byte
	_, err := fmt.Sscanf(s, "%d", &b)
	if err != nil {
		panic(fmt.Sprintf("bad vpack_special_values value: %v", err))
	}
	return b
}

// getOrCreateMapMarkerIndex ensures we have e.g. "staticIdxMapMarker3" => 0x83
func (g *codeGenerator) getOrCreateMapMarkerIndex(n int) {
	cn := fmt.Sprintf("staticIdxMapMarker%d", n)
	if g.findItemIndexByConstName(cn) >= 0 {
		return
	}
	if n > 15 { // e.g. 0x80 - 0x8f
		panic(fmt.Sprintf("map marker index %d unsupported", n))
	}

	idx := g.baseMapIndex | byte(n)
	data := []byte{0x80 | byte(n)}
	g.items = append(g.items, staticItem{
		ConstName: cn,
		Index:     idx,
		Data:      data,
		Comment:   fmt.Sprintf("Map with %d items", n),
	})
}

// getOrCreateStaticIndexForField creates a fixstr entry for a field name: e.g. 0xa3,"snd"
func (g *codeGenerator) getOrCreateStaticIndexForField(fieldName string) string {
	cn := "staticIdx" + strings.Title(fieldName) + "Field"
	idxNum := g.findItemIndexByConstName(cn)
	if idxNum >= 0 {
		return cn
	}
	idx := g.nextIndex
	g.nextIndex++
	// fixstr prefix 0xa0 + length
	b := []byte{0xa0 | byte(len(fieldName))}
	b = append(b, fieldName...)
	g.items = append(g.items, staticItem{
		ConstName: cn,
		Index:     idx,
		Data:      b,
		Comment:   fmt.Sprintf("\"%s\" field", fieldName),
	})
	return cn
}

// findItemIndexByConstName returns the index of the item in g.items or -1
func (g *codeGenerator) findItemIndexByConstName(cn string) int {
	for i, it := range g.items {
		if it.ConstName == cn {
			return i
		}
	}
	return -1
}

// renderConstBlock uses constBlockTemplate to output static index constants.
func (g *codeGenerator) renderConstBlock() (string, error) {
	// Sort items by index
	sort.Slice(g.items, func(i, j int) bool {
		return g.items[i].Index < g.items[j].Index
	})

	// Find the minimum and maximum static index values
	var minIdx, maxIdx uint8
	if len(g.items) > 0 {
		minIdx = g.items[0].Index              // First item after sorting
		maxIdx = g.items[len(g.items)-1].Index // Last item after sorting
	}

	data := struct {
		Items          []staticItem
		StaticIdxStart uint8
		StaticIdxEnd   uint8
	}{
		Items:          g.items,
		StaticIdxStart: minIdx,
		StaticIdxEnd:   maxIdx,
	}

	tmpl, err := template.New("constBlock").Parse(constBlockTemplate)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// renderFileHeader uses fileHeaderTemplate for createGeneratedStaticTable
// plus expansions in specialPatterns.
func (g *codeGenerator) renderFileHeader() (string, error) {
	// Sort items by index so table is stable
	sort.Slice(g.items, func(i, j int) bool {
		return g.items[i].Index < g.items[j].Index
	})

	data := struct {
		Items           []staticItem
		SpecialPatterns []specialPattern
	}{
		Items:           g.items,
		SpecialPatterns: g.specialPatterns,
	}

	tmpl, err := template.New("fileHeader").Parse(fileHeaderTemplate)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// renderParseFunctions uses parseFuncTemplate for each discovered struct type.
// We define top-level template functions in FuncMap. For the numeric special
// expansions, we call `{{ makeNumericConst ... }}` from the nested range block.
func (g *codeGenerator) renderParseFunction(typeName string) (string, error) {
	var sb strings.Builder
	tmpl, err := template.New("parseFunc").Funcs(template.FuncMap{
		"split": func(s, sep string) []string {
			return strings.Split(s, sep)
		},
		// top-level function to build e.g. "staticIdxStepVal3Field"
		"makeNumericConst": func(fieldName, val string) string {
			// fieldName = "step", val="3" => "staticIdxStepVal3Field"
			return fmt.Sprintf("staticIdx%sVal%sField", strings.Title(fieldName), val)
		},
		"renderParseFunction": func(typeName string) string {
			ret, err := g.renderParseFunction(typeName)
			if err != nil {
				panic(fmt.Sprintf("renderParseFunction for %s: %v", typeName, err))
			}
			return ret
		},
	}).Parse(parseFuncTemplate)
	if err != nil {
		return "", err
	}

	// Sort the types by name for stable output
	var types []reflect.Type
	for t, pf := range g.parseFuncDataMap {
		if pf.TypeName == typeName {
			types = append(types, t)
		}
	}

	for _, t := range types {
		pf := g.parseFuncDataMap[t]
		var buf strings.Builder
		if err := tmpl.Execute(&buf, pf); err != nil {
			return "", err
		}
		sb.WriteString(buf.String())
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func exportedCodecFields(t reflect.Type) []reflect.StructField {
	var out []reflect.StructField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		tag := getCodecTagName(f)
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func getCodecTagName(f reflect.StructField) string {
	tag := f.Tag.Get("codec")
	if tag == "" {
		return ""
	}
	parts := strings.Split(tag, ",")
	return parts[0]
}

func isUint64Alias(t reflect.Type) bool {
	// covers named aliases of uint64
	return t.Kind() == reflect.Uint64 || t.ConvertibleTo(reflect.TypeOf(uint64(0)))
}
