// Copyright (C) 2019-2024 Algorand, Inc.
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

package logic

import (
	"bytes"
	"strings"
)

// sourceMapVersion is currently 3.
// Refer to the full specs of sourcemap here: https://sourcemaps.info/spec.html
const sourceMapVersion = 3
const b64table string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// SourceMap contains details from the source to assembly process.
// Currently, contains the map between TEAL source line to
// the assembled bytecode position and details about
// the template variables contained in the source file.
type SourceMap struct {
	Version    int      `json:"version"`
	File       string   `json:"file,omitempty"`
	SourceRoot string   `json:"sourceRoot,omitempty"`
	Sources    []string `json:"sources"`
	Names      []string `json:"names"`
	Mappings   string   `json:"mappings"`
}

// GetSourceMap returns a struct containing details about
// the assembled file and encoded mappings to the source file.
func GetSourceMap(sourceNames []string, offsetToLocation map[int]SourceLocation) SourceMap {
	maxPC := 0
	for pc := range offsetToLocation {
		if pc > maxPC {
			maxPC = pc
		}
	}

	// Array where index is the PC and value is the line for `mappings` field.
	prevSourceLocation := SourceLocation{}
	pcToLine := make([]string, maxPC+1)
	for pc := range pcToLine {
		if location, ok := offsetToLocation[pc]; ok {
			pcToLine[pc] = MakeSourceMapLine(0, 0, location.Line-prevSourceLocation.Line, location.Column-prevSourceLocation.Column)
			prevSourceLocation = location
		} else {
			pcToLine[pc] = ""
		}
	}

	return SourceMap{
		Version:  sourceMapVersion,
		Sources:  sourceNames,
		Names:    []string{}, // TEAL code does not generate any names.
		Mappings: strings.Join(pcToLine, ";"),
	}
}

// intToVLQ writes out value to bytes.Buffer
func intToVLQ(v int, buf *bytes.Buffer) {
	v <<= 1
	if v < 0 {
		v = -v
		v |= 1
	}
	for v >= 32 {
		buf.WriteByte(b64table[32|(v&31)])
		v >>= 5
	}
	buf.WriteByte(b64table[v])
}

// MakeSourceMapLine creates source map mapping's line entry
func MakeSourceMapLine(tcol, sindex, sline, scol int) string {
	buf := bytes.NewBuffer(nil)
	intToVLQ(tcol, buf)
	intToVLQ(sindex, buf)
	intToVLQ(sline, buf)
	intToVLQ(scol, buf)
	return buf.String()
}
