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

package logic

import (
	"bytes"
	"strings"
)

// sourceMapVersion is currently 3: https://sourcemaps.info/spec.html
const sourceMapVersion = 3
const b64table string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// SourceMap contains details from the source to assembly process
// currently contains map of TEAL source line to assembled bytecode position
// and details about the template variables contained in the source file
type SourceMap struct {
	Version    int      `json:"version"`
	File       string   `json:"file"`
	SourceRoot string   `json:"sourceRoot"`
	Sources    []string `json:"sources"`
	Names      []string `json:"names"`
	Mapping    string   `json:"mapping"`
}

// GetSourceMap returns a struct containing details about
// the assembled file and encoded mappings to the source file.
func GetSourceMap(sourceNames []string, offsetToLine map[int]int) SourceMap {
	maxPC := 0
	for pc := range offsetToLine {
		if pc > maxPC {
			maxPC = pc
		}
	}

	// Array where index is the PC and value is the line.
	pcToLine := make([]string, maxPC+1)
	for pc := range pcToLine {
		if line, ok := offsetToLine[pc]; ok {
			pcToLine[pc] = MakeSourceMapLine(0, 0, line, 0)
		} else {
			pcToLine[pc] = ""
		}
	}

	// Encode the source map into a string
	encodedMapping := strings.Join(pcToLine, ";")

	return SourceMap{
		Version: sourceMapVersion,
		File:    "", // Assembled file does not have a name.
		Sources: sourceNames,
		Names:   []string{}, // TEAL code does not generate any names.
		Mapping: encodedMapping,
	}
}

// IntToVLQ writes out value to bytes.Buffer
func IntToVLQ(v int, buf *bytes.Buffer) {
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
	IntToVLQ(tcol, buf)
	IntToVLQ(sindex, buf)
	IntToVLQ(sline, buf)
	IntToVLQ(scol, buf)
	return buf.String()
}
