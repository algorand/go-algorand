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
	"strconv"
	"strings"
)

const sourceMapVersion = 3

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
// the assembled file and mappings to the source file.
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
			pcToLine[pc] = strconv.Itoa(line)
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
		Names:   []string{}, // TEAL code does not generate any names
		Mapping: encodedMapping,
	}
}
