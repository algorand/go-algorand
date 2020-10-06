// Copyright (C) 2019-2020 Algorand, Inc.
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
	"unicode"
	"unicode/utf8"

	"github.com/algorand/go-algorand/data/basics"
)

// unicodePrintable scan the input string str, and find if it contains any
// non-printable unicode characters. If so, it returns false, along with the
// printable characters that do appear in the input string. Otherwise, it
// returns true, along with a copy of the original string. The returned string
// printableString is gurenteed to be printable in all cases.
func unicodePrintable(str string) (isPrintable bool, printableString string) {
	isPrintable = true
	encRuneBuf := make([]byte, 8)
	for _, r := range str {
		if !unicode.IsPrint(r) {
			isPrintable = false
		} else {
			n := utf8.EncodeRune(encRuneBuf, r)
			printableString += string(encRuneBuf[:n])
		}
	}
	return
}

func jsonPrintable(str string) bool {
	// htmlSafeSet holds the value true if the ASCII character with the given
	// array position can be safely represented inside a JSON string, embedded
	// inside of HTML <script> tags, without any additional escaping.
	//
	// All values are true except for the ASCII control characters (0-31), the
	// double quote ("), the backslash character ("\"), HTML opening and closing
	// tags ("<" and ">"), and the ampersand ("&").
	var htmlSafeSet = [utf8.RuneSelf]bool{
		' ':      true,
		'!':      true,
		'"':      false,
		'#':      true,
		'$':      true,
		'%':      true,
		'&':      false,
		'\'':     true,
		'(':      true,
		')':      true,
		'*':      true,
		'+':      true,
		',':      true,
		'-':      true,
		'.':      true,
		'/':      true,
		'0':      true,
		'1':      true,
		'2':      true,
		'3':      true,
		'4':      true,
		'5':      true,
		'6':      true,
		'7':      true,
		'8':      true,
		'9':      true,
		':':      true,
		';':      true,
		'<':      false,
		'=':      true,
		'>':      false,
		'?':      true,
		'@':      true,
		'A':      true,
		'B':      true,
		'C':      true,
		'D':      true,
		'E':      true,
		'F':      true,
		'G':      true,
		'H':      true,
		'I':      true,
		'J':      true,
		'K':      true,
		'L':      true,
		'M':      true,
		'N':      true,
		'O':      true,
		'P':      true,
		'Q':      true,
		'R':      true,
		'S':      true,
		'T':      true,
		'U':      true,
		'V':      true,
		'W':      true,
		'X':      true,
		'Y':      true,
		'Z':      true,
		'[':      true,
		'\\':     false,
		']':      true,
		'^':      true,
		'_':      true,
		'`':      true,
		'a':      true,
		'b':      true,
		'c':      true,
		'd':      true,
		'e':      true,
		'f':      true,
		'g':      true,
		'h':      true,
		'i':      true,
		'j':      true,
		'k':      true,
		'l':      true,
		'm':      true,
		'n':      true,
		'o':      true,
		'p':      true,
		'q':      true,
		'r':      true,
		's':      true,
		't':      true,
		'u':      true,
		'v':      true,
		'w':      true,
		'x':      true,
		'y':      true,
		'z':      true,
		'{':      true,
		'|':      true,
		'}':      true,
		'~':      true,
		'\u007f': true,
	}

	for _, r := range str {
		if r >= utf8.RuneSelf {
			return false
		}
		if htmlSafeSet[r] == false {
			return false
		}
	}
	return true
}

func heuristicFormatStr(str string) string {
	// See if we can print it as a json output
	if jsonPrintable(str) {
		return str
	}

	// otherwise, see if it's a 32 byte string that could be printed as an address
	if len(str) == 32 {
		var addr basics.Address
		copy(addr[:], []byte(str))
		return addr.String()
	}

	// otherwise, use the default json formatter to output the byte array.
	return str
}

func heuristicFormatKey(key string) string {
	return heuristicFormatStr(key)
}

func heuristicFormatVal(val basics.TealValue) basics.TealValue {
	if val.Type == basics.TealUintType {
		return val
	}
	val.Bytes = heuristicFormatStr(val.Bytes)
	return val
}

func heuristicFormat(state map[string]basics.TealValue) map[string]basics.TealValue {
	result := make(map[string]basics.TealValue)
	for k, v := range state {
		result[heuristicFormatKey(k)] = heuristicFormatVal(v)
	}
	return result
}
