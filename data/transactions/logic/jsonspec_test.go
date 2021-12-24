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

package logic

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/encoding/unicode/utf32"
)

// As of go1.17.5, json implements encoding and decoding of JSON as defined in RFC 7159. https://pkg.go.dev/encoding/json
type utf8String string

func (s utf8String) MarshalJSON() ([]byte, error) {
	return []byte(strconv.QuoteToASCII(string(s))), nil
}
func TestParseScalar(t *testing.T) {
	partitiontest.PartitionTest(t)
	intScalar := `{"key0": 4160}`
	_, err := parseJSON([]byte(intScalar))
	require.Nil(t, err)
	strScalar := `{"key0": "algo"}`
	_, err = parseJSON([]byte(strScalar))
	require.Nil(t, err)
}

func TestParseTrailingCommas(t *testing.T) {
	partitiontest.PartitionTest(t)
	for i := 1; i <= 10; i++ {
		commas := strings.Repeat(",", i)
		intScalar := `{"key0": 4160` + commas + `}`
		_, err := parseJSON([]byte(intScalar))
		require.NotNil(t, err)
		strScalar := `{"key0": "algo"` + commas + `}`
		_, err = parseJSON([]byte(strScalar))
		require.NotNil(t, err)
	}
}

func TestParseComments(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": /*comment*/"algo"}`
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": "algo"}/*comment*/`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": [1,/*comment*/,3]}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
}

func TestParseUnclosed(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": ["algo"}`
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": ["algo"]]}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": ["algo"],"key1":{}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": ["algo"],"key1":{{}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": [1,}]}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
}

func TestParseNested(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": [[1,2,3],[4,5,6]], "key1":{"key10":{"key100":"algo"}}}`
	_, err := parseJSON([]byte(text))
	require.Nil(t, err)
}

func TestParseWhiteSpace(t *testing.T) {
	partitiontest.PartitionTest(t)
	//empty text
	text := ""
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
	//space, tab, new line and carriage return are allowed
	text = "{\"key0\": [\t]\n\r}"
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	//form feed is not allowed
	text = "{\"key0\": [\f]}"
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
}

func TestParseSpecialValues(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": NaN}`
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": +Inf}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": -Inf}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": null}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
}

func TestParseHexValue(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": 0x1}`
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": 0xFF}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
}

func TestParseBigNum(t *testing.T) {
	partitiontest.PartitionTest(t)
	//max int can be represented using float64, 2<<52
	text := `{"key0":9007199254740992}`
	msg, err := parseJSON([]byte(text))
	require.Nil(t, err)
	require.True(t, json.Valid([]byte(text)))
	require.Equal(t, uint64(9007199254740992), uint64(msg.(map[string]interface{})["key0"].(float64)))

	//2<<52+1
	text = `{"key0":9007199254740993}`
	msg, err = parseJSON([]byte(text))
	require.Nil(t, err)
	require.True(t, json.Valid([]byte(text)))
	require.NotEqual(t, uint64(9007199254740993), uint64(msg.(map[string]interface{})["key0"].(float64)))
	require.Equal(t, uint64(9007199254740992), uint64(msg.(map[string]interface{})["key0"].(float64)))
}

func TestParseExp(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": 1.2E+}`
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": 1.2E+8}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": 0E+8}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": 0.2E+8}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": 0.2E-3}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": 1.2E-6}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
}

func TestParseArrays(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": [,1,]}`
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
	text = "{\"key0\":[1\n]}"
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": [[1]]}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
}

func TestParseKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"": 1}`
	_, err := parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"": "algo"}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": 1,"key0": 2}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": "1","key0": "2"}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"keys.1": 1}`
	_, err = parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0":: 1}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0":: "1"}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": 'algo'}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{1: 1}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)

}

func TestParseFileEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)
	//utf-8
	text := `{"key0": "algo"}`
	_, err := parseJSON([]byte(text))
	require.Nil(t, err)
	//utf-16LE
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	encoded, err := enc.String(text)
	require.Nil(t, err)
	_, err = parseJSON([]byte(encoded))
	require.NotNil(t, err)
	//utf-16BE
	enc = unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewEncoder()
	encoded, err = enc.String(text)
	require.Nil(t, err)
	_, err = parseJSON([]byte(encoded))
	require.NotNil(t, err)
	//utf-32LE
	enc = utf32.UTF32(utf32.LittleEndian, utf32.IgnoreBOM).NewEncoder()
	encoded, err = enc.String(text)
	require.Nil(t, err)
	_, err = parseJSON([]byte(encoded))
	require.NotNil(t, err)
	//utf-32BE
	enc = utf32.UTF32(utf32.BigEndian, utf32.IgnoreBOM).NewEncoder()
	encoded, err = enc.String(text)
	require.Nil(t, err)
	_, err = parseJSON([]byte(encoded))
	require.NotNil(t, err)

}

func TestParseByteOrderMark(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := "\uFEFF{\"key0\": 1}"
	_, err := parseJSON([]byte(text))
	require.NotNil(t, err)
}

func TestParseControlChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	//control chars (u0000 - u001F) must be escaped
	for i := 0x0; i <= 0x1f; i++ {
		text := fmt.Sprintf("{\"key0\":\"\\u%04X\"}", i)
		_, err := parseJSON([]byte(text))
		require.Nil(t, err)
	}
}

func TestParseEscapeChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	// escaped control char
	text := "{\"key0\": \"\\u0000\"}"
	_, err := parseJSON([]byte(text))
	require.Nil(t, err)
	// incomplete escaped chars
	text = `{"key0": ["\u00A"]}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": "\"}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": """}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
}

func TestParseEscapedInvalidChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	// accepted surrogate pair
	text := `{"key0": "\uD801\udc37"}`
	msg, err := parseJSON([]byte(text))
	require.Nil(t, err)
	require.NotContains(t, msg.(map[string]interface{})["key0"], "�")

	// escaped invalid codepoints are replaced by uFFFD REPLACEMENT CHARACTER
	text = `{"key0": "\uD800\uD800n"}`
	msg, err = parseJSON([]byte(text))
	require.Nil(t, err)
	require.Contains(t, msg.(map[string]interface{})["key0"], "�")

	text = `{"key0": "\uDFAA"}`
	msg, err = parseJSON([]byte(text))
	require.Nil(t, err)
	require.Contains(t, msg.(map[string]interface{})["key0"], "�")

	text = `{"key0": "\uD888\u1234"}`
	msg, err = parseJSON([]byte(text))
	require.Nil(t, err)
	require.Contains(t, msg.(map[string]interface{})["key0"], "�")

	text = `{"key0": "\uDd1e\uD834"}`
	msg, err = parseJSON([]byte(text))
	require.Nil(t, err)
	require.Contains(t, msg.(map[string]interface{})["key0"], "�")
}

func TestParseRawNonUnicodeChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": "&!%"}`
	_, err := parseJSON([]byte(text))
	require.Nil(t, err)
	text = `{"key0": "\uFF"}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
	text = `{"key0": FF}`
	_, err = parseJSON([]byte(text))
	require.NotNil(t, err)
}
