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
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/encoding/unicode/utf32"
)

// As of go1.10, json implements encoding and decoding of JSON as defined in RFC 7159. https://pkg.go.dev/encoding/json

func TestParseScalar(t *testing.T) {
	partitiontest.PartitionTest(t)
	intScalar := `{"key0": 4160}`
	_, err := parseJSON([]byte(intScalar))
	require.NoError(t, err)
	strScalar := `{"key0": "algo"}`
	_, err = parseJSON([]byte(strScalar))
	require.NoError(t, err)
}

func TestParseTrailingCommas(t *testing.T) {
	partitiontest.PartitionTest(t)
	for i := 1; i <= 10; i++ {
		commas := strings.Repeat(",", i)
		intScalar := `{"key0": 4160` + commas + `}`
		_, err := parseJSON([]byte(intScalar))
		require.Error(t, err)
		strScalar := `{"key0": "algo"` + commas + `}`
		_, err = parseJSON([]byte(strScalar))
		require.Error(t, err)
	}
}

func TestParseComments(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": /*comment*/"algo"}`
	_, err := parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": [1,/*comment*/,3]}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
}

func TestParseUnclosed(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": ["algo"}`
	_, err := parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": ["algo"]]}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": ["algo"],"key1":{}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": ["algo"],"key1":{{}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": [1,}]}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
}

func TestParseNested(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": [[1,2,3],[4,5,6]], "key1":{"key10":{"key100":"algo"}}}`
	_, err := parseJSON([]byte(text))
	require.NoError(t, err)
}

func TestParseWhiteSpace(t *testing.T) {
	partitiontest.PartitionTest(t)
	//empty text
	text := ""
	_, err := parseJSON([]byte(text))
	require.Error(t, err)
	//space, tab, new line and carriage return are allowed
	text = "{\"key0\": [\t]\n\r}"
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
	//form feed is not allowed
	text = "{\"key0\": [\f]}"
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
}

func TestParseSpecialValues(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": NaN}`
	_, err := parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": +Inf}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": -Inf}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": null}`
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"key0": true}`
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"key0": false}`
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
}

func TestParseHexValue(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": 0x1}`
	_, err := parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": 0xFF}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
}

func TestParseBigNum(t *testing.T) {
	partitiontest.PartitionTest(t)
	// values in range uint64 parsed correctly
	// parse 0
	text := `{"key0":0}`
	msg, err := parseJSON([]byte(text))
	require.NoError(t, err)
	require.True(t, json.Valid([]byte(text)))
	require.Equal(t, "0", string(msg["key0"]))
	// parse int
	text = `{"key0":123456789}`
	msg, err = parseJSON([]byte(text))
	require.NoError(t, err)
	require.True(t, json.Valid([]byte(text)))
	require.Equal(t, "123456789", string(msg["key0"]))
	// parse 2^64-1
	text = `{"key0":18446744073709551615}`
	msg, err = parseJSON([]byte(text))
	require.NoError(t, err)
	require.True(t, json.Valid([]byte(text)))
	require.Equal(t, "18446744073709551615", string(msg["key0"]))
}

func TestParseArrays(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": [,1,]}`
	_, err := parseJSON([]byte(text))
	require.Error(t, err)
	text = "{\"key0\":[1\n]}"
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"key0": [[1]]}`
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
}

func TestParseKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"": 1}`
	_, err := parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"": "algo"}`
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"\u0061": 1}`
	parsed, err := parseJSON([]byte(text))
	require.NoError(t, err)
	require.Equal(t, "1", string(parsed["\u0061"]))
	require.Equal(t, "1", string(parsed["a"]))
	text = `{"key0": 1,"key0": 2}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": 1,"key1": {"key2":2,"key2":"10"}}`
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"keys.1": 1}`
	_, err = parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"key0":: 1}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0":: "1"}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": 'algo'}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{1: 1}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
}

func TestParseFileEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)
	// create utf-8, utf-16, and utf-32 encoded text and check which is supported by json
	// it appears that json only supports utf-8 encoded json text

	// utf-8
	text := `{"key0": "algo"}`
	_, err := parseJSON([]byte(text))
	require.NoError(t, err)

	// json fails to parse utf-16 encoded text
	// utf-16LE
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	encoded, err := enc.String(text)
	require.NoError(t, err)
	_, err = parseJSON([]byte(encoded))
	require.Error(t, err)
	// utf-16BE
	enc = unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewEncoder()
	encoded, err = enc.String(text)
	require.NoError(t, err)
	_, err = parseJSON([]byte(encoded))
	require.Error(t, err)

	// json fails to parse utf-32 encoded text
	// utf-32LE
	enc = utf32.UTF32(utf32.LittleEndian, utf32.IgnoreBOM).NewEncoder()
	encoded, err = enc.String(text)
	require.NoError(t, err)
	_, err = parseJSON([]byte(encoded))
	require.Error(t, err)
	// utf-32BE
	enc = utf32.UTF32(utf32.BigEndian, utf32.IgnoreBOM).NewEncoder()
	encoded, err = enc.String(text)
	require.NoError(t, err)
	_, err = parseJSON([]byte(encoded))
	require.Error(t, err)
}

func TestParseByteOrderMark(t *testing.T) {
	partitiontest.PartitionTest(t)
	// byte order mark is not allowed at the beginning of a JSON text,
	// it is treated as an error
	text := "\uFEFF{\"key0\": 1}"
	_, err := parseJSON([]byte(text))
	require.Error(t, err)
}

func TestParseControlChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	// control chars (u0000 - u001F) must be escaped
	for i := 0x0; i <= 0x1f; i++ {
		text := fmt.Sprintf("{\"key0\":\"\\u%04X\"}", i)
		_, err := parseJSON([]byte(text))
		require.NoError(t, err)
	}
}

func TestParseEscapeChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	// escaped control char
	text := "{\"key0\": \"\\u0000\"}"
	_, err := parseJSON([]byte(text))
	require.NoError(t, err)
	// incomplete escaped chars
	text = `{"key0": ["\u00A"]}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": "\"}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": """}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
}

func TestParseEscapedInvalidChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	// unicode escape sequence remains in string
	// accepted surrogate pair
	text := `{"key0": "\uD801\udc37"}`
	msg, err := parseJSON([]byte(text))
	require.NoError(t, err)
	require.Equal(t, "\"\\uD801\\udc37\"", string(msg["key0"]))
	// escaped invalid codepoints
	text = `{"key0": "\uD800\uD800n"}`
	msg, err = parseJSON([]byte(text))
	require.NoError(t, err)
	require.Equal(t, "\"\\uD800\\uD800n\"", string(msg["key0"]))

	text = `{"key0": "\uD800\uD800n"}`
	msg, err = parseJSON([]byte(text))
	require.NoError(t, err)
	require.Equal(t, "\"\\uD800\\uD800n\"", string(msg["key0"]))
}

func TestParseRawNonUnicodeChar(t *testing.T) {
	partitiontest.PartitionTest(t)
	text := `{"key0": "πζθ"}`
	_, err := parseJSON([]byte(text))
	require.NoError(t, err)
	text = `{"key0": "\uFF"}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
	text = `{"key0": FF}`
	_, err = parseJSON([]byte(text))
	require.Error(t, err)
}
