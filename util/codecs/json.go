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

package codecs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
)

// NewFormattedJSONEncoder returns a json encoder configured for
// pretty-printed output (human-readable)
func NewFormattedJSONEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	enc.SetEscapeHTML(false)
	return enc
}

// LoadObjectFromFile implements the common pattern for loading an instance
// of an object from a json file.
func LoadObjectFromFile(filename string, object interface{}) (err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(object)
	return
}

func writeBytes(writer io.Writer, object interface{}, prettyFormat bool) error {
	var enc *json.Encoder
	if prettyFormat {
		enc = NewFormattedJSONEncoder(writer)
	} else {
		enc = json.NewEncoder(writer)
	}
	return enc.Encode(object)
}

// SaveObjectToFile implements the common pattern for saving an object to a file as json
func SaveObjectToFile(filename string, object interface{}, prettyFormat bool) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeBytes(f, object, prettyFormat)
}

// WriteNonDefaultValues writes object to a writer as json, but only fields that are not
// currently set to be the default value.
// Optionally, you can specify an array of field names to always include.
func WriteNonDefaultValues(writer io.Writer, object, defaultObject interface{}, ignore []string) error {
	// Iterate one line at a time, parse Name
	// If ignore contains Name, don't delete
	// Use reflection to compare object[Name].value == defaultObject[Name].value
	// If same, delete line from array
	// When done, ensure last value line doesn't include comma
	// Write string array to file.

	var buf bytes.Buffer
	err := writeBytes(&buf, object, true)
	if err != nil {
		return err
	}
	content := buf.Bytes()

	valueLines := strings.Split(string(content), "\n")

	// Create maps of the name->value pairs for the object and the defaults
	objectValues := createValueMap(object)
	defaultValues := createValueMap(defaultObject)

	newFile := make([]string, len(valueLines))
	newIndex := 0
	inContent := false

	for _, line := range valueLines {
		if line == "" {
			continue // Ignore blank lines
		}
		valName := extractValueName(line)
		if valName == "" {
			if !inContent {
				if !strings.Contains(line, "{") {
					return fmt.Errorf("error processing serialized object - we don't support nested types: %s", line)
				}
				inContent = true
			} else {
				if !strings.Contains(line, "}") {
					return fmt.Errorf("error processing serialized object - we don't support nested types: %s", line)
				}
				inContent = false
			}
			newFile[newIndex] = line
			newIndex++
			continue
		}

		if !inContent {
			return fmt.Errorf("error processing serialized object - should be at EOF: %s", line)
		}

		if slices.Contains(ignore, valName) {
			newFile[newIndex] = line
			newIndex++
			continue
		}

		if isDefaultValue(valName, objectValues, defaultValues) {
			continue
		}

		newFile[newIndex] = line
		newIndex++
	}

	// Ensure last value line doesn't end in comma
	if newIndex > 2 {
		lastValLine := newFile[newIndex-2]
		if lastValLine[len(lastValLine)-1] == ',' {
			newFile[newIndex-2] = lastValLine[:len(lastValLine)-1]
		}
	}

	combined := strings.Join(newFile, "\n")
	combined = strings.TrimRight(combined, "\r\n ")
	_, err = writer.Write([]byte(combined))
	return err
}

// SaveNonDefaultValuesToFile saves an object to a file as json, but only fields that are not
// currently set to be the default value.
// Optionally, you can specify an array of field names to always include.
func SaveNonDefaultValuesToFile(filename string, object, defaultObject interface{}, ignore []string) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)

	err = WriteNonDefaultValues(writer, object, defaultObject, ignore)
	if err != nil {
		return err
	}

	writer.Flush()
	return nil
}

func extractValueName(line string) (name string) {
	start := strings.Index(line, "\"")
	if start < 0 {
		return
	}
	end := strings.Index(line, "\":")
	if end < 0 || end <= start {
		return
	}
	return line[start+1 : end]
}

func createValueMap(object interface{}) map[string]interface{} {
	valueMap := make(map[string]interface{})

	v := reflect.ValueOf(object)
	val := reflect.Indirect(v)

	for i := 0; i < v.NumField(); i++ {
		name := val.Type().Field(i).Name
		value := v.Field(i).Interface()
		valueMap[name] = value
	}
	return valueMap
}

func isDefaultValue(name string, values, defaults map[string]interface{}) bool {
	val, hasVal := values[name]
	def, hasDef := defaults[name]
	if hasVal != hasDef {
		return false
	}

	return reflect.DeepEqual(val, def)
}
