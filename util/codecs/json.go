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

package codecs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
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

// SaveObjectToFile implements the common pattern for saving an object to a file as json
func SaveObjectToFile(filename string, object interface{}, prettyFormat bool) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	var enc *json.Encoder
	if prettyFormat {
		enc = NewFormattedJSONEncoder(f)
	} else {
		enc = json.NewEncoder(f)
	}
	err = enc.Encode(object)
	return err
}

// SaveNonDefaultValuesToFile saves an object to a file as json, but only fields that are not
// currently set to be the default value.
// Optionally, you can specify an array of field names to always include.
func SaveNonDefaultValuesToFile(filename string, object, defaultObject interface{}, ignore []string, prettyFormat bool) error {
	// Serialize object to temporary file.
	// Read file into string array
	// Iterate one line at a time, parse Name
	// If ignore contains Name, don't delete
	// Use reflection to compare object[Name].value == defaultObject[Name].value
	// If same, delete line from array
	// When done, ensure last value line doesn't include comma
	// Write string array to file.

	file, err := ioutil.TempFile("", "encsndv")
	if err != nil {
		return err
	}
	name := file.Name()
	file.Close()

	defer os.Remove(name)
	// Save object to file pretty-formatted so we can read one value-per-line
	err = SaveObjectToFile(name, object, true)
	if err != nil {
		return err
	}

	// Read lines from encoded file into string array
	content, err := ioutil.ReadFile(name)
	if err != nil {
		return err
	}
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
				if strings.Index(line, "{") < 0 {
					return fmt.Errorf("error processing serialized object - we don't support nested types: %s", line)
				}
				inContent = true
			} else {
				if strings.Index(line, "}") < 0 {
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

		if inStringArray(valName, ignore) {
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

	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	combined := strings.Join(newFile, "\n")
	combined = strings.TrimRight(combined, "\r\n ")
	_, err = writer.WriteString(combined)
	if err == nil {
		writer.Flush()
	}
	return err
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

func inStringArray(item string, set []string) bool {
	for _, s := range set {
		if item == s {
			return true
		}
	}
	return false
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
