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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sort"

	"github.com/algorand/go-algorand/config"
)

const localDefaultsFileName = "./local_defaults.go"
const exampleFileName = "../installer/config.json.example"

func main() {
	localDefaultsBytes, err := ioutil.ReadFile(localDefaultsFileName)
	if err != nil {
		fmt.Printf("Unable to load file %s : %v", localDefaultsFileName, err)
		os.Exit(1)
	}

	// find start location of localDefault
	startIdx := bytes.Index(localDefaultsBytes, []byte("var defaultLocal"))
	if startIdx == -1 {
		fmt.Printf("Unable to find `var defaultLocalX` in local_defaults.go file.")
		os.Exit(1)
	}
	endIdx := bytes.Index(localDefaultsBytes[startIdx:], []byte("\n\n"))
	if startIdx == -1 {
		fmt.Printf("Unable to find empty line after `var defaultLocalX` in local_defaults.go file.")
		os.Exit(1)
	}
	endIdx += startIdx

	autoDefaultsBytes := []byte(prettyPrint(config.AutogenLocal, "go"))

	outBuf := make([]byte, len(localDefaultsBytes)-(endIdx-startIdx)+len(autoDefaultsBytes))
	copy(outBuf[:], localDefaultsBytes[:startIdx])
	copy(outBuf[startIdx:], autoDefaultsBytes)
	copy(outBuf[startIdx+len(autoDefaultsBytes):], localDefaultsBytes[endIdx:])
	err = ioutil.WriteFile(localDefaultsFileName, outBuf, 0644)
	if err != nil {
		fmt.Printf("Unable to write file %s : %v", localDefaultsFileName, err)
		os.Exit(1)
	}

	// generate an update json for the example as well.
	autoDefaultsBytes = []byte(prettyPrint(config.AutogenLocal, "json"))
	err = ioutil.WriteFile(exampleFileName, autoDefaultsBytes, 0644)
	if err != nil {
		fmt.Printf("Unable to write file %s : %v", exampleFileName, err)
		os.Exit(1)
	}
}

type byFieldName []reflect.StructField

func (a byFieldName) Len() int      { return len(a) }
func (a byFieldName) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byFieldName) Less(i, j int) bool {
	if a[i].Name == "Version" {
		return true
	} else if a[j].Name == "Version" {
		return false
	}
	return a[i].Name < a[j].Name
}

func prettyPrint(c config.Local, format string) (out string) {
	localType := reflect.TypeOf(c)

	fields := []reflect.StructField{}
	for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
		fields = append(fields, localType.Field(fieldNum))
	}

	sort.Sort(byFieldName(fields))

	if format == "go" {
		out = "var defaultLocal = Local{\n"
	} else {
		out = "{\n"
	}

	for _, field := range fields {
		switch field.Type.Kind() {
		case reflect.Bool:
			v := reflect.ValueOf(&c).Elem().FieldByName(field.Name).Bool()
			if format == "go" {
				out = fmt.Sprintf("%s\t%s:\t%v,\n", out, field.Name, v)
			} else {
				out = fmt.Sprintf("%s    \"%s\": %v,\n", out, field.Name, v)
			}
		case reflect.Int32:
			fallthrough
		case reflect.Int:
			fallthrough
		case reflect.Int64:
			v := reflect.ValueOf(&c).Elem().FieldByName(field.Name).Int()
			if format == "go" {
				out = fmt.Sprintf("%s\t%s:\t%d,\n", out, field.Name, v)
			} else {
				out = fmt.Sprintf("%s    \"%s\": %d,\n", out, field.Name, v)
			}
		case reflect.Uint32:
			fallthrough
		case reflect.Uint:
			fallthrough
		case reflect.Uint64:
			v := reflect.ValueOf(&c).Elem().FieldByName(field.Name).Uint()
			if format == "go" {
				out = fmt.Sprintf("%s\t%s:\t%d,\n", out, field.Name, v)
			} else {
				out = fmt.Sprintf("%s    \"%s\": %d,\n", out, field.Name, v)
			}
		case reflect.String:
			v := reflect.ValueOf(&c).Elem().FieldByName(field.Name).String()
			if format == "go" {
				out = fmt.Sprintf("%s\t%s:\t\"%s\",\n", out, field.Name, v)
			} else {
				out = fmt.Sprintf("%s    \"%s\": \"%s\",\n", out, field.Name, v)
			}
		case reflect.Map:
			if reflect.ValueOf(&c).Elem().FieldByName(field.Name).Len() == 0 {
				if format == "go" {
					// it's an empty map; good, we know how to initialize empty maps.
					mapKeysType := field.Type.Key()
					mapValueType := field.Type.Elem()

					out = fmt.Sprintf("%s\t%s:\tmap[%s]%s{},\n", out, field.Name, mapKeysType, mapValueType)
				} else {
					out = fmt.Sprintf("%s    \"%s\": {},\n", out, field.Name)
				}
			} else {
				panic(fmt.Sprintf("non-empty default maps data type encountered when reflecting on config.Local datatype %s", field.Name))
			}
		default:
			panic(fmt.Sprintf("unsupported data type (%s) encountered when reflecting on config.Local datatype %s", field.Type.Kind(), field.Name))
		}
	}
	out = out + "}"
	return
}
