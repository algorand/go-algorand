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

package protocol

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/msgp/msgp"
	"github.com/stretchr/testify/require"
)

const debugCodecTester = false

type msgpMarshalUnmarshal interface {
	msgp.Marshaler
	msgp.Unmarshaler
}

var rawMsgpType = reflect.TypeOf(msgp.Raw{})
var errSkipRawMsgpTesting = fmt.Errorf("skipping msgp.Raw serializing, since it won't be the same across go-codec and msgp")

func oneOf(n int) bool {
	return (rand.Int() % n) == 0
}

// RandomizeObject returns a random object of the same type as template
func RandomizeObject(template interface{}) (interface{}, error) {
	tt := reflect.TypeOf(template)
	if tt.Kind() != reflect.Ptr {
		return nil, fmt.Errorf("RandomizeObject: must be ptr")
	}

	v := reflect.New(tt.Elem())
	err := randomizeValue(v.Elem(), tt.String(), "")
	return v.Interface(), err
}

func parseStructTags(structTag string) map[string]string {
	tagsMap := map[string]string{}

	for _, tag := range strings.Split(reflect.StructTag(structTag).Get("codec"), ",") {
		elements := strings.Split(tag, "=")
		if len(elements) != 2 {
			continue
		}
		tagsMap[elements[0]] = elements[1]
	}
	return tagsMap
}

var printWarningOnce deadlock.Mutex
var warningMessages map[string]bool

func printWarning(warnMsg string) {
	printWarningOnce.Lock()
	defer printWarningOnce.Unlock()
	if warningMessages == nil {
		warningMessages = make(map[string]bool)
	}
	if !warningMessages[warnMsg] {
		warningMessages[warnMsg] = true
		fmt.Printf("%s\n", warnMsg)
	}
}

var testedDatatypesForAllocBound = map[string]bool{}
var testedDatatypesForAllocBoundMu = deadlock.Mutex{}

func checkBoundsLimitingTag(val reflect.Value, datapath string, structTag string) (hasAllocBound bool) {
	if structTag == "" {
		return
	}

	testedDatatypesForAllocBoundMu.Lock()
	defer testedDatatypesForAllocBoundMu.Unlock()
	// make sure we test each datatype only once.
	if val.Type().Name() == "" {
		if testedDatatypesForAllocBound[datapath] {
			hasAllocBound = true
			return
		}
		testedDatatypesForAllocBound[datapath] = true
	} else {
		if testedDatatypesForAllocBound[val.Type().Name()] {
			hasAllocBound = true
			return
		}
		testedDatatypesForAllocBound[val.Type().Name()] = true
	}

	var objType string
	if val.Kind() == reflect.Slice {
		objType = "slice"
	} else if val.Kind() == reflect.Map {
		objType = "map"
	}

	tagsMap := parseStructTags(structTag)

	if tagsMap["allocbound"] == "-" {
		printWarning(fmt.Sprintf("%s %s have an unbounded allocbound defined", objType, datapath))
		return
	}
	if _, have := tagsMap["allocbound"]; have {
		hasAllocBound = true
		return
	}

	if val.Type().Name() != "" {
		// does any of the go files in the package directroy has the msgp:allocbound defined for that datatype ?
		gopath := os.Getenv("GOPATH")
		packageFilesPath := path.Join(gopath, "src", val.Type().PkgPath())
		packageFiles := []string{}
		filepath.Walk(packageFilesPath, func(path string, info os.FileInfo, err error) error {
			if filepath.Ext(path) == ".go" {
				packageFiles = append(packageFiles, path)
			}
			return nil
		})
		for _, packageFile := range packageFiles {
			fileBytes, err := ioutil.ReadFile(packageFile)
			if err != nil {
				continue
			}
			if strings.Index(string(fileBytes), fmt.Sprintf("msgp:allocbound %s", val.Type().Name())) != -1 {
				// message pack alloc bound definition was found.
				hasAllocBound = true
				return
			}
		}
	}
	printWarning(fmt.Sprintf("%s %s does not have an allocbound defined - %s", objType, datapath, val.Type().PkgPath()))
	return
}

func randomizeValue(v reflect.Value, datapath string, tag string) error {
	if oneOf(5) {
		// Leave zero value
		return nil
	}

	switch v.Kind() {
	case reflect.Uint, reflect.Uintptr, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(rand.Uint64())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(rand.Uint64()))
	case reflect.String:
		var buf []byte
		len := rand.Int() % 64
		for i := 0; i < len; i++ {
			buf = append(buf, byte(rand.Uint32()))
		}
		v.SetString(string(buf))
	case reflect.Struct:
		st := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := st.Field(i)
			tag := f.Tag

			if f.PkgPath != "" && !f.Anonymous {
				// unexported
				continue
			}
			if rawMsgpType == f.Type {
				return errSkipRawMsgpTesting
			}
			err := randomizeValue(v.Field(i), datapath+"/"+f.Name, string(tag))
			if err != nil {
				return err
			}
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			err := randomizeValue(v.Index(i), fmt.Sprintf("%s/%d", datapath, i), "")
			if err != nil {
				return err
			}
		}
	case reflect.Slice:
		hasAllocBound := checkBoundsLimitingTag(v, datapath, tag)
		l := rand.Int() % 32
		if hasAllocBound {
			l = 1
		}
		s := reflect.MakeSlice(v.Type(), l, l)
		for i := 0; i < l; i++ {
			err := randomizeValue(s.Index(i), fmt.Sprintf("%s/%d", datapath, i), "")
			if err != nil {
				return err
			}
		}
		v.Set(s)
	case reflect.Bool:
		v.SetBool(rand.Uint32()%2 == 0)
	case reflect.Map:
		hasAllocBound := checkBoundsLimitingTag(v, datapath, tag)
		mt := v.Type()
		v.Set(reflect.MakeMap(mt))
		l := rand.Int() % 32
		if hasAllocBound {
			l = 1
		}
		for i := 0; i < l; i++ {
			mk := reflect.New(mt.Key())
			err := randomizeValue(mk.Elem(), fmt.Sprintf("%s/%d", datapath, i), "")
			if err != nil {
				return err
			}

			mv := reflect.New(mt.Elem())
			err = randomizeValue(mv.Elem(), fmt.Sprintf("%s/%d", datapath, i), "")
			if err != nil {
				return err
			}

			v.SetMapIndex(mk.Elem(), mv.Elem())
		}
	default:
		return fmt.Errorf("unsupported object kind %v", v.Kind())
	}
	return nil
}

// EncodingTest tests that our two msgpack codecs (msgp and go-codec)
// agree on encodings and decodings of random values of the type of
// template, returning an error if there is a mismatch.
func EncodingTest(template msgpMarshalUnmarshal) error {
	v0, err := RandomizeObject(template)
	if err != nil {
		return err
	}

	if debugCodecTester {
		ioutil.WriteFile("/tmp/v0", []byte(fmt.Sprintf("%#v", v0)), 0666)
	}

	e1 := EncodeMsgp(v0.(msgp.Marshaler))
	e2 := EncodeReflect(v0)

	// for debug, write out the encodings to a file
	if debugCodecTester {
		ioutil.WriteFile("/tmp/e1", e1, 0666)
		ioutil.WriteFile("/tmp/e2", e2, 0666)
	}

	if !reflect.DeepEqual(e1, e2) {
		return fmt.Errorf("encoding mismatch for %v: %v != %v", v0, e1, e2)
	}

	v1 := reflect.New(reflect.TypeOf(template).Elem()).Interface().(msgpMarshalUnmarshal)
	v2 := reflect.New(reflect.TypeOf(template).Elem()).Interface().(msgpMarshalUnmarshal)

	err = DecodeMsgp(e1, v1)
	if err != nil {
		return err
	}

	err = DecodeReflect(e1, v2)
	if err != nil {
		return err
	}

	if debugCodecTester {
		ioutil.WriteFile("/tmp/v1", []byte(fmt.Sprintf("%#v", v1)), 0666)
		ioutil.WriteFile("/tmp/v2", []byte(fmt.Sprintf("%#v", v2)), 0666)
	}

	// At this point, it might be that v differs from v1 and v2,
	// because there are multiple representations (e.g., an empty
	// byte slice could be either nil or a zero-length slice).
	// But we require that the msgp codec match the behavior of
	// go-codec.

	if !reflect.DeepEqual(v1, v2) {
		return fmt.Errorf("decoding mismatch")
	}

	// Finally, check that the value encodes back to the same encoding.

	ee1 := EncodeMsgp(v1)
	ee2 := EncodeReflect(v1)

	if debugCodecTester {
		ioutil.WriteFile("/tmp/ee1", ee1, 0666)
		ioutil.WriteFile("/tmp/ee2", ee2, 0666)
	}

	if !reflect.DeepEqual(e1, ee1) {
		return fmt.Errorf("re-encoding mismatch: e1 != ee1")
	}
	if !reflect.DeepEqual(e1, ee2) {
		return fmt.Errorf("re-encoding mismatch: e1 != ee2")
	}

	return nil
}

// RunEncodingTest runs several iterations of encoding/decoding
// consistency testing of object type specified by template.
func RunEncodingTest(t *testing.T, template msgpMarshalUnmarshal) {
	for i := 0; i < 1000; i++ {
		err := EncodingTest(template)
		if err == errSkipRawMsgpTesting {
			// we want to skip the serilization test in this case.
			t.Skip()
			return
		}
		require.NoError(t, err)
	}
}
