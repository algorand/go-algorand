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

package protocol

import (
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/msgp/msgp"
	"github.com/stretchr/testify/require"
)

const debugCodecTester = false

type msgpMarshalUnmarshal interface {
	msgp.Marshaler
	msgp.Unmarshaler
}

var rawMsgpType = reflect.TypeFor[msgp.Raw]()
var errSkipRawMsgpTesting = fmt.Errorf("skipping msgp.Raw serializing, since it won't be the same across go-codec and msgp")

func oneOf(n int) bool {
	return (rand.Int() % n) == 0
}

type randomizeObjectCfg struct {
	// ZeroesEveryN will increase the chance of zero values being generated.
	ZeroesEveryN int
	// AllUintSizes will be equally likely to generate 8-bit, 16-bit, 32-bit, or 64-bit uints.
	AllUintSizes bool
	// MaxCollectionLen bounds randomized slice/map lengths when positive.
	MaxCollectionLen int
	// SilenceAllocWarnings suppresses allocbound warning prints.
	SilenceAllocWarnings bool
}

// RandomizeObjectOption is an option for RandomizeObject
type RandomizeObjectOption func(*randomizeObjectCfg)

// RandomizeObjectWithZeroesEveryN sets the chance of zero values being generated (one in n)
func RandomizeObjectWithZeroesEveryN(n int) RandomizeObjectOption {
	return func(cfg *randomizeObjectCfg) { cfg.ZeroesEveryN = n }
}

// RandomizeObjectWithAllUintSizes will be equally likely to generate 8-bit, 16-bit, 32-bit, or 64-bit uints.
func RandomizeObjectWithAllUintSizes() RandomizeObjectOption {
	return func(cfg *randomizeObjectCfg) { cfg.AllUintSizes = true }
}

// RandomizeObjectSilenceAllocWarnings silences allocbound warning prints.
func RandomizeObjectSilenceAllocWarnings() RandomizeObjectOption {
	return func(cfg *randomizeObjectCfg) { cfg.SilenceAllocWarnings = true }
}

// RandomizeObjectWithMaxCollectionLen limits randomized slice/map lengths to n (when n>0).
func RandomizeObjectWithMaxCollectionLen(n int) RandomizeObjectOption {
	return func(cfg *randomizeObjectCfg) {
		if n > 0 {
			cfg.MaxCollectionLen = n
		}
	}
}

// RandomizeObject returns a random object of the same type as template
func RandomizeObject(template interface{}, opts ...RandomizeObjectOption) (interface{}, error) {
	cfg := randomizeObjectCfg{}
	for _, opt := range opts {
		opt(&cfg)
	}
	tt := reflect.TypeOf(template)
	if tt.Kind() != reflect.Ptr {
		return nil, fmt.Errorf("RandomizeObject: must be ptr")
	}
	v := reflect.New(tt.Elem())
	changes := int(^uint(0) >> 1)
	err := randomizeValue(v.Elem(), 0, tt.String(), "", &changes, cfg, make(map[reflect.Type]bool))
	return v.Interface(), err
}

// RandomizeObjectField returns a random object of the same type as template where a single field was modified.
func RandomizeObjectField(template interface{}, opts ...RandomizeObjectOption) (interface{}, error) {
	cfg := randomizeObjectCfg{}
	for _, opt := range opts {
		opt(&cfg)
	}
	tt := reflect.TypeOf(template)
	if tt.Kind() != reflect.Ptr {
		return nil, fmt.Errorf("RandomizeObject: must be ptr")
	}
	v := reflect.New(tt.Elem())
	changes := 1
	err := randomizeValue(v.Elem(), 0, tt.String(), "", &changes, cfg, make(map[reflect.Type]bool))
	return v.Interface(), err
}

func parseStructTags(structTag string) map[string]string {
	tagsMap := map[string]string{}

	for tag := range strings.SplitSeq(reflect.StructTag(structTag).Get("codec"), ",") {
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

func checkMsgpAllocBoundDirective(dataType reflect.Type) bool {
	// does any of the go files in the package directory has the msgp:allocbound defined for that datatype ?
	gopath := os.Getenv("GOPATH")
	const repositoryRoot = "go-algorand/"
	const thisFile = "protocol/codec_tester.go"
	packageFilesPath := path.Join(gopath, "src", dataType.PkgPath())

	if _, err := os.Stat(packageFilesPath); os.IsNotExist(err) {
		// no such directory. Try to assemble the path based on the current working directory.
		cwd, err := os.Getwd()
		if err != nil {
			return false
		}
		if cwdPaths := strings.SplitAfter(cwd, repositoryRoot); len(cwdPaths) == 2 {
			cwd = cwdPaths[0]
		} else {
			// try to assemble the project directory based on the current stack frame
			_, file, _, ok := runtime.Caller(0)
			if !ok {
				return false
			}
			cwd = strings.TrimSuffix(file, thisFile)
		}

		relPkdPath := strings.SplitAfter(dataType.PkgPath(), repositoryRoot)
		if len(relPkdPath) != 2 {
			return false
		}
		packageFilesPath = path.Join(cwd, relPkdPath[1])
		if _, err := os.Stat(packageFilesPath); os.IsNotExist(err) {
			return false
		}
	}
	packageFiles := []string{}
	filepath.Walk(packageFilesPath, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".go" {
			packageFiles = append(packageFiles, path)
		}
		return nil
	})
	for _, packageFile := range packageFiles {
		fileBytes, err := os.ReadFile(packageFile)
		if err != nil {
			continue
		}
		if strings.Contains(string(fileBytes), fmt.Sprintf("msgp:allocbound %s", dataType.Name())) {
			// message pack alloc bound definition was found.
			return true
		}
	}
	return false
}

func checkBoundsLimitingTag(val reflect.Value, datapath string, structTag string, cfg randomizeObjectCfg) (hasAllocBound bool) {
	var objType string
	if val.Kind() == reflect.Slice {
		objType = "slice"
	} else if val.Kind() == reflect.Map {
		objType = "map"
	} else if val.Kind() == reflect.String {
		objType = "string"
	}

	if structTag != "" {
		tagsMap := parseStructTags(structTag)

		if tagsMap["allocbound"] == "-" {
			if !cfg.SilenceAllocWarnings {
				printWarning(fmt.Sprintf("%s %s have an unbounded allocbound defined", objType, datapath))
			}
			return
		}

		if _, have := tagsMap["allocbound"]; have {
			hasAllocBound = true
			testedDatatypesForAllocBoundMu.Lock()
			defer testedDatatypesForAllocBoundMu.Unlock()
			if val.Type().Name() == "" {
				testedDatatypesForAllocBound[datapath] = true
			} else {
				testedDatatypesForAllocBound[val.Type().Name()] = true
			}
			return
		}
	}
	// no struct tag, or have a struct tag with no allocbound.
	if val.Type().Name() != "" {
		testedDatatypesForAllocBoundMu.Lock()
		var exists bool
		hasAllocBound, exists = testedDatatypesForAllocBound[val.Type().Name()]
		testedDatatypesForAllocBoundMu.Unlock()
		if !exists {
			// does any of the go files in the package directory has the msgp:allocbound defined for that datatype ?
			hasAllocBound = checkMsgpAllocBoundDirective(val.Type())
			testedDatatypesForAllocBoundMu.Lock()
			testedDatatypesForAllocBound[val.Type().Name()] = hasAllocBound
			testedDatatypesForAllocBoundMu.Unlock()
			return
		} else if hasAllocBound {
			return
		}
	}

	if val.Type().Kind() == reflect.Slice || val.Type().Kind() == reflect.Map || val.Type().Kind() == reflect.Array {
		if !cfg.SilenceAllocWarnings {
			printWarning(fmt.Sprintf("%s %s does not have an allocbound defined for %s %s", objType, datapath, val.Type().String(), val.Type().PkgPath()))
		}
	}
	return
}

func randomizeValue(v reflect.Value, depth int, datapath string, tag string, remainingChanges *int, cfg randomizeObjectCfg, seenTypes map[reflect.Type]bool) error {
	if *remainingChanges == 0 {
		return nil
	}
	if depth != 0 && cfg.ZeroesEveryN > 0 && oneOf(cfg.ZeroesEveryN) {
		// Leave zero value
		return nil
	}

	/* Consider cutting off recursive structures by stopping at some datapath depth.

	    if len(datapath) > 200 {
			// Cut off recursive structures
			return nil
		}
	*/

	switch v.Kind() {
	case reflect.Uint, reflect.Uintptr, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if strings.HasSuffix(datapath, "/HashType") &&
			strings.HasSuffix(v.Type().PkgPath(), "go-algorand/crypto") && v.Type().Name() == "HashType" {
			// generate value that will avoid protocol.ErrInvalidObject from HashType.Validate()
			v.SetUint(rand.Uint64() % 3) // 3 is crypto.MaxHashType
		} else {
			var num uint64
			if cfg.AllUintSizes {
				switch rand.Intn(4) {
				case 0: // fewer than 8 bits
					num = uint64(rand.Intn(1 << 8)) // 0 to 255
				case 1: // fewer than 16 bits
					num = uint64(rand.Intn(1 << 16)) // 0 to 65535
				case 2: // fewer than 32 bits
					num = uint64(rand.Uint32()) // 0 to 2^32-1
				case 3: // fewer than 64 bits
					num = rand.Uint64() // 0 to 2^64-1
				}
			} else {
				num = rand.Uint64()
			}
			v.SetUint(num)
		}
		*remainingChanges--
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(rand.Uint64()))
		*remainingChanges--
	case reflect.String:
		hasAllocBound := checkBoundsLimitingTag(v, datapath, tag, cfg)
		var buf []byte
		var len int
		if strings.HasSuffix(v.Type().PkgPath(), "go-algorand/agreement") && v.Type().Name() == "serializableError" {
			// Don't generate empty strings for serializableError since nil values of *string type
			// will serialize differently by msgp and go-codec
			len = rand.Int()%63 + 1
		} else if strings.HasSuffix(v.Type().PkgPath(), "go-algorand/protocol") && v.Type().Name() == "TxType" {
			// protocol.TxType has allocbound defined as a custom msgp:allocbound directive so not supported by reflect
			len = rand.Int()%6 + 1
		} else if hasAllocBound {
			len = 1
		} else {
			len = rand.Int() % 64
		}
		for i := 0; i < len; i++ {
			buf = append(buf, byte(rand.Uint32()))
		}
		v.SetString(string(buf))
		*remainingChanges--
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		err := randomizeValue(reflect.Indirect(v), depth+1, datapath, tag, remainingChanges, cfg, seenTypes)
		if err != nil {
			return err
		}
	case reflect.Struct:
		st := v.Type()
		if !seenTypes[st] {
			seenTypes[st] = true
		} else {
			return nil
		}
		fieldsOrder := rand.Perm(v.NumField())
		for i := 0; i < v.NumField(); i++ {
			fieldIdx := fieldsOrder[i]
			f := st.Field(fieldIdx)
			tag := f.Tag

			if f.PkgPath != "" && !f.Anonymous {
				// unexported
				continue
			}
			if st.Name() == "messageEvent" && f.Name == "Tail" {
				// Don't try and set the Tail field since it's recursive
				continue
			}
			if rawMsgpType == f.Type {
				return errSkipRawMsgpTesting
			}
			err := randomizeValue(v.Field(fieldIdx), depth+1, datapath+"/"+f.Name, string(tag), remainingChanges, cfg, seenTypes)
			if err != nil {
				return err
			}
			if *remainingChanges == 0 {
				break
			}
			*remainingChanges--
		}
	case reflect.Array:
		indicesOrder := rand.Perm(v.Len())
		for i := 0; i < v.Len(); i++ {
			err := randomizeValue(v.Index(indicesOrder[i]), depth+1, fmt.Sprintf("%s/%d", datapath, indicesOrder[i]), "", remainingChanges, cfg, seenTypes)
			if err != nil {
				return err
			}
			if *remainingChanges == 0 {
				break
			}
			*remainingChanges--
		}
	case reflect.Slice:
		// we don't want to allocate a slice with size of 0. This is because decoding and encoding this slice
		// will result in nil and not slice of size 0
		maxLen := 31
		if cfg.MaxCollectionLen > 0 {
			maxLen = min(maxLen, cfg.MaxCollectionLen)
		}
		l := rand.Intn(maxLen) + 1

		hasAllocBound := checkBoundsLimitingTag(v, datapath, tag, cfg)
		if hasAllocBound {
			l = 1
		}
		s := reflect.MakeSlice(v.Type(), l, l)
		indicesOrder := rand.Perm(l)
		for i := 0; i < l; i++ {
			err := randomizeValue(s.Index(indicesOrder[i]), depth+1, fmt.Sprintf("%s/%d", datapath, indicesOrder[i]), "", remainingChanges, cfg, seenTypes)
			if err != nil {
				return err
			}
			if *remainingChanges == 0 {
				break
			}
		}
		v.Set(s)
		*remainingChanges--
	case reflect.Bool:
		v.SetBool(rand.Uint32()%2 == 0)
		*remainingChanges--
	case reflect.Map:
		hasAllocBound := checkBoundsLimitingTag(v, datapath, tag, cfg)
		mt := v.Type()
		v.Set(reflect.MakeMap(mt))
		maxLen := 32
		if cfg.MaxCollectionLen > 0 {
			// preserve possibility of zero entries while capping positive lengths
			maxLen = min(maxLen, cfg.MaxCollectionLen+1)
		}
		l := rand.Intn(maxLen)
		if hasAllocBound {
			l = 1
		}
		indicesOrder := rand.Perm(l)
		for i := 0; i < l; i++ {
			mk := reflect.New(mt.Key())
			err := randomizeValue(mk.Elem(), depth+1, fmt.Sprintf("%s/%d", datapath, indicesOrder[i]), "", remainingChanges, cfg, seenTypes)
			if err != nil {
				return err
			}

			mv := reflect.New(mt.Elem())
			err = randomizeValue(mv.Elem(), depth+1, fmt.Sprintf("%s/%d", datapath, indicesOrder[i]), "", remainingChanges, cfg, seenTypes)
			if err != nil {
				return err
			}

			v.SetMapIndex(mk.Elem(), mv.Elem())
			if *remainingChanges == 0 {
				break
			}
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
		err = os.WriteFile("/tmp/v0", []byte(fmt.Sprintf("%#v", v0)), 0666)
		if err != nil {
			return err
		}

	}

	e1 := EncodeMsgp(v0.(msgp.Marshaler))
	e2 := EncodeReflect(v0)

	// for debug, write out the encodings to a file
	if debugCodecTester {
		err = os.WriteFile("/tmp/e1", e1, 0666)
		if err != nil {
			return err
		}
		err = os.WriteFile("/tmp/e2", e2, 0666)
		if err != nil {
			return err
		}
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
		err = os.WriteFile("/tmp/v1", []byte(fmt.Sprintf("%#v", v1)), 0666)
		if err != nil {
			return err
		}
		err = os.WriteFile("/tmp/v2", []byte(fmt.Sprintf("%#v", v2)), 0666)
		if err != nil {
			return err
		}
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
		err = os.WriteFile("/tmp/ee1", ee1, 0666)
		if err != nil {
			return err
		}
		err = os.WriteFile("/tmp/ee2", ee2, 0666)
		if err != nil {
			return err
		}
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
	partitiontest.PartitionTest(t)
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
