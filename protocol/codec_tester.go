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

package protocol

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"reflect"
	"testing"

	"github.com/algorand/msgp/msgp"
	"github.com/stretchr/testify/require"
)

const debugCodecTester = false

type msgpMarshalUnmarshal interface {
	msgp.Marshaler
	msgp.Unmarshaler
}

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
	err := randomizeValue(v.Elem())
	return v.Interface(), err
}

func randomizeValue(v reflect.Value) error {
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
			if f.PkgPath != "" && !f.Anonymous {
				// unexported
				continue
			}

			err := randomizeValue(v.Field(i))
			if err != nil {
				return err
			}
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			err := randomizeValue(v.Index(i))
			if err != nil {
				return err
			}
		}
	case reflect.Slice:
		l := rand.Int() % 32
		s := reflect.MakeSlice(v.Type(), l, l)
		for i := 0; i < l; i++ {
			err := randomizeValue(s.Index(i))
			if err != nil {
				return err
			}
		}
		v.Set(s)
	case reflect.Bool:
		v.SetBool(rand.Uint32()%2 == 0)
	case reflect.Map:
		mt := v.Type()
		v.Set(reflect.MakeMap(mt))
		l := rand.Int() % 32
		for i := 0; i < l; i++ {
			mk := reflect.New(mt.Key())
			err := randomizeValue(mk.Elem())
			if err != nil {
				return err
			}

			mv := reflect.New(mt.Elem())
			err = randomizeValue(mv.Elem())
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
		require.NoError(t, err)
	}
}
