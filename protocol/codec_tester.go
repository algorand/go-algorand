// Copyright (C) 2019 Algorand, Inc.
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
	"io/ioutil"
	"reflect"

	"github.com/zeldovich/msgp/msgp"
)

type MsgpMarshalUnmarshal interface {
	msgp.Marshaler
	msgp.Unmarshaler
}

func oneOf(n int) bool {
	return (rand.Int() % n) == 0
}

func RandomizeObject(template interface{}) (interface{}, error) {
	tt := reflect.TypeOf(template)
	if tt.Kind() != reflect.Ptr {
		return nil, fmt.Errorf("RandomizeObject: must be ptr")
	}

	v := reflect.New(tt.Elem())
	err := RandomizeValue(v.Elem())
	return v.Interface(), err
}

func RandomizeValue(v reflect.Value) error {
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
			if f.PkgPath != "" {
				// unexported
				continue
			}

			err := RandomizeValue(v.Field(i))
			if err != nil {
				return err
			}
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			err := RandomizeValue(v.Index(i))
			if err != nil {
				return err
			}
		}
	case reflect.Slice:
		l := rand.Int() % 32
		s := reflect.MakeSlice(v.Type(), l, l)
		for i := 0; i < l; i++ {
			err := RandomizeValue(s.Index(i))
			if err != nil {
				return err
			}
		}
		v.Set(s)
	case reflect.Bool:
		v.SetBool(rand.Uint32() % 2 == 0)
	default:
		return fmt.Errorf("unsupported object kind %v", v.Kind())
	}
	return nil
}

func EncodingTest(template MsgpMarshalUnmarshal) error {
	v, err := RandomizeObject(template)
	if err != nil {
		return err
	}

	e1 := EncodeMsgp(v.(msgp.Marshaler))
	e2 := EncodeReflect(v)

	// for debug, write out the encodings to a file
	if true {
		ioutil.WriteFile("/tmp/e1", e1, 0666)
		ioutil.WriteFile("/tmp/e2", e2, 0666)
	}

	if !reflect.DeepEqual(e1, e2) {
		return fmt.Errorf("encoding mismatch for %v: %v != %v", v, e1, e2)
	}

	v1 := reflect.New(reflect.TypeOf(template).Elem()).Interface().(MsgpMarshalUnmarshal)
	v2 := reflect.New(reflect.TypeOf(template).Elem()).Interface().(MsgpMarshalUnmarshal)

	err = DecodeMsgp(e1, v1)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(v, v1) {
		return fmt.Errorf("decoding msgp mismatch: %v != %v", v, v1)
	}

	err = DecodeReflect(e1, v2)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(v, v2) {
		return fmt.Errorf("decoding reflect mismatch: %v != %v", v, v2)
	}

	return nil
}
