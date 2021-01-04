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

package transcode

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/algorand/go-codec/codec"
)

type decoder interface {
	Decode(v interface{}) error
}

// Transcode turns msgpack to JSON or JSON to msgpack
func Transcode(mpToJSON bool, base32Encoding, strictJSON bool, in io.Reader, out io.Writer) error {
	canonicalMsgpackHandle := new(codec.MsgpackHandle)
	canonicalMsgpackHandle.ErrorIfNoField = true
	canonicalMsgpackHandle.ErrorIfNoArrayExpand = true
	canonicalMsgpackHandle.Canonical = true
	canonicalMsgpackHandle.RawToString = true
	canonicalMsgpackHandle.WriteExt = true
	canonicalMsgpackHandle.PositiveIntUnsigned = true

	jsonHandle := new(codec.JsonHandle)
	jsonHandle.ErrorIfNoField = true
	jsonHandle.ErrorIfNoArrayExpand = true
	jsonHandle.Canonical = true
	jsonHandle.Indent = 2

	var dec decoder
	var enc *codec.Encoder

	if mpToJSON {
		dec = codec.NewDecoder(in, canonicalMsgpackHandle)
		enc = codec.NewEncoder(out, jsonHandle)
	} else {
		// We use the JSON decoder from Go's stdlib because the go-codec
		// JSON decoder does not properly deal with EOF.
		jsonDec := json.NewDecoder(in)
		jsonDec.UseNumber()
		dec = jsonDec
		enc = codec.NewEncoder(out, canonicalMsgpackHandle)
	}

	for {
		var a interface{}
		err := dec.Decode(&a)
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		if mpToJSON {
			a = toJSON(a, base32Encoding, strictJSON)
		} else {
			a = fromJSON(a)
		}

		err = enc.Encode(a)
		if err != nil {
			return err
		}

		if mpToJSON {
			out.Write([]byte("\n"))
		}
	}
}

func toJSON(a interface{}, base32Encoding, strictJSON bool) interface{} {
	switch v := a.(type) {
	case map[interface{}]interface{}:
		r := make(map[interface{}]interface{})
		for k, e := range v {
			// Special case: if key is a string, and entry is
			// a []byte, base64-encode the entry and append
			// ":b64" to the key (or, if the base32Encoding flag
			// is set, base32-encode and append ":b32").
			ks, ok1 := k.(string)
			eb, ok2 := e.([]byte)

			if ok1 && ok2 {
				if base32Encoding {
					r[fmt.Sprintf("%s:b32", ks)] = base32.StdEncoding.EncodeToString(eb)
				} else {
					r[fmt.Sprintf("%s:b64", ks)] = base64.StdEncoding.EncodeToString(eb)
				}
			} else {
				if strictJSON {
					k = fmt.Sprintf("%v", k)
				}
				kenc := toJSON(k, base32Encoding, strictJSON)
				eenc := toJSON(e, base32Encoding, strictJSON)
				r[kenc] = eenc
			}
		}
		return r

	case []interface{}:
		r := make([]interface{}, 0)
		for _, e := range v {
			eenc := toJSON(e, base32Encoding, strictJSON)
			r = append(r, eenc)
		}
		return r

	default:
		return a
	}
}

func fromJSON(a interface{}) interface{} {
	switch v := a.(type) {
	case map[interface{}]interface{}:
		r := make(map[interface{}]interface{})
		for k, e := range v {
			// Special case: if key is a string, and ends in
			// ":b64", and entry is a string, then base64-decode
			// the entry and drop the ":b64" from the key.
			// Same for ":b32" and base32-decoding.
			ks, ok1 := k.(string)
			es, ok2 := e.(string)

			if ok1 && ok2 && strings.HasSuffix(ks, ":b64") {
				eb, err := base64.StdEncoding.DecodeString(es)
				if err != nil {
					panic(err)
				}

				r[ks[:len(ks)-4]] = eb
			} else if ok1 && ok2 && strings.HasSuffix(ks, ":b32") {
				eb, err := base32.StdEncoding.DecodeString(es)
				if err != nil {
					panic(err)
				}

				r[ks[:len(ks)-4]] = eb
			} else {
				r[fromJSON(k)] = fromJSON(e)
			}
		}
		return r

	case map[string]interface{}:
		r := make(map[string]interface{})
		for k, e := range v {
			// Special case: if key ends in ":b64", and entry
			// is a string, then base64-decode the entry and
			// drop the ":b64" from the key.  Same for ":b32"
			// and base32-decoding.
			es, ok := e.(string)

			if ok && strings.HasSuffix(k, ":b64") {
				eb, err := base64.StdEncoding.DecodeString(es)
				if err != nil {
					panic(err)
				}

				r[k[:len(k)-4]] = eb
			} else if ok && strings.HasSuffix(k, ":b32") {
				eb, err := base32.StdEncoding.DecodeString(es)
				if err != nil {
					panic(err)
				}

				r[k[:len(k)-4]] = eb
			} else {
				r[k] = fromJSON(e)
			}
		}
		return r

	case []interface{}:
		r := make([]interface{}, 0)
		for _, e := range v {
			r = append(r, fromJSON(e))
		}
		return r

	case json.Number:
		s := v.String()
		i64, err := strconv.ParseInt(s, 10, 64)
		if err == nil {
			return i64
		}

		u64, err := strconv.ParseUint(s, 10, 64)
		if err == nil {
			return u64
		}

		return s

	default:
		return a
	}
}
