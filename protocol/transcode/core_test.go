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

package transcode

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func transcodeNoError(t *testing.T, mpToJSON bool, in io.ReadCloser, out io.WriteCloser) {
	defer in.Close()
	defer out.Close()
	err := Transcode(mpToJSON, false, false, in, out)
	require.NoError(t, err)
}

func testIdempotentRoundtrip(t *testing.T, mpdata []byte) {
	p1out, p1in := io.Pipe()
	p2out, p2in := io.Pipe()
	p3out, p3in := io.Pipe()

	go transcodeNoError(t, true, p1out, p2in)
	go transcodeNoError(t, false, p2out, p3in)

	go func() {
		if len(mpdata) > 0 {
			// Bug in some combination of go-codec and io.Pipe:
			// sending an empty write to a pipe causes the pipe
			// reader to return from Read() with a 0 byte count
			// but no EOF error.  This in turn causes go-codec
			// to decode an empty msgpack encoding as integer 0.
			p1in.Write(mpdata)
		}
		p1in.Close()
	}()
	res, err := io.ReadAll(p3out)

	require.NoError(t, err)
	require.Equal(t, mpdata, res,
		"%v != %v", base64.StdEncoding.EncodeToString(mpdata), base64.StdEncoding.EncodeToString(res))
}

type objectType int

const (
	objectUint8 objectType = iota
	objectUint16
	objectUint32
	objectUint64
	objectInt8
	objectInt16
	objectInt32
	objectInt64
	objectBool
	objectBytes
	objectString
	objectArray
	objectSlice
	objectMap
	objectTypeMax
)

func randomObjectOfType(randtype uint64, width int, depth int) interface{} {
	if depth == 0 {
		return 0
	}

	objType := objectType(randtype % uint64(objectTypeMax))

	switch objType {
	case objectUint8:
		return uint8(crypto.RandUint64())
	case objectUint16:
		return uint16(crypto.RandUint64())
	case objectUint32:
		return uint32(crypto.RandUint64())
	case objectUint64:
		return uint64(crypto.RandUint64())
	case objectInt8:
		return int8(crypto.RandUint64())
	case objectInt16:
		return int16(crypto.RandUint64())
	case objectInt32:
		return int32(crypto.RandUint64())
	case objectInt64:
		return int64(crypto.RandUint64())
	case objectBool:
		return crypto.RandUint64()%2 == 0
	case objectBytes:
		var buf [64]byte
		crypto.RandBytes(buf[:])
		return buf[:]
	case objectString:
		var buf [64]byte
		crypto.RandBytes(buf[:])
		return base32.StdEncoding.EncodeToString(buf[:])
	case objectArray:
		var arr [2]interface{}
		if crypto.RandUint64()%2 == 0 { // half the time, make the slice a uniform type
			t := crypto.RandUint64()
			for i := range arr {
				arr[i] = randomObjectOfType(t, width, depth-1)
			}
		} else {
			for i := range arr {
				t := crypto.RandUint64()
				if t%uint64(objectTypeMax) == uint64(objectBytes) {
					// We cannot cleanly handle binary blobs unless the entire array is.
					t++
				}
				arr[i] = randomObjectOfType(t, width, depth-1)
			}
		}
		return arr
	case objectSlice:
		slice := make([]interface{}, 0)
		sz := crypto.RandUint64() % uint64(width)
		if crypto.RandUint64()%2 == 0 { // half the time, make the slice a uniform type
			t := crypto.RandUint64()
			for range sz {
				slice = append(slice, randomObjectOfType(t, width, depth-1))
			}
		} else {
			for range sz {
				t := crypto.RandUint64()
				if t%uint64(objectTypeMax) == uint64(objectBytes) {
					// We cannot cleanly handle binary blobs unless the entire slice is.
					t++
				}
				slice = append(slice, randomObjectOfType(t, width, depth-1))
			}
		}
		return slice
	case objectMap:
		return randomMap(width, depth-1)
	default:
		panic("unreachable")
	}
}

func randomObject(width int, depth int) interface{} {
	return randomObjectOfType(crypto.RandUint64(), width, depth)
}

func randomMap(width int, depth int) interface{} {
	r := make(map[string]interface{})

	for i := 0; i < width; i++ {
		var k [8]byte
		crypto.RandBytes(k[:])
		r[base32.StdEncoding.EncodeToString(k[:])] = randomObject(width, depth)
	}

	return r
}

func TestIdempotence(t *testing.T) {
	partitiontest.PartitionTest(t)

	niter := 10000
	if testing.Short() {
		niter = 1000
	}

	for i := 0; i < niter; i++ {
		o := randomMap(i%7, i%3)
		testIdempotentRoundtrip(t, protocol.EncodeReflect(o))
	}
}

func TestIdempotenceMultiobject(t *testing.T) {
	partitiontest.PartitionTest(t)

	niter := 1000
	if testing.Short() {
		niter = 100
	}

	for i := 0; i < niter; i++ {
		nobj := crypto.RandUint64() % 8
		buf := []byte{}
		for j := 0; j < int(nobj); j++ {
			buf = append(buf, protocol.EncodeReflect(randomMap(i%7, i%3))...)
		}
		testIdempotentRoundtrip(t, buf)
	}
}

type childStruct struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	U uint64 `codec:"u"`
	I int64  `codec:"i"`
}

type parentStruct struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	A  []byte            `codec:"a"`
	M  map[string]string `codec:"m"`
	C  childStruct       `codec:"c"`
	D  []childStruct     `codec:"d"`
	S  string            `codec:"s"`
	B  bool              `codec:"b"`
	U8 uint8             `codec:"u8"`
}

func TestIdempotenceStruct(t *testing.T) {
	partitiontest.PartitionTest(t)

	niter := 10000
	if testing.Short() {
		niter = 1000
	}

	for i := 0; i < niter; i++ {
		var p parentStruct

		p.A = make([]byte, int(crypto.RandUint64()%64))
		crypto.RandBytes(p.A)
		p.B = crypto.RandUint64()%2 == 0
		p.S = fmt.Sprintf("S%dS", crypto.RandUint64())
		p.U8 = uint8(crypto.RandUint64())
		p.C.U = crypto.RandUint64()
		p.C.I = int64(crypto.RandUint64())
		p.D = make([]childStruct, 2)
		for j := 0; j < 2; j++ {
			p.D[j].U = crypto.RandUint64()
			p.D[j].I = int64(crypto.RandUint64())
		}

		mapKeys := crypto.RandUint64() % 4
		for k := 0; k < int(mapKeys); k++ {
			if p.M == nil {
				p.M = make(map[string]string)
			}
			p.M[fmt.Sprintf("K%dK", crypto.RandUint64())] = fmt.Sprintf("V%dV", crypto.RandUint64())
		}

		testIdempotentRoundtrip(t, protocol.EncodeReflect(&p))
	}
}
