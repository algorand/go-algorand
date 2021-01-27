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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestArray [4]uint64

type TestStruct struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	A       int      `codec:",omitempty"`
	B       struct {
		B1 bool
		B2 string
	}
	C []byte
	E [8]string `codec:",omitemptyarray"`
	F [2]struct {
		F1 uint64
		F2 struct{}
	}
	G TestArray
	HelperStruct1
	H HelperStruct2
}

type HelperStruct1 struct {
	I map[string]string
}

type HelperStruct2 struct {
	J byte
	K string
}

func TestOmitEmpty(t *testing.T) {
	var x TestStruct
	enc := EncodeReflect(&x)
	require.Equal(t, 1, len(enc))
}

func TestEncodeOrder(t *testing.T) {
	var a struct {
		A int
		B string
	}
	a.A = 1
	a.B = "foo"

	var b struct {
		B string
		A int
	}
	b.A = 1
	b.B = "foo"

	require.Equal(t, EncodeReflect(&a), EncodeReflect(&b))

	var c struct {
		A int    `codec:"x"`
		B string `codec:"y"`
	}
	c.A = 1
	c.B = "foo"

	var d struct {
		A string `codec:"y"`
		B int    `codec:"x"`
	}
	d.B = 1
	d.A = "foo"

	type QQ struct {
		Q string `codec:"y"`
	}
	type RR struct {
		R int `codec:"x"`
	}

	var e struct {
		QQ
		RR
	}
	e.R = 1
	e.Q = "foo"

	require.Equal(t, EncodeReflect(&c), EncodeReflect(&d))
	require.Equal(t, EncodeReflect(&c), EncodeReflect(&e))
}

type InlineChild struct {
	X int `codec:"x"`
}

type InlineParent struct {
	InlineChild
}

func TestEncodeInline(t *testing.T) {
	a := InlineChild{X: 5}
	b := InlineParent{InlineChild: a}

	require.Equal(t, EncodeReflect(a), EncodeReflect(b))
}

type embeddedMsgp struct {
	TxType
	A uint64
}

func TestEncodeEmbedded(t *testing.T) {
	var x embeddedMsgp

	x.TxType = PaymentTx
	x.A = 5

	require.Equal(t, Encode(x), Encode(&x))
	require.Equal(t, Encode(x.TxType), Encode(&x.TxType))
	require.NotEqual(t, Encode(&x), Encode(&x.TxType))

	var y embeddedMsgp

	require.NoError(t, Decode(Encode(&x), &y))
	require.Equal(t, x, y)
}

func TestEncodeJSON(t *testing.T) {
	type ar []string
	type mp struct {
		Map map[int]ar `codec:"ld,allocbound=config.MaxEvalDeltaAccounts"`
	}

	var v mp
	v.Map = make(map[int]ar)
	v.Map[0] = []string{"test0"}
	v.Map[1] = []string{"test1"}

	nonStrict := EncodeJSON(&v)
	strings.Contains(string(nonStrict), `0:`)
	strings.Contains(string(nonStrict), `1:`)

	strict := EncodeJSONStrict(&v)
	strings.Contains(string(strict), `"0":`)
	strings.Contains(string(strict), `"1":`)

	var nsv mp
	err := DecodeJSON(nonStrict, &nsv)
	require.NoError(t, err)

	var sv mp
	err = DecodeJSON(nonStrict, &sv)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(v, nsv))
	require.True(t, reflect.DeepEqual(v, sv))
}
