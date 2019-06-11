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
	enc := Encode(&x)
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

	require.Equal(t, Encode(&a), Encode(&b))

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

	require.Equal(t, Encode(&c), Encode(&d))
	require.Equal(t, Encode(&c), Encode(&e))
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

	require.Equal(t, Encode(a), Encode(b))
}
