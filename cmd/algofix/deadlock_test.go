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

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

const deadlock_simple_src = `package main

import (
	"sync"
)

func main() {
	// lol wut?
	var l sync.Mutex
	var r sync.Mutex
	var x sync.Mutex

	l.Lock()
	defer l.Unlock()
	r.Lock()
	defer r.Unlock()
	x.Lock()
	defer x.Unlock()
}
`
const deadlock_simple_dest = `package main

import (
	"github.com/algorand/go-deadlock"
	"sync"
)

func main() {
	// lol wut?
	var l deadlock.Mutex
	var r deadlock.Mutex
	var x deadlock.Mutex

	l.Lock()
	defer l.Unlock()
	r.Lock()
	defer r.Unlock()
	x.Lock()
	defer x.Unlock()
}
`

const deadlock_test_src = `package main

import (
	"sync"
)

func main() {
	var l sync.Mutex

	// algofix allow sync
	var r sync.Mutex

	// algofix require deadlock
	var x sync.Mutex

	l.Lock()
	defer l.Unlock()
	r.Lock()
	defer r.Unlock()
	x.Lock()
	defer x.Unlock()
}
`

const deadlock_test_fin = `package main

import (
	"github.com/algorand/go-deadlock"
	"sync"
)

func main() {
	var l deadlock.Mutex

	// algofix allow sync
	var r sync.Mutex

	// algofix require deadlock
	var x deadlock.Mutex

	l.Lock()
	defer l.Unlock()
	r.Lock()
	defer r.Unlock()
	x.Lock()
	defer x.Unlock()
}
`

func TestDeadlockRewrite(t *testing.T) {
	t.Run("simple", func(t *testing.T) { testDeadlock(t, deadlock_simple_src, deadlock_simple_dest) })
	t.Run("onoff", func(t *testing.T) { testDeadlock(t, deadlock_test_src, deadlock_test_fin) })
}

func testGoFmt(fset *token.FileSet, node interface{}) (out string, err error) {
	var buf bytes.Buffer
	err = format.Node(&buf, fset, node)
	if err == nil {
		out = string(buf.Bytes())
	}
	return
}

func testDeadlock(t *testing.T, src, dest string) {
	fset := token.NewFileSet()
	filename := "testmain.go"
	file, err := parser.ParseFile(fset, filename, src, parserMode)
	require.NoError(t, err)
	fixed := deadlock(file)
	require.True(t, fixed)
	src2, err := testGoFmt(fset, file)
	require.NoError(t, err)

	// rinse, repeat?
	newFile, err := parser.ParseFile(fset, filename, src2, parserMode)
	require.NoError(t, err)
	src3, err := testGoFmt(fset, newFile)
	require.NoError(t, err)

	if string(src3) != dest {
		fmt.Printf("===== %s orig =====\n", t.Name())
		fmt.Println(string(src))
		fmt.Printf("===== %s orig =====\n", t.Name())
		fmt.Printf("===== %s src2 =====\n", t.Name())
		fmt.Println(string(src2))
		fmt.Printf("===== %s src2 =====\n", t.Name())
		fmt.Printf("===== %s actual =====\n", t.Name())
		fmt.Println(string(src3))
		fmt.Printf("===== %s actual =====\n", t.Name())
	}
	require.Equal(t, dest, string(src3))
}
