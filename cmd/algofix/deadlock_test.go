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

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

const deadlockSimpleSrc = `package main

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
const deadlockSimpleDest = `package main

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

func tripleTickToBacktick(x string) string {
	return strings.ReplaceAll(x, "'''", "`")
}

const deadlockTestSrc = `package main

import (
	"sync"
)

type thing struct {
	l sync.Mutex
	r sync.Mutex '''algofix:"allow sync.Mutex"'''
	x sync.Mutex
}

func (t *thing) foo() {
	t.l.Lock()
	defer t.l.Unlock()
	t.r.Lock()
	defer t.r.Unlock()
	t.x.Lock()
	defer t.x.Unlock()
}

func main() {
	var t thing
	t.foo()
}
`

const deadlockTestFin = `package main

import (
	"github.com/algorand/go-deadlock"
	"sync"
)

type thing struct {
	l deadlock.Mutex
	r sync.Mutex '''algofix:"allow sync.Mutex"'''
	x deadlock.Mutex
}

func (t *thing) foo() {
	t.l.Lock()
	defer t.l.Unlock()
	t.r.Lock()
	defer t.r.Unlock()
	t.x.Lock()
	defer t.x.Unlock()
}

func main() {
	var t thing
	t.foo()
}
`

func TestDeadlockRewrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// nolint:paralleltest // Subtests modify shared resources.
	t.Run("simple", func(t *testing.T) { testDeadlock(t, deadlockSimpleSrc, deadlockSimpleDest) })
	// nolint:paralleltest // Subtests modify shared resources.
	t.Run("onoff", func(t *testing.T) { testDeadlock(t, deadlockTestSrc, deadlockTestFin) })
}

func testGoFmt(fset *token.FileSet, node interface{}) (out string, err error) {
	var buf bytes.Buffer
	err = format.Node(&buf, fset, node)
	if err == nil {
		out = buf.String()
	}
	return
}

func testDeadlock(t *testing.T, src, dest string) {
	src = tripleTickToBacktick(src)
	dest = tripleTickToBacktick(dest)
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
