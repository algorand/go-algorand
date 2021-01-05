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
	"go/ast"
)

func init() {
	register(deadlockFix)
}

var deadlockFix = fix{
	name: "deadlock",
	date: "2018-11-18",
	f:    deadlock,
	desc: `Switch from sync.Mutex and sync.RWMutex to deadlock-checked variants`,
}

func deadlock(f *ast.File) bool {
	if !imports(f, "sync") {
		return false
	}

	fixed := false
	walk(f, func(n interface{}) {
		e, ok := n.(*ast.SelectorExpr)
		if !ok {
			return
		}

		pkg, ok := e.X.(*ast.Ident)
		if !ok {
			return
		}

		estr := pkg.Name + "." + e.Sel.Name
		if estr == "sync.Mutex" || estr == "sync.RWMutex" {
			e.X = &ast.Ident{Name: "deadlock"}
			fixed = true
		}
	})

	if fixed {
		addImport(f, "github.com/algorand/go-deadlock")
	}

	return fixed
}
