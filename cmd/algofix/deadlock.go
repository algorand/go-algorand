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
	"strings"
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

	var provisionalRewrites []*ast.SelectorExpr

	walk(f, func(n interface{}) {
		if f, ok := n.(*ast.Field); ok {
			if f.Tag != nil {
				if strings.Contains(f.Tag.Value, `algofix:"allow sync.Mutex"`) {
					exceptPos := f.Pos()
					exceptEnd := f.End()
					// cancel a provisional rewrite if it winds up being contained in a struct field decl with a tag to allow sync.Mutex
					for i, e := range provisionalRewrites {
						if e == nil {
							continue
						}
						if exceptPos <= e.Pos() && e.End() <= exceptEnd {
							provisionalRewrites[i] = nil
						}
					}
				}
			}
			return
		}

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
			provisionalRewrites = append(provisionalRewrites, e)
		}
	})

	// actually apply any provisional rewrites that weren't cancelled
	for _, e := range provisionalRewrites {
		if e == nil {
			continue
		}
		e.X = &ast.Ident{Name: "deadlock"}
		fixed = true
	}

	if fixed {
		addImport(f, "github.com/algorand/go-deadlock")
	}

	return fixed
}
