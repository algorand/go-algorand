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

// Command replace rewrites require.Error/assert.Error/a.Error calls to use
// errorcontains.CaptureError for error capture during migration.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: replace <file.go> [file2.go ...]")
		os.Exit(1)
	}

	for _, filename := range os.Args[1:] {
		if err := processFile(filename); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", filename, err)
		}
	}
}

func processFile(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Set global for exprToString
	sourceContent = content

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, content, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	var replacements []replacement

	// Find all function declarations and their testing parameter name
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Find the testing.T or testing.TB parameter name
			tVar := findTestingParam(node)
			if tVar == "" {
				return true
			}

			// Find assertions object variable (a := require.New(t))
			assertVar, assertStyle := findAssertionsVar(node)

			// Walk the function body for Error calls
			ast.Inspect(node.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}

				r := analyzeErrorCall(call, tVar, assertVar, assertStyle, fset)
				if r != nil {
					replacements = append(replacements, *r)
				}
				return true
			})
		}
		return true
	})

	if len(replacements) == 0 {
		return nil
	}

	// Apply replacements from end to start to preserve positions
	result := string(content)
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		result = result[:r.start] + r.newText + result[r.end:]
	}

	// Write the result
	if err := os.WriteFile(filename, []byte(result), 0644); err != nil {
		return err
	}

	// Run goimports to fix imports and format
	cmd := exec.Command("goimports", "-w", filename)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("goimports failed: %v\n%s", err, output)
	}

	fmt.Printf("Processed %s (%d replacements)\n", filename, len(replacements))
	return nil
}

type replacement struct {
	start   int
	end     int
	newText string
}

func findTestingParam(fn *ast.FuncDecl) string {
	if fn.Type.Params == nil {
		return ""
	}
	for _, param := range fn.Type.Params.List {
		if isTestingType(param.Type) {
			if len(param.Names) > 0 {
				return param.Names[0].Name
			}
		}
	}
	return ""
}

func isTestingType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.StarExpr:
		sel, ok := t.X.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return false
		}
		return ident.Name == "testing" && (sel.Sel.Name == "T" || sel.Sel.Name == "B" || sel.Sel.Name == "F")
	case *ast.SelectorExpr:
		ident, ok := t.X.(*ast.Ident)
		if !ok {
			return false
		}
		return ident.Name == "testing" && t.Sel.Name == "TB"
	}
	return false
}

func findAssertionsVar(fn *ast.FuncDecl) (varName string, isRequire bool) {
	if fn.Body == nil {
		return "", false
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}

		// Check for require.New(t) or assert.New(t)
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if sel.Sel.Name != "New" {
			return true
		}

		if ident.Name == "require" {
			if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
				varName = lhs.Name
				isRequire = true
			}
		} else if ident.Name == "assert" {
			if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
				varName = lhs.Name
				isRequire = false
			}
		}
		return true
	})
	return
}

func analyzeErrorCall(call *ast.CallExpr, tVar, assertVar string, assertIsRequire bool, fset *token.FileSet) *replacement {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	if sel.Sel.Name != "Error" {
		return nil
	}

	// Check what kind of call this is
	switch x := sel.X.(type) {
	case *ast.Ident:
		// Could be: require.Error, assert.Error, or a.Error
		switch x.Name {
		case "require":
			// require.Error(t, err, ...) -> errorcontains.CaptureError(t, err, ...)
			return makeReplacement(call, fset, "errorcontains.CaptureError", nil)

		case "assert":
			// assert.Error(t, err, ...) -> errorcontains.CaptureErrorAssert(t, err, ...)
			return makeReplacement(call, fset, "errorcontains.CaptureErrorAssert", nil)

		default:
			// Check if this is the assertions variable (a.Error)
			if x.Name == assertVar {
				// a.Error(err, ...) -> errorcontains.CaptureError(t, err, ...)
				funcName := "errorcontains.CaptureError"
				if !assertIsRequire {
					funcName = "errorcontains.CaptureErrorAssert"
				}
				return makeReplacementWithT(call, fset, funcName, tVar)
			}
		}
	}

	return nil
}

func makeReplacement(call *ast.CallExpr, fset *token.FileSet, newFunc string, extraArgs []string) *replacement {
	start := fset.Position(call.Pos()).Offset
	end := fset.Position(call.End()).Offset

	// Build new call: newFunc(args...)
	var args []string
	for _, arg := range call.Args {
		args = append(args, exprToString(arg, fset))
	}

	newText := fmt.Sprintf("%s(%s)", newFunc, strings.Join(args, ", "))
	return &replacement{start: start, end: end, newText: newText}
}

func makeReplacementWithT(call *ast.CallExpr, fset *token.FileSet, newFunc, tVar string) *replacement {
	start := fset.Position(call.Pos()).Offset
	end := fset.Position(call.End()).Offset

	// Build new call: newFunc(t, args...)
	args := []string{tVar}
	for _, arg := range call.Args {
		args = append(args, exprToString(arg, fset))
	}

	newText := fmt.Sprintf("%s(%s)", newFunc, strings.Join(args, ", "))
	return &replacement{start: start, end: end, newText: newText}
}

// sourceContent holds the original file content for extracting expressions
var sourceContent []byte

func exprToString(expr ast.Expr, fset *token.FileSet) string {
	start := fset.Position(expr.Pos()).Offset
	end := fset.Position(expr.End()).Offset
	if start >= 0 && end <= len(sourceContent) && start < end {
		return string(sourceContent[start:end])
	}
	return ""
}
