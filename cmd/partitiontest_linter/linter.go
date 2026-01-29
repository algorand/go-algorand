// Copyright (C) 2019-2026 Algorand, Inc.
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

package linter

import (
	"go/ast"
	"strings"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
)

const packageName string = "partitiontest"
const functionName string = "PartitionTest"
const fileNameSuffix string = "_test.go"
const functionNamePrefix string = "Test"
const parameterType string = "T"
const parameterName string = "t"

// Analyzer initialization
var Analyzer = &analysis.Analyzer{
	Name: "partitiontest",
	Doc:  "This custom linter checks inside files that end in '_test.go', and inside functions that start with 'Test' and have testing argument, for a line 'partitiontest.PartitionTest(<testing arg>)'",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, f := range pass.Files {
		currentFileName := pass.Fset.File(f.Pos()).Name()
		if !strings.HasSuffix(currentFileName, fileNameSuffix) {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				// Ignore non-functions or functions with receivers.
				continue
			}

			// Check that function name starts with "Test"
			if !strings.HasPrefix(fn.Name.Name, functionNamePrefix) {
				continue
			}

			if !isTestParameterInFunction(fn.Type.Params.List[0].Type, parameterType) {
				continue
			}
			if !hasPartitionInvocation(f, fn) {
				pass.Reportf(fn.Pos(), "%s: Add missing partition call to top of test. To disable partitioning, add it as a comment: %s.%s(%s)", fn.Name.Name, packageName, functionName, parameterName)
			}

		}
	}
	return nil, nil
}

func isTestParameterInFunction(typ ast.Expr, wantType string) bool {
	ptr, ok := typ.(*ast.StarExpr)
	if !ok {
		// Not a pointer.
		return false
	}

	if name, ok := ptr.X.(*ast.Ident); ok {
		return name.Name == wantType
	}
	if sel, ok := ptr.X.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == wantType
	}
	return false
}

func hasPartitionInvocation(file *ast.File, fn *ast.FuncDecl) bool {
	if isSearchLineInFunction(fn) {
		return true
	}
	return hasPartitionComment(file, fn)
}

func isSearchLineInFunction(fn *ast.FuncDecl) bool {
	for _, oneline := range fn.Body.List {
		if exprStmt, ok := oneline.(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok {
				fun, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if !doesPackageNameMatch(fun) {
					continue
				}
				if !doesFunctionNameMatch(fun) {
					continue
				}

				if !doesParameterNameMatch(call, fn) {
					continue
				}

				return true
			}
		}
	}
	return false
}

func hasPartitionComment(file *ast.File, fn *ast.FuncDecl) bool {
	for _, commentGroup := range file.Comments {
		if commentGroup.Pos() < fn.Pos() || commentGroup.Pos() > fn.End() {
			continue
		}
		for _, comment := range commentGroup.List {
			if strings.Contains(comment.Text, "partitiontest.PartitionTest(") {
				return true
			}
		}
	}
	return false
}

func doesPackageNameMatch(fun *ast.SelectorExpr) bool {
	if packageobject, ok := fun.X.(*ast.Ident); ok {
		if packageobject.Name == packageName {
			return true
		}
	}
	return false
}

func doesFunctionNameMatch(fun *ast.SelectorExpr) bool {
	return fun.Sel.Name == functionName
}

func doesParameterNameMatch(call *ast.CallExpr, fn *ast.FuncDecl) bool {
	for _, oneArg := range call.Args {

		if realArg, ok := oneArg.(*ast.Ident); ok {
			if realArg != nil && realArg.Obj != nil && realArg.Obj.Name == fn.Type.Params.List[0].Names[0].Obj.Name {
				return true
			}
		}
	}
	return false
}

// V2 module plugin registration

func init() {
	register.Plugin("partitiontest", New)
}

// PartitionTestPlugin implements the golangci-lint v2 module plugin interface
type PartitionTestPlugin struct{}

func New(_ any) (register.LinterPlugin, error) {
	return &PartitionTestPlugin{}, nil
}

func (p *PartitionTestPlugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{Analyzer}, nil
}

func (p *PartitionTestPlugin) GetLoadMode() string {
	return register.LoadModeSyntax
}
