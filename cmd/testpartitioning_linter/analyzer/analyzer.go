package analyzer

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const packageName string = "partitiontest"
const functionName string = "PartitionTest"
const fileNameSuffix string = "_test.go"
const functionNamePrefix string = "Test"
const parameterType string = "T"

var Analyzer = &analysis.Analyzer{
	Name: "lint",
	Doc:  "This custom linter checks inside files that end in '_test.go', and inside functions that start with 'Test' and have testing argument, for a line 'testpatitioning.ParitionTest(<testing arg>)'",
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
			if !isSearchLineInFunction(fn) {
				pass.Reportf(fn.Pos(), "%s function is missing %s.%s(<%s type parameter>)", fn.Name.Name, packageName, functionName, parameterType)
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

func isSearchLineInFunction(fn *ast.FuncDecl) bool {
	for _, oneline := range fn.Body.List {
		if exprStmt, ok := oneline.(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok {
				if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
					if !doesPackageNameMatch(fun) {
						continue
					}
					if !doesFunctionNameMatch(fun) {
						continue
					}
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
			if realArg.Obj.Name == fn.Type.Params.List[0].Names[0].Obj.Name {
				return true
			}
		}
	}
	return false
}
