// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

// Package linter implements the retryclosure analyzer, which reports closures that may be run
// more than once by a database retry loop and that write to variables declared outside the
// closure. State written that way survives from one attempt to the next, so a retried attempt
// can see (and, for example, append to) results left behind by a failed one.
package linter

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

const (
	dbPkgPath        = "github.com/algorand/go-algorand/util/db"
	trackerdbPkgPath = "github.com/algorand/go-algorand/ledger/store/trackerdb"
)

// dbRetryFuncs are the functions and methods in util/db whose first function-typed parameter
// is called again when it returns an error that indicates database contention. LoggedRetry and
// atomic hold the retry loops; the rest, and any function that forwards to them, are also
// found as wrappers, but are listed so the analyzer does not depend on how util/db is layered.
var dbRetryFuncs = map[string]bool{
	"Retry":         true,
	"LoggedRetry":   true,
	"Atomic":        true,
	"AtomicContext": true,
	"atomic":        true,
}

// trackerdbRetryMethods are the trackerdb.Store methods (and their implementations in the
// trackerdb driver packages) that run their first function-typed parameter inside a retried
// transaction.
var trackerdbRetryMethods = map[string]bool{
	"Batch":                              true,
	"BatchContext":                       true,
	"Snapshot":                           true,
	"SnapshotContext":                    true,
	"Transaction":                        true,
	"TransactionContext":                 true,
	"TransactionWithRetryClearFn":        true,
	"TransactionContextWithRetryClearFn": true,
}

// Analyzer reports writes to captured variables inside closures that may be retried.
var Analyzer = &analysis.Analyzer{
	Name:      "retryclosure",
	Doc:       "reports closures passed to database retry functions (util/db Retry and Atomic, trackerdb Transaction/Snapshot/Batch, and functions that forward to them) that write to variables declared outside the closure, since those writes persist between retried attempts",
	Run:       run,
	FactTypes: []analysis.Fact{new(retriesParams)},
}

// listChecked makes the analyzer also report every retried function it checks, including
// those with no writes, so its coverage can be compared against a text search of call sites.
var listChecked bool

func init() {
	Analyzer.Flags.BoolVar(&listChecked, "list-checked", false, "also report every retried function that was checked")
}

// retriesParams records which function-typed parameters of a function are passed on to a
// retrying call, so that closures passed to the function may also be run more than once.
type retriesParams struct{ Indexes []int }

func (*retriesParams) AFact() {}

func (f *retriesParams) String() string { return fmt.Sprintf("retriesParams%v", f.Indexes) }

type checker struct {
	pass *analysis.Pass
	// wrappers holds retried parameter indexes for functions declared in this package.
	wrappers map[*types.Func][]int
	// funcLits maps local variables to the function literal they are initialized with, so a
	// closure stored in a variable before being passed to a retrying call is still checked.
	funcLits map[types.Object]*ast.FuncLit
	decls    map[*types.Func]*ast.FuncDecl
}

func run(pass *analysis.Pass) (any, error) {
	c := &checker{
		pass:     pass,
		wrappers: make(map[*types.Func][]int),
		funcLits: make(map[types.Object]*ast.FuncLit),
		decls:    make(map[*types.Func]*ast.FuncDecl),
	}
	c.collectDecls()
	c.findWrappers()
	for fn, idxs := range c.wrappers {
		pass.ExportObjectFact(fn, &retriesParams{Indexes: idxs})
	}

	reported := make(map[token.Pos]bool)
	for _, f := range pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, idxs := c.retriedParams(call)
			for _, i := range idxs {
				if i >= len(call.Args) || reported[call.Args[i].Pos()] {
					continue
				}
				reported[call.Args[i].Pos()] = true
				c.checkArg(call.Args[i], callee)
			}
			return true
		})
	}
	return nil, nil
}

// collectDecls indexes function declarations and closure-valued local variables.
func (c *checker) collectDecls() {
	info := c.pass.TypesInfo
	for _, f := range c.pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if fn, ok := info.Defs[n.Name].(*types.Func); ok && n.Body != nil {
					c.decls[fn] = n
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, rhs := range n.Rhs {
						lit, ok := ast.Unparen(rhs).(*ast.FuncLit)
						id, isIdent := n.Lhs[i].(*ast.Ident)
						if ok && isIdent {
							if obj := objOf(info, id); obj != nil {
								c.funcLits[obj] = lit
							}
						}
					}
				}
			case *ast.ValueSpec:
				if len(n.Names) == len(n.Values) {
					for i, v := range n.Values {
						if lit, ok := ast.Unparen(v).(*ast.FuncLit); ok {
							if obj := info.Defs[n.Names[i]]; obj != nil {
								c.funcLits[obj] = lit
							}
						}
					}
				}
			}
			return true
		})
	}
}

func objOf(info *types.Info, id *ast.Ident) types.Object {
	if obj := info.Defs[id]; obj != nil {
		return obj
	}
	return info.Uses[id]
}

// findWrappers computes, to a fixed point, which function-typed parameters of this package's
// functions are passed into retrying calls, either directly or from inside a closure that is.
func (c *checker) findWrappers() {
	info := c.pass.TypesInfo
	for changed := true; changed; {
		changed = false
		for fn, decl := range c.decls {
			params := funcParams(info, decl)
			if len(params) == 0 {
				continue
			}
			found := slices.Clone(c.wrappers[fn])
			ast.Inspect(decl.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				_, idxs := c.retriedParams(call)
				for _, i := range idxs {
					if i >= len(call.Args) {
						continue
					}
					for obj, pi := range params {
						if c.refersTo(call.Args[i], obj) && !slices.Contains(found, pi) {
							found = append(found, pi)
						}
					}
				}
				return true
			})
			if len(found) > len(c.wrappers[fn]) {
				sort.Ints(found)
				c.wrappers[fn] = found
				changed = true
			}
		}
	}
}

// funcParams returns the function-typed parameters of decl, keyed by object, with their index.
func funcParams(info *types.Info, decl *ast.FuncDecl) map[types.Object]int {
	params := make(map[types.Object]int)
	i := 0
	for _, field := range decl.Type.Params.List {
		names := field.Names
		if len(names) == 0 {
			i++
			continue
		}
		for _, name := range names {
			if obj := info.Defs[name]; obj != nil {
				if _, ok := obj.Type().Underlying().(*types.Signature); ok {
					params[obj] = i
				}
			}
			i++
		}
	}
	return params
}

// refersTo reports whether arg is obj, or is a closure (directly or via a local variable)
// whose body refers to obj.
func (c *checker) refersTo(arg ast.Expr, obj types.Object) bool {
	info := c.pass.TypesInfo
	arg = ast.Unparen(arg)
	if id, ok := arg.(*ast.Ident); ok {
		o := info.Uses[id]
		if o == obj {
			return true
		}
		if lit, ok := c.funcLits[o]; ok {
			arg = lit
		}
	}
	lit, ok := arg.(*ast.FuncLit)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == obj {
			found = true
		}
		return !found
	})
	return found
}

// retriedParams returns the callee of call and the indexes of its arguments that may be run
// more than once.
func (c *checker) retriedParams(call *ast.CallExpr) (*types.Func, []int) {
	fn, ok := typeutil.Callee(c.pass.TypesInfo, call).(*types.Func)
	if !ok {
		return nil, nil
	}
	fn = fn.Origin()
	if idxs, ok := c.wrappers[fn]; ok {
		return fn, idxs
	}
	var fact retriesParams
	if fn.Pkg() != c.pass.Pkg && c.pass.ImportObjectFact(fn, &fact) {
		return fn, fact.Indexes
	}
	if fn.Pkg() == nil {
		return nil, nil
	}
	sig := fn.Type().(*types.Signature)
	path := fn.Pkg().Path()
	isSeed := (path == dbPkgPath && dbRetryFuncs[fn.Name()]) ||
		((path == trackerdbPkgPath || strings.HasPrefix(path, trackerdbPkgPath+"/")) && sig.Recv() != nil && trackerdbRetryMethods[fn.Name()])
	if !isSeed {
		return nil, nil
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if _, ok := sig.Params().At(i).Type().Underlying().(*types.Signature); ok {
			return fn, []int{i}
		}
	}
	return nil, nil
}

// checkArg reports writes to captured state in the function passed as a retried argument.
func (c *checker) checkArg(arg ast.Expr, callee *types.Func) {
	info := c.pass.TypesInfo
	e := ast.Unparen(arg)
	if id, ok := e.(*ast.Ident); ok {
		obj := info.Uses[id]
		if lit, ok := c.funcLits[obj]; ok {
			c.checkBody(arg.Pos(), callee, lit.Body, lit.Pos(), lit.End(), nil)
			return
		}
		if _, isNil := obj.(*types.Nil); isNil {
			return
		}
		if v, ok := obj.(*types.Var); ok && v.Kind() == types.ParamVar {
			// A wrapper forwarding its caller's closure; that closure is checked at the call to the wrapper.
			return
		}
	}
	switch e := e.(type) {
	case *ast.FuncLit:
		c.checkBody(arg.Pos(), callee, e.Body, e.Pos(), e.End(), nil)
		return
	case *ast.Ident, *ast.SelectorExpr:
		if fn, ok := typeutil.Callee(info, &ast.CallExpr{Fun: e}).(*types.Func); ok {
			if decl, ok := c.decls[fn]; ok {
				var recv types.Object
				if decl.Recv != nil && len(decl.Recv.List) > 0 && len(decl.Recv.List[0].Names) > 0 {
					recv = info.Defs[decl.Recv.List[0].Names[0]]
				}
				// For a named function, everything declared in its own body and parameters is
				// fresh per call; its receiver and package-level variables are not.
				c.checkBody(arg.Pos(), callee, decl.Body, decl.Type.Params.Pos(), decl.End(), recv)
				return
			}
		}
	}
	c.pass.Reportf(arg.Pos(), "retryclosure: cannot check the function passed to %s, which may run more than once; pass a function literal or a function declared in this package", calleeName(callee))
}

func calleeName(fn *types.Func) string {
	if fn == nil {
		return "a retrying function"
	}
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		return fn.Name()
	}
	return fn.Pkg().Name() + "." + fn.Name()
}

// checkBody reports variables written in body that are declared outside [start, end), or
// that are extraCaptured.
func (c *checker) checkBody(reportPos token.Pos, callee *types.Func, body ast.Node, start, end token.Pos, extraCaptured types.Object) {
	info := c.pass.TypesInfo
	// aliases are variables declared inside the body that reference captured state, such as
	// a pointer or map taken from a captured variable.
	aliases := make(map[types.Object]bool)
	captured := func(obj types.Object) bool {
		v, ok := obj.(*types.Var)
		if !ok || v.IsField() || v.Name() == "_" {
			return false
		}
		if obj == extraCaptured || aliases[obj] {
			return true
		}
		return obj.Pos() < start || obj.Pos() >= end
	}

	written := make(map[string]token.Pos)
	how := make(map[string]string)
	var order []string
	record := func(e ast.Expr, kind string) {
		id := c.rootIdent(e)
		if id == nil {
			return
		}
		obj := objOf(info, id)
		if obj == nil || !captured(obj) {
			return
		}
		name := id.Name
		if _, ok := written[name]; !ok {
			written[name] = e.Pos()
			how[name] = kind
			order = append(order, name)
		}
	}
	noteAlias := func(lhs ast.Expr, rhs ast.Expr) {
		id, ok := lhs.(*ast.Ident)
		if !ok {
			return
		}
		obj := info.Defs[id]
		if obj == nil || !isReference(obj.Type()) {
			return
		}
		if r := c.rootIdent(rhs); r != nil {
			if robj := objOf(info, r); robj != nil && captured(robj) {
				aliases[obj] = true
			}
		}
	}

	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				if len(n.Lhs) == len(n.Rhs) {
					for i := range n.Lhs {
						noteAlias(n.Lhs[i], n.Rhs[i])
					}
				}
				return true
			}
			for _, lhs := range n.Lhs {
				record(lhs, "assign")
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i := range n.Names {
					noteAlias(n.Names[i], n.Values[i])
				}
			}
		case *ast.IncDecStmt:
			record(n.X, "incdec")
		case *ast.RangeStmt:
			if n.Tok == token.ASSIGN {
				if n.Key != nil {
					record(n.Key, "range")
				}
				if n.Value != nil {
					record(n.Value, "range")
				}
			} else if n.Tok == token.DEFINE && n.Value != nil {
				noteAlias(n.Value, n.X)
			}
		case *ast.SendStmt:
			record(n.Chan, "send")
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				record(n.X, "addr")
			}
		case *ast.CallExpr:
			if id, ok := ast.Unparen(n.Fun).(*ast.Ident); ok && len(n.Args) > 0 {
				if b, ok := info.Uses[id].(*types.Builtin); ok {
					switch b.Name() {
					case "delete", "clear", "copy":
						record(n.Args[0], "builtin")
					}
				}
			}
		case *ast.SelectorExpr:
			// Calling a pointer method on an addressable value implicitly takes its address.
			if sel, ok := info.Selections[n]; ok && sel.Kind() == types.MethodVal {
				if fn, ok := sel.Obj().(*types.Func); ok {
					recv := fn.Type().(*types.Signature).Recv()
					if recv != nil {
						_, ptrRecv := recv.Type().(*types.Pointer)
						_, ptrVal := sel.Recv().Underlying().(*types.Pointer)
						_, isIface := sel.Recv().Underlying().(*types.Interface)
						if ptrRecv && !ptrVal && !isIface {
							record(n.X, "ptrmethod")
						}
					}
				}
			}
		}
		return true
	})

	if len(order) == 0 {
		if listChecked {
			c.pass.Reportf(reportPos, "retryclosure-checked: %s", calleeName(callee))
		}
		return
	}
	parts := make([]string, len(order))
	for i, name := range order {
		parts[i] = fmt.Sprintf("%s (line %d, %s)", name, c.pass.Fset.Position(written[name]).Line, how[name])
	}
	c.pass.Reportf(reportPos, "retryclosure: function passed to %s may run more than once, but writes to %s, declared outside it; that state persists between attempts. Return results from the function instead, or reset the state at the start of each attempt and explain with //nolint:retryclosure",
		calleeName(callee), strings.Join(parts, ", "))
}

// rootIdent returns the variable whose storage an assignment to e writes, following field
// selections, indexing, slicing, and dereferences, or nil if e does not name a variable.
func (c *checker) rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				if _, isPkg := c.pass.TypesInfo.Uses[id].(*types.PkgName); isPkg {
					return x.Sel
				}
			}
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return nil
		}
	}
}

// isReference reports whether values of type t share underlying storage when copied.
func isReference(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Map, *types.Slice, *types.Chan:
		return true
	}
	return false
}

// V2 module plugin registration

func init() {
	register.Plugin("retryclosure", New)
}

// RetryClosurePlugin implements the golangci-lint v2 module plugin interface.
type RetryClosurePlugin struct{}

// New returns the retryclosure plugin.
func New(_ any) (register.LinterPlugin, error) {
	return &RetryClosurePlugin{}, nil
}

// BuildAnalyzers returns the retryclosure analyzer.
func (p *RetryClosurePlugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{Analyzer}, nil
}

// GetLoadMode returns the load mode the analyzer needs, which includes type information.
func (p *RetryClosurePlugin) GetLoadMode() string {
	return register.LoadModeTypesInfo
}
