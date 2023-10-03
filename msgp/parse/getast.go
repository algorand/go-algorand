package parse

import (
	"fmt"
	"go/ast"
	"reflect"
	"sort"
	"strings"

	"github.com/algorand/msgp/gen"
	"github.com/ttacon/chalk"
	"golang.org/x/tools/go/packages"
)

// A FileSet is the in-memory representation of a
// parsed file.
type FileSet struct {
	Package    string              // package name
	PkgPath    string              // package path
	Specs      map[string]ast.Expr // type specs in file
	Aliases    map[string]ast.Expr // type aliases in file
	Interfaces map[string]ast.Expr // type interfaces in file
	Consts     map[string]ast.Expr // consts
	Identities map[string]gen.Elem // processed from specs
	Directives []string            // raw preprocessor directives
	Imports    []*ast.ImportSpec   // imports
	ImportSet  ImportSet
	ImportName map[string]string
}

// An ImportSet describes the FileSets for a group of imported packages
type ImportSet map[string]*FileSet

// File parses a file at the relative path
// provided and produces a new *FileSet.
// If you pass in a path to a directory, the entire
// directory will be parsed.
// If unexport is false, only exported identifiers are included in the FileSet.
// If the resulting FileSet would be empty, an error is returned.
func File(name string, unexported bool, warnPkgMask string) (*FileSet, error) {
	pushstate(name)
	defer popstate()

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedImports | packages.NeedDeps | packages.NeedSyntax | packages.NeedFiles | packages.NeedExportsFile | packages.NeedTypesInfo,
	}

	pkgs, err := packages.Load(cfg, name)
	if err != nil {
		return nil, err
	}

	if len(pkgs) != 1 {
		return nil, fmt.Errorf("multiple packages in directory: %s", name)
	}

	var one *packages.Package
	for _, nm := range pkgs {
		one = nm
		break
	}

	imps := make(map[string]*FileSet)

	fs := packageToFileSet(one, imps, unexported)
	for _, ifs := range imps {
		ifs.process(warnPkgMask)
		ifs.applyDirectives()
		ifs.propInline()
	}
	fs.process(warnPkgMask)
	fs.applyDirectives()
	fs.propInline()
	return fs, nil
}

func packageToFileSet(p *packages.Package, imps map[string]*FileSet, unexported bool) *FileSet {
	fs := &FileSet{
		Package:    p.Name,
		PkgPath:    p.PkgPath,
		Specs:      make(map[string]ast.Expr),
		Aliases:    make(map[string]ast.Expr),
		Interfaces: make(map[string]ast.Expr),
		Consts:     make(map[string]ast.Expr),
		Identities: make(map[string]gen.Elem),
		ImportSet:  imps,
		ImportName: make(map[string]string),
	}

	for name, importpkg := range p.Imports {
		_, ok := imps[name]
		if ok {
			continue
		}

		imps[name] = packageToFileSet(importpkg, imps, unexported)
	}

	for _, fl := range p.Syntax {
		pushstate(fl.Name.Name)
		fs.Directives = append(fs.Directives, yieldComments(fl.Comments)...)
		if !unexported {
			ast.FileExports(fl)
		}

		for _, importspec := range fl.Imports {
			pkgpath := importspec.Path.Value[1 : len(importspec.Path.Value)-1]
			if pkgpath == "C" {
				continue
			}

			var importname string
			if importspec.Name != nil {
				importname = importspec.Name.Name
			} else {
				p, ok := imps[pkgpath]
				if !ok {
					fmt.Printf("missing import %s\n", pkgpath)
				} else {
					importname = p.Package
				}
			}
			fs.ImportName[importname] = pkgpath
		}

		fs.getTypeSpecs(fl)
		popstate()
	}

	return fs
}

// applyDirectives applies all of the directives that
// are known to the parser. additional method-specific
// directives remain in f.Directives
func (f *FileSet) applyDirectives() {
	newdirs := make([]string, 0, len(f.Directives))
	for _, d := range f.Directives {
		chunks := strings.Split(d, " ")
		if len(chunks) > 0 {
			if fn, ok := directives[chunks[0]]; ok {
				pushstate(chunks[0])
				err := fn(chunks, f)
				if err != nil {
					warnln(err.Error())
				}
				popstate()
			} else {
				newdirs = append(newdirs, d)
			}
		}
	}
	f.Directives = newdirs
}

// A linkset is a graph of unresolved
// identities.
//
// Since gen.Ident can only represent
// one level of type indirection (e.g. Foo -> uint8),
// type declarations like `type Foo Bar`
// aren't resolve-able until we've processed
// everything else.
//
// The goal of this dependency resolution
// is to distill the type declaration
// into just one level of indirection.
// In other words, if we have:
//
//	type A uint64
//	type B A
//	type C B
//	type D C
//
// ... then we want to end up
// figuring out that D is just a uint64.
type linkset map[string]*gen.BaseElem

func (f *FileSet) resolve(ls linkset) {
	progress := true
	for progress && len(ls) > 0 {
		progress = false
		for name, elem := range ls {
			real, ok := f.Identities[elem.TypeName()]
			if ok {
				// copy the old type descriptor,
				// alias it to the new value,
				// and insert it into the resolved
				// identities list
				progress = true
				nt := real.Copy()
				nt.Alias(name)
				f.Identities[name] = nt
				delete(ls, name)
			}
		}
	}

	// what's left can't be resolved
	for name, elem := range ls {
		// warnf("couldn't resolve type %s (%s)\n", name, elem.TypeName())
		nt := elem.Copy()
		nt.Alias(name)
		f.Identities[name] = nt
	}
}

// process takes the contents of f.Specs and
// uses them to populate f.Identities
func (f *FileSet) process(warnPkgMask string) {
	if warnPkgMask != "" && !strings.HasPrefix(f.PkgPath, warnPkgMask) {
		increasePrintLevel()
		defer decreasePrintLevel()
	}
	deferred := make(linkset)
parse:
	for name, def := range f.Specs {
		pushstate(name)

		el := f.parseExpr("", def)

		if el == nil {
			warnln("failed to parse")
			popstate()
			continue parse
		}
		// push unresolved identities into
		// the graph of links and resolve after
		// we've handled every possible named type.
		if be, ok := el.(*gen.BaseElem); ok && be.Value == gen.IDENT {
			deferred[name] = be
			popstate()
			continue parse
		}
		el.Alias(name)
		f.Identities[name] = el
		popstate()
	}

	if len(deferred) > 0 {
		f.resolve(deferred)
	}
}

func strToMethod(s string) gen.Method {
	switch s {
	case "test":
		return gen.Test
	case "size":
		return gen.Size
	case "marshal":
		return gen.Marshal
	case "unmarshal":
		return gen.Unmarshal
	case "maxsize":
		return gen.MaxSize
	default:
		return 0
	}
}

func (f *FileSet) applyDirs(p *gen.Printer) {
	// apply directives of the form
	//
	// 	//msgp:encode ignore {{TypeName}}
	//
loop:
	for _, d := range f.Directives {
		chunks := strings.Split(d, " ")
		if len(chunks) > 1 {
			for i := range chunks {
				chunks[i] = strings.TrimSpace(chunks[i])
			}
			m := strToMethod(chunks[0])
			if m == 0 {
				warnf("unknown pass name: %q\n", chunks[0])
				continue loop
			}
			if fn, ok := passDirectives[chunks[1]]; ok {
				pushstate(chunks[1])
				err := fn(m, chunks[2:], p)
				if err != nil {
					warnf("error applying directive: %s\n", err)
				}
				popstate()
			} else {
				warnf("unrecognized directive %q\n", chunks[1])
			}
		} else {
			warnf("empty directive: %q\n", d)
		}
	}
}

func (f *FileSet) PrintTo(p *gen.Printer) error {
	var msgs []string

	f.applyDirs(p)
	names := make([]string, 0, len(f.Identities))
	for name := range f.Identities {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		el := f.Identities[name]
		el.SetVarname("z")
		pushstate(el.TypeName())
		m, err := p.Print(el)
		popstate()
		if err != nil {
			return err
		}
		msgs = append(msgs, m...)
	}
	for _, msg := range msgs {
		warnln(msg)
	}
	if len(msgs) > 0 {
		return fmt.Errorf("Errors encountered, exiting")
	}
	return nil
}

// getTypeSpecs extracts all of the *ast.TypeSpecs in the file
// into fs.Identities, but does not set the actual element
func (fs *FileSet) getTypeSpecs(f *ast.File) {

	// collect all imports...
	fs.Imports = append(fs.Imports, f.Imports...)

	// check all declarations...
	for i := range f.Decls {

		// for GenDecls...
		if g, ok := f.Decls[i].(*ast.GenDecl); ok {

			// and check the specs...
			for _, s := range g.Specs {

				// for ast.TypeSpecs....
				switch s := s.(type) {
				case *ast.TypeSpec:
					switch s.Type.(type) {

					// this is the list of parse-able
					// type specs
					case *ast.StructType,
						*ast.ArrayType,
						*ast.StarExpr,
						*ast.SelectorExpr,
						*ast.MapType,
						*ast.Ident:

						if strings.HasPrefix(s.Name.Name, "_Ctype_") || s.Name.Name == "_" {
							continue
						}

						if s.Assign == 0 {
							fs.Specs[s.Name.Name] = s.Type
						} else {
							fs.Aliases[s.Name.Name] = s.Type
						}
					case *ast.InterfaceType:
						fs.Interfaces[s.Name.Name] = s.Type
					}

				case *ast.ValueSpec:
					if len(s.Names) == 1 && len(s.Values) == 1 {
						fs.Consts[s.Names[0].Name] = s.Values[0]
					}
				}
			}
		}
	}
}

func fieldName(f *ast.Field) string {
	switch len(f.Names) {
	case 0:
		return stringify(f.Type)
	case 1:
		return f.Names[0].Name
	default:
		return f.Names[0].Name + " (and others)"
	}
}

func (fs *FileSet) parseFieldList(importPrefix string, fl *ast.FieldList) []gen.StructField {
	if fl == nil || fl.NumFields() == 0 {
		return nil
	}
	out := make([]gen.StructField, 0, fl.NumFields())
	for _, field := range fl.List {
		pushstate(fieldName(field))
		fds := fs.getField(importPrefix, field)
		if len(fds) > 0 {
			out = append(out, fds...)
		} else {
			warnln("ignored.")
		}
		popstate()
	}
	return out
}

// translate *ast.Field into []gen.StructField
func (fs *FileSet) getField(importPrefix string, f *ast.Field) []gen.StructField {
	sf := make([]gen.StructField, 1)
	var extension, flatten bool
	var allocbound string
	var allocbounds []string
	var maxtotalbytes string

	// always flatten embedded structs
	flatten = true

	// parse tag; otherwise field name is field tag
	if f.Tag != nil {
		var body string
		body, sf[0].HasCodecTag = reflect.StructTag(strings.Trim(f.Tag.Value, "`")).Lookup("codec")
		tags := strings.Split(body, ",")
		for _, tag := range tags[1:] {
			if tag == "extension" {
				extension = true
			}
			if strings.HasPrefix(tag, "allocbound=") {
				allocbounds = append(allocbounds, strings.Split(tag, "=")[1])
			}
			if strings.HasPrefix(tag, "maxtotalbytes=") {
				maxtotalbytes = strings.Split(tag, "=")[1]
			}
		}
		// ignore "-" fields
		if tags[0] == "-" {
			return nil
		}
		sf[0].FieldTag = tags[0]
		sf[0].FieldTagParts = tags
		sf[0].RawTag = f.Tag.Value
	}
	allocbound = strings.Join(allocbounds, ",")
	ex := fs.parseExpr(importPrefix, f.Type)
	if ex == nil {
		return nil
	}

	// parse field name
	switch len(f.Names) {
	case 0:
		if flatten {
			maybe := fs.getFieldsFromEmbeddedStruct(importPrefix, f.Type)
			if maybe != nil {
				// Prefix all field names with the explicit
				// embedded struct selector, to avoid ambiguity.
				for i := range maybe {
					maybe[i].FieldPath = append([]string{embedded(f.Type)}, maybe[i].FieldPath...)
				}

				return maybe
			}
		}

		// If not flattening, or the embedded type wasn't a struct,
		// embed it under the type name.
		sf[0].FieldName = embedded(f.Type)
	case 1:
		sf[0].FieldName = f.Names[0].Name
	default:
		// this is for a multiple in-line declaration,
		// e.g. type A struct { One, Two int }
		sf = sf[0:0]
		for _, nm := range f.Names {
			sf = append(sf, gen.StructField{
				FieldTag:  nm.Name,
				FieldName: nm.Name,
				FieldElem: ex.Copy(),
			})
		}
		return sf
	}

	// resolve local package type aliases that referenced in this package structs
	resolveAlias := func(el gen.Elem) {
		if a, ok := fs.Aliases[el.TypeName()]; ok {
			if b, ok := a.(*ast.SelectorExpr); ok {
				if c, ok := b.X.(*ast.Ident); ok {
					el.Alias(c.Name + "." + b.Sel.Name)
				}
			} else if b, ok := a.(*ast.Ident); ok {
				el.Alias(b.Name)
			}
		}
	}
	// resolve field alias type
	resolveAlias(ex)
	// resolve field map type that have alias type key or value
	if m, ok := ex.(*gen.Map); ok {
		resolveAlias(m.Key)
		resolveAlias(m.Value)
	}
	// resolve field slice type that have alias type element
	if m, ok := ex.(*gen.Slice); ok {
		resolveAlias(m.Els)
	}

	sf[0].FieldElem = ex
	if sf[0].FieldTag == "" {
		sf[0].FieldTag = sf[0].FieldName
	}
	if sf[0].FieldTagParts == nil {
		sf[0].FieldTagParts = []string{sf[0].FieldName}
	}
	sf[0].FieldElem.SetAllocBound(allocbound)
	sf[0].FieldElem.SetMaxTotalBytes(maxtotalbytes)

	// validate extension
	if extension {
		switch ex := ex.(type) {
		case *gen.Ptr:
			if b, ok := ex.Value.(*gen.BaseElem); ok {
				b.Value = gen.Ext
			} else {
				warnln("couldn't cast to extension.")
				return nil
			}
		case *gen.BaseElem:
			ex.Value = gen.Ext
		default:
			warnln("couldn't cast to extension.")
			return nil
		}
	}
	return sf
}

func (fs *FileSet) getFieldsFromEmbeddedStruct(importPrefix string, f ast.Expr) []gen.StructField {
	switch f := f.(type) {
	case *ast.Ident:
		s, ok := fs.Specs[f.Name]
		if !ok {
			s = fs.Aliases[f.Name]
		}

		switch s := s.(type) {
		case *ast.StructType:
			return fs.parseFieldList(importPrefix, s.Fields)
		default:
			return nil
		}
	case *ast.SelectorExpr:
		pkg := f.X
		pkgid, ok := pkg.(*ast.Ident)
		if !ok {
			return nil
		}

		pkgname, ok := fs.ImportName[pkgid.Name]
		if !ok {
			return nil
		}

		pkgfs, ok := fs.ImportSet[pkgname]
		if !ok {
			return nil
		}

		return pkgfs.getFieldsFromEmbeddedStruct(pkgid.Name+".", f.Sel)
	default:
		// other possibilities are disallowed
		return nil
	}
}

// extract embedded field name
//
// so, for a struct like
//
//		type A struct {
//			io.Writer
//	 }
//
// we want "Writer"
func embedded(f ast.Expr) string {
	switch f := f.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.StarExpr:
		return embedded(f.X)
	case *ast.SelectorExpr:
		return f.Sel.Name
	default:
		// other possibilities are disallowed
		return ""
	}
}

// stringify a field type name
func stringify(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return "*" + stringify(e.X)
	case *ast.SelectorExpr:
		return stringify(e.X) + "." + e.Sel.Name
	case *ast.ArrayType:
		if e.Len == nil {
			return "[]" + stringify(e.Elt)
		}
		return fmt.Sprintf("[%s]%s", stringify(e.Len), stringify(e.Elt))
	case *ast.InterfaceType:
		if e.Methods == nil || e.Methods.NumFields() == 0 {
			return "interface{}"
		}
	}
	return "<BAD>"
}

// recursively translate ast.Expr to gen.Elem; nil means type not supported
// expected input types:
// - *ast.MapType (map[T]J)
// - *ast.Ident (name)
// - *ast.ArrayType ([(sz)]T)
// - *ast.StarExpr (*T)
// - *ast.StructType (struct {})
// - *ast.SelectorExpr (a.B)
// - *ast.InterfaceType (interface {})
func (fs *FileSet) parseExpr(importPrefix string, e ast.Expr) gen.Elem {
	switch e := e.(type) {

	case *ast.MapType:
		kt := fs.parseExpr(importPrefix, e.Key)
		if kt == nil {
			return nil
		}

		vt := fs.parseExpr(importPrefix, e.Value)
		if vt == nil {
			return nil
		}

		return &gen.Map{Key: kt, Value: vt}

	case *ast.Ident:
		b := gen.Ident(importPrefix, e.Name)

		// work to resove this expression
		// can be done later, once we've resolved
		// everything else.
		if b.Value == gen.IDENT {
			_, specOK := fs.Specs[e.Name]
			_, aliasOK := fs.Aliases[e.Name]
			_, interfaceOK := fs.Interfaces[e.Name]
			if !specOK && !aliasOK && !interfaceOK {
				warnf("non-local identifier: %s\n", e.Name)
			}
		}
		return b

	case *ast.ArrayType:

		// special case for []byte
		if e.Len == nil {
			if i, ok := e.Elt.(*ast.Ident); ok && i.Name == "byte" {
				return &gen.BaseElem{Value: gen.Bytes}
			}
		}

		// return early if we don't know
		// what the slice element type is
		els := fs.parseExpr(importPrefix, e.Elt)
		if els == nil {
			return nil
		}

		// array and not a slice
		if e.Len != nil {
			switch s := e.Len.(type) {
			case *ast.BasicLit:
				return &gen.Array{
					Size: s.Value,
					Els:  els,
				}

			case *ast.Ident:
				sizeHint := ""
				if s.Obj != nil && s.Obj.Kind == ast.Con {
					switch d := s.Obj.Decl.(type) {
					case *ast.ValueSpec:
						if len(d.Names) == 1 && len(d.Values) == 1 {
							v := d.Values[0]
							// Keep trying to resolve this value
							repeat := true
							for repeat {
								switch vv := v.(type) {
								case *ast.BasicLit:
									sizeHint = vv.Value
									repeat = false
								case *ast.SelectorExpr:
									switch xv := vv.X.(type) {
									case *ast.Ident:
										pkgpath := fs.ImportName[xv.Name]
										pkg := fs.ImportSet[pkgpath]
										v = pkg.Consts[vv.Sel.Name]
									}
								default:
									repeat = false
								}
							}
						}
					}
				}
				return &gen.Array{
					Size:     s.String(),
					SizeHint: sizeHint,
					Els:      els,
				}

			case *ast.SelectorExpr:
				return &gen.Array{
					Size: stringify(s),
					Els:  els,
				}

			default:
				return nil
			}
		}
		return &gen.Slice{Els: els}

	case *ast.StarExpr:
		if v := fs.parseExpr(importPrefix, e.X); v != nil {
			return &gen.Ptr{Value: v}
		}
		return nil

	case *ast.StructType:
		return &gen.Struct{Fields: fs.parseFieldList(importPrefix, e.Fields)}

	case *ast.SelectorExpr:
		return gen.Ident("", stringify(e))

	case *ast.InterfaceType:
		// support `interface{}`
		if len(e.Methods.List) == 0 {
			return &gen.BaseElem{Value: gen.Intf}
		}
		return nil

	default: // other types not supported
		return nil
	}
}

func infof(s string, v ...interface{}) {
	pushstate(s)
	if print(0) {
		fmt.Printf(chalk.Green.Color(strings.Join(logctx, ": ")), v...)
	}
	popstate()
}

func infoln(s string) {
	pushstate(s)
	if print(0) {
		fmt.Println(chalk.Green.Color(strings.Join(logctx, ": ")))
	}
	popstate()
}

func warnf(s string, v ...interface{}) {
	pushstate(s)
	if print(1) {
		fmt.Printf(chalk.Yellow.Color(strings.Join(logctx, ": ")), v...)
	}
	popstate()
}

func warnln(s string) {
	pushstate(s)
	if print(1) {
		fmt.Println(chalk.Yellow.Color(strings.Join(logctx, ": ")))
	}
	popstate()
}

func fatalf(s string, v ...interface{}) {
	pushstate(s)
	if print(2) {
		fmt.Printf(chalk.Red.Color(strings.Join(logctx, ": ")), v...)
	}
	popstate()
}

var logctx []string
var printlevel int

func increasePrintLevel() {
	printlevel++
}

func decreasePrintLevel() {
	printlevel--
}

func print(level int) bool {
	return printlevel < level
}

// push logging state
func pushstate(s string) {
	logctx = append(logctx, s)
}

// pop logging state
func popstate() {
	logctx = logctx[:len(logctx)-1]
}
