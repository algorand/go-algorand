package gen

import (
	"fmt"
	"go/ast"
	"strconv"
	"strings"
)

var (
	identNext   = 0
	identPrefix = "za"
)

func resetIdent(prefix string) {
	identPrefix = prefix
	identNext = 0
}

// generate a random identifier name
func randIdent() string {
	identNext++
	return fmt.Sprintf("%s%04d", identPrefix, identNext)
}

// This code defines the type declaration tree.
//
// Consider the following:
//
// type Marshaler struct {
// 	  Thing1 *float64 `msg:"thing1"`
// 	  Body   []byte   `msg:"body"`
// }
//
// A parser using this generator as a backend
// should parse the above into:
//
// var val Elem = &Ptr{
// 	name: "z",
// 	Value: &Struct{
// 		Name: "Marshaler",
// 		Fields: []StructField{
// 			{
// 				FieldTag: "thing1",
// 				FieldElem: &Ptr{
// 					name: "z.Thing1",
// 					Value: &BaseElem{
// 						name:    "*z.Thing1",
// 						Value:   Float64,
//						Convert: false,
// 					},
// 				},
// 			},
// 			{
// 				FieldTag: "body",
// 				FieldElem: &BaseElem{
// 					name:    "z.Body",
// 					Value:   Bytes,
// 					Convert: false,
// 				},
// 			},
// 		},
// 	},
// }

// Base is one of the
// base types
type Primitive uint8

// this is effectively the
// list of currently available
// ReadXxxx / WriteXxxx methods.
const (
	Invalid Primitive = iota
	Bytes
	String
	Float32
	Float64
	Complex64
	Complex128
	Uint
	Uint8
	Uint16
	Uint32
	Uint64
	Uintptr
	Byte
	Int
	Int8
	Int16
	Int32
	Int64
	Bool
	Intf     // interface{}
	Time     // time.Time
	Ext      // extension
	Error    // error
	Duration // time.Duration

	IDENT // IDENT means an unrecognized identifier
)

// all of the recognized identities
// that map to primitive types
var primitives = map[string]Primitive{
	"[]byte":         Bytes,
	"string":         String,
	"float32":        Float32,
	"float64":        Float64,
	"complex64":      Complex64,
	"complex128":     Complex128,
	"uint":           Uint,
	"uint8":          Uint8,
	"uint16":         Uint16,
	"uint32":         Uint32,
	"uint64":         Uint64,
	"uintptr":        Uintptr,
	"byte":           Byte,
	"rune":           Int32,
	"int":            Int,
	"int8":           Int8,
	"int16":          Int16,
	"int32":          Int32,
	"int64":          Int64,
	"bool":           Bool,
	"interface{}":    Intf,
	"time.Time":      Time,
	"msgp.Extension": Ext,
	"error":          Error,
	"time.Duration":  Duration,
}

// types built into the library
// that satisfy all of the
// interfaces.
var builtins = map[string]struct{}{
	"msgp.Raw":    struct{}{},
	"msgp.Number": struct{}{},
}

// Callback represents a function that can is expected to be printed into the generated code.
// for example, at the end of a successful unmarshalling.
type Callback struct {
	Fname        string
	CallbackType CallbackType
}

type CallbackType uint64

// UnmarshalCallBack represents a type callback that should run over the generated code.
const UnmarshalCallBack CallbackType = 1

func (c Callback) IsUnmarshallCallback() bool { return c.CallbackType == UnmarshalCallBack }
func (c Callback) GetName() string            { return c.Fname }

// common data/methods for every Elem
type common struct {
	vname, alias  string
	allocbound    string
	maxtotalbytes string
	callbacks     []Callback
}

func (c *common) SetVarname(s string)       { c.vname = s }
func (c *common) Varname() string           { return c.vname }
func (c *common) Alias(typ string)          { c.alias = typ }
func (c *common) SortInterface() string     { return "" }
func (c *common) SetAllocBound(s string)    { c.allocbound = s }
func (c *common) AllocBound() string        { return c.allocbound }
func (c *common) SetMaxTotalBytes(s string) { c.maxtotalbytes = s }
func (c *common) MaxTotalBytes() string     { return c.maxtotalbytes }
func (c *common) GetCallbacks() []Callback  { return c.callbacks }
func (c *common) AddCallback(cb Callback)   { c.callbacks = append(c.callbacks, cb) }
func (c *common) hidden()                   {}

func IsDangling(e Elem) bool {
	if be, ok := e.(*BaseElem); ok && be.Dangling() {
		return true
	}
	return false
}

// Elem is a go type capable of being
// serialized into MessagePack. It is
// implemented by *Ptr, *Struct, *Array,
// *Slice, *Map, and *BaseElem.
type Elem interface {
	// SetVarname sets this nodes
	// variable name and recursively
	// sets the names of all its children.
	// In general, this should only be
	// called on the parent of the tree.
	SetVarname(s string)

	// Varname returns the variable
	// name of the element.
	Varname() string

	// TypeName is the canonical
	// go type name of the node
	// e.g. "string", "int", "map[string]float64"
	// OR the alias name, if it has been set.
	TypeName() string

	// Alias sets a type (alias) name
	Alias(typ string)

	// Copy should perform a deep copy of the object
	Copy() Elem

	// Complexity returns a measure of the
	// complexity of element (greater than
	// or equal to 1.)
	Complexity() int

	// ZeroExpr returns the expression for the correct zero/empty
	// value.  Can be used for assignment.
	// Returns "" if zero/empty not supported for this Elem.
	ZeroExpr() string

	// IfZeroExpr returns the expression to compare to zero/empty
	// for this type.  It is meant to be used in an if statement
	// and may include the simple statement form followed by
	// semicolon and then the expression.
	// Returns "" if zero/empty not supported for this Elem.
	IfZeroExpr() string

	// SortInterface returns the sort.Interface for sorting a
	// slice of this type.
	SortInterface() string

	// Comparable returns whether the type is comparable, along the lines
	// of the Go spec (https://golang.org/ref/spec#Comparison_operators),
	// used to determine whether we can compare to a zero value to determine
	// zeroness.
	Comparable() bool

	// SetAllocBound specifies the maximum number of elements to allocate
	// when decoding this type.  Meaningful for slices and maps.
	// Blank means unspecified bound.  "-" means no bound.
	SetAllocBound(bound string)

	// AllocBound returns the maximum number of elements to allocate
	// when decoding this type.  Meaningful for slices and maps.
	AllocBound() string

	// SetMaxTotalBytes specifies the maximum number of bytes to allocate when
	// decoding this type.
	// Blank means unspecified bound.  "-" means no bound.
	SetMaxTotalBytes(bound string)

	// MaxTotalBytes specifies the maximum number of bytes to allocate when
	// decoding this type. Meaningful for slices of strings or byteslices.
	MaxTotalBytes() string

	// AddCallback adds to the elem a Callback it should call at the end of marshaling
	AddCallback(Callback)

	// GetCallbacks fetches all callbacks this Elem stored.
	GetCallbacks() []Callback

	hidden()
}

// Ident returns the *BaseElem that corresponds
// to the provided identity.
func Ident(importPrefix string, id string) *BaseElem {
	p, ok := primitives[id]
	if ok {
		return &BaseElem{Value: p}
	}
	id = importPrefix + id
	be := &BaseElem{Value: IDENT, IdentName: id}
	be.Alias(id)
	return be
}

type Array struct {
	common
	Index    string // index variable name
	Size     string // array size
	SizeHint string // const object referred to by Size
	Els      Elem   // child
}

func (a *Array) SetVarname(s string) {
	a.common.SetVarname(s)
ridx:
	a.Index = randIdent()

	// try to avoid using the same
	// index as a parent slice
	if strings.Contains(a.Varname(), a.Index) {
		goto ridx
	}

	a.Els.SetVarname(fmt.Sprintf("%s[%s]", a.Varname(), a.Index))
}

func (a *Array) TypeName() string {
	if a.common.alias != "" {
		return a.common.alias
	}
	a.common.Alias(fmt.Sprintf("[%s]%s", a.Size, a.Els.TypeName()))
	return a.common.alias
}

func (a *Array) Copy() Elem {
	b := *a
	b.Els = a.Els.Copy()
	return &b
}

func (a *Array) Complexity() int { return 1 + a.Els.Complexity() }

func (a *Array) sz() int {
	szString := a.SizeHint
	if szString == "" {
		szString = a.Size
	}

	s, err := strconv.Atoi(szString)
	if err != nil {
		panic(err)
	}

	return s
}

// ZeroExpr returns the zero/empty expression or empty string if not supported.
func (a *Array) ZeroExpr() string {
	zeroElem := a.Els.ZeroExpr()
	if zeroElem == "" {
		return ""
	}

	sz := a.sz()

	res := fmt.Sprintf("%s{", a.TypeName())
	for i := 0; i < sz; i++ {
		res += fmt.Sprintf("%s, ", zeroElem)
	}
	res += "}"
	return res
}

// IfZeroExpr returns the expression to compare to zero/empty.
func (a *Array) IfZeroExpr() string {
	// Special case for arrays of comparable elements: Go generates
	// faster code if we just compare to a zero value.
	if a.Els.Comparable() {
		return fmt.Sprintf("%s == (%s{})", a.Varname(), a.TypeName())
	}

	sz := a.sz()

	var res string
	for i := 0; i < sz; i++ {
		el := a.Els.Copy()
		el.SetVarname(fmt.Sprintf("%s[%d]", a.Varname(), i))
		if res != "" {
			res += " && "
		}
		res += "(" + el.IfZeroExpr() + ")"
	}
	return res
}

// Comparable returns whether this elem's type is comparable.
func (a *Array) Comparable() bool {
	return a.Els.Comparable()
}

// Map is a map[string]Elem
type Map struct {
	common
	Keyidx string // key variable name
	Key    Elem   // type of map key
	Validx string // value variable name
	Value  Elem   // value element
}

func (m *Map) SetVarname(s string) {
	m.common.SetVarname(s)
ridx:
	m.Keyidx = randIdent()
	m.Validx = randIdent()

	// just in case
	if m.Keyidx == m.Validx {
		goto ridx
	}

	m.Key.SetVarname(m.Keyidx)
	m.Value.SetVarname(m.Validx)
}

func (m *Map) TypeName() string {
	if m.common.alias != "" {
		return m.common.alias
	}
	m.common.Alias("map[" + m.Key.TypeName() + "]" + m.Value.TypeName())
	return m.common.alias
}

func (m *Map) Copy() Elem {
	g := *m
	g.Key = m.Key.Copy()
	g.Value = m.Value.Copy()
	return &g
}

func (m *Map) Complexity() int { return 2 + m.Value.Complexity() }

// ZeroExpr returns the zero/empty expression or empty string if not supported.  Always "nil" for this case.
func (m *Map) ZeroExpr() string { return "nil" }

// IfZeroExpr returns the expression to compare to zero/empty.
func (m *Map) IfZeroExpr() string { return "len(" + m.Varname() + ") == 0" }

// Comparable returns whether this elem's type is comparable.
func (m *Map) Comparable() bool {
	return false
}

type Slice struct {
	common
	Index string
	Els   Elem // The type of each element
}

func (s *Slice) SetVarname(a string) {
	s.common.SetVarname(a)
	s.Index = randIdent()
	varName := s.Varname()
	if varName[0] == '*' {
		// Pointer-to-slice requires parenthesis for slicing.
		varName = "(" + varName + ")"
	}
	s.Els.SetVarname(fmt.Sprintf("%s[%s]", varName, s.Index))
}

func (s *Slice) TypeName() string {
	if s.common.alias != "" {
		return s.common.alias
	}
	s.common.Alias("[]" + s.Els.TypeName())
	return s.common.alias
}

func (s *Slice) Copy() Elem {
	z := *s
	z.Els = s.Els.Copy()
	return &z
}

func (s *Slice) Complexity() int {
	return 1 + s.Els.Complexity()
}

// ZeroExpr returns the zero/empty expression or empty string if not supported.  Always "nil" for this case.
func (s *Slice) ZeroExpr() string { return "nil" }

// IfZeroExpr returns the expression to compare to zero/empty.
func (s *Slice) IfZeroExpr() string { return "len(" + s.Varname() + ") == 0" }

// Comparable returns whether this elem's type is comparable.
func (s *Slice) Comparable() bool {
	return false
}

type Ptr struct {
	common
	Value Elem
}

func (s *Ptr) SetVarname(a string) {
	s.common.SetVarname(a)

	// struct fields are dereferenced
	// automatically...
	switch x := s.Value.(type) {
	case *Struct:
		// struct fields are automatically dereferenced
		x.SetVarname(a)
		return

	case *BaseElem:
		// identities have pointer receivers
		if x.Value == IDENT {
			x.SetVarname(a)
		} else {
			x.SetVarname("*" + a)
		}
		return

	default:
		s.Value.SetVarname("*" + a)
		return
	}
}

func (s *Ptr) TypeName() string {
	if s.common.alias != "" {
		return s.common.alias
	}
	s.common.Alias("*" + s.Value.TypeName())
	return s.common.alias
}

func (s *Ptr) Copy() Elem {
	v := *s
	v.Value = s.Value.Copy()
	return &v
}

func (s *Ptr) Complexity() int { return 1 + s.Value.Complexity() }

func (s *Ptr) Needsinit() bool {
	if be, ok := s.Value.(*BaseElem); ok && be.needsref {
		return false
	}
	return true
}

// ZeroExpr returns the zero/empty expression or empty string if not supported.  Always "nil" for this case.
func (s *Ptr) ZeroExpr() string { return "nil" }

// IfZeroExpr returns the expression to compare to zero/empty.
func (s *Ptr) IfZeroExpr() string { return s.Varname() + " == nil" }

// Comparable returns whether this elem's type is comparable.
func (s *Ptr) Comparable() bool {
	return false
}

type Struct struct {
	common
	Fields  []StructField // field list
	AsTuple bool          // write as an array instead of a map
}

func (s *Struct) TypeName() string {
	if s.common.alias != "" {
		return s.common.alias
	}
	str := "struct{\n"
	for i := range s.Fields {
		str += s.Fields[i].FieldName +
			" " + s.Fields[i].FieldElem.TypeName() +
			" " + s.Fields[i].RawTag + ";\n"
	}
	str += "}"
	s.common.Alias(str)
	return s.common.alias
}

func (s *Struct) SetVarname(a string) {
	s.common.SetVarname(a)
	writeStructFields(s.Fields, a)
}

func (s *Struct) Copy() Elem {
	g := *s
	g.Fields = make([]StructField, len(s.Fields))
	copy(g.Fields, s.Fields)
	for i := range s.Fields {
		g.Fields[i].FieldElem = s.Fields[i].FieldElem.Copy()
	}
	return &g
}

func (s *Struct) Complexity() int {
	c := 1
	for i := range s.Fields {
		c += s.Fields[i].FieldElem.Complexity()
	}
	return c
}

// ZeroExpr returns the zero/empty expression or empty string if not supported.
func (s *Struct) ZeroExpr() string {
	if s.alias == "" {
		return "" // structs with no names not supported (for now)
	}
	return "(" + s.TypeName() + "{})"
}

// IfZeroExpr returns the expression to compare to zero/empty.
func (s *Struct) IfZeroExpr() string {
	if s.alias == "" {
		return "" // structs with no names not supported (for now)
	}

	var res string
	for i := range s.Fields {
		if !ast.IsExported(s.Fields[i].FieldName) {
			continue
		}

		fieldZero := s.Fields[i].FieldElem.IfZeroExpr()
		if fieldZero != "" {
			if res != "" {
				res += " && "
			}
			res += "(" + fieldZero + ")"
		}
	}
	return res
}

// Comparable returns whether this elem's type is comparable.
func (s *Struct) Comparable() bool {
	for _, sf := range s.Fields {
		if !sf.FieldElem.Comparable() {
			return false
		}
	}
	return true
}

// AnyHasTagPart returns true if HasTagPart(p) is true for any field.
func (s *Struct) AnyHasTagPart(pname string) bool {
	for _, sf := range s.Fields {
		if sf.HasTagPart(pname) {
			return true
		}
	}
	return false
}

// UnderscoreStructHasTagPart returns true if HasTagPart(p) is true for the _struct field.
func (s *Struct) UnderscoreStructHasTagPart(pname string) bool {
	for _, sf := range s.Fields {
		if sf.FieldName == "_struct" && sf.HasTagPart(pname) {
			return true
		}
	}
	return false
}

// HasAnyStructTag returns true if any of the fields in the struct have
// a codec: tag.  This is used to determine which structs we can skip
// because they are not intended for encoding/decoding.
func (s *Struct) HasAnyStructTag() bool {
	for _, sf := range s.Fields {
		if sf.HasCodecTag {
			return true
		}
	}
	return false
}

// HasUnderscoreStructTag returns true if there is a field named _struct
// with a codec: tag.  This is used to ensure developers don't forget to
// annotate their structs with omitempty (unless explicitly opted out).
func (s *Struct) HasUnderscoreStructTag() bool {
	for _, sf := range s.Fields {
		if sf.FieldName == "_struct" && sf.HasCodecTag {
			return true
		}
	}
	return false
}

type StructField struct {
	FieldTag      string   // the string inside the `codec:""` tag up to the first comma
	FieldTagParts []string // the string inside the `codec:""` tag split by commas
	RawTag        string   // the full struct tag
	HasCodecTag   bool     // has a `codec:` tag
	FieldName     string   // the name of the struct field
	FieldElem     Elem     // the field type
	FieldPath     []string // set of embedded struct names for accessing FieldName
}

type byFieldTag []StructField

func (a byFieldTag) Len() int           { return len(a) }
func (a byFieldTag) Less(i, j int) bool { return a[i].FieldTag < a[j].FieldTag }
func (a byFieldTag) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// HasTagPart returns true if the specified tag part (option) is present.
func (sf *StructField) HasTagPart(pname string) bool {
	if len(sf.FieldTagParts) < 2 {
		return false
	}
	for _, p := range sf.FieldTagParts[1:] {
		if p == pname {
			return true
		}
	}
	return false
}

type ShimMode int

const (
	Cast ShimMode = iota
	Convert
)

// BaseElem is an element that
// can be represented by a primitive
// MessagePack type.
type BaseElem struct {
	common
	ShimMode     ShimMode  // Method used to shim
	ShimToBase   string    // shim to base type, or empty
	ShimFromBase string    // shim from base type, or empty
	Value        Primitive // Type of element
	IdentName    string    // name, for Value == IDENT
	Convert      bool      // should we do an explicit conversion?
	mustinline   bool      // must inline; not printable
	needsref     bool      // needs reference for shim
}

func (s *BaseElem) Dangling() bool { return s.mustinline }

func (s *BaseElem) Alias(typ string) {
	s.common.Alias(typ)
	if s.Value != IDENT {
		s.Convert = true
	}
	if strings.Contains(typ, ".") {
		s.mustinline = true
	}
}

func (s *BaseElem) SetVarname(a string) {
	// extensions whose parents
	// are not pointers need to
	// be explicitly referenced
	if s.Value == Ext || s.needsref {
		if strings.HasPrefix(a, "*") {
			s.common.SetVarname(a[1:])
			return
		}
		s.common.SetVarname("&" + a)
		return
	}

	s.common.SetVarname(a)
}

// TypeName returns the syntactically correct Go
// type name for the base element.
func (s *BaseElem) TypeName() string {
	if s.common.alias != "" {
		return s.common.alias
	}
	s.common.Alias(s.BaseType())
	return s.common.alias
}

// ToBase, used if Convert==true, is used as tmp = {{ToBase}}({{Varname}})
func (s *BaseElem) ToBase() string {
	if s.ShimToBase != "" {
		return s.ShimToBase
	}
	return s.BaseType()
}

// FromBase, used if Convert==true, is used as {{Varname}} = {{FromBase}}(tmp)
func (s *BaseElem) FromBase() string {
	if s.ShimFromBase != "" {
		return s.ShimFromBase
	}
	return s.TypeName()
}

// BaseName returns the string form of the
// base type (e.g. Float64, Ident, etc)
func (s *BaseElem) BaseName() string {
	// time and duration are special cases;
	// we strip the package prefix
	if s.Value == Time {
		return "Time"
	}
	if s.Value == Duration {
		return "Duration"
	}
	return s.Value.String()
}

func (s *BaseElem) BaseType() string {
	switch s.Value {
	case IDENT:
		return s.TypeName()

	// exceptions to the naming/capitalization
	// rule:
	case Intf:
		return "interface{}"
	case Bytes:
		return "[]byte"
	case Time:
		return "time.Time"
	case Ext:
		return "msgp.Extension"

	// everything else is base.String() with
	// the first letter as lowercase
	default:
		return strings.ToLower(s.BaseName())
	}
}

func (s *BaseElem) Needsref(b bool) {
	s.needsref = b
}

func (s *BaseElem) Copy() Elem {
	g := *s
	return &g
}

func (s *BaseElem) Complexity() int {
	if s.Convert && !s.mustinline {
		return 2
	}
	// we need to return 1 if !printable(),
	// in order to make sure that stuff gets
	// inlined appropriately
	return 1
}

// Resolved returns whether or not
// the type of the element is
// a primitive or a builtin provided
// by the package.
func (s *BaseElem) Resolved() bool {
	if s.Value == IDENT {
		_, ok := builtins[s.TypeName()]
		return ok
	}
	return true
}

// ZeroExpr returns the zero/empty expression or empty string if not supported.
func (s *BaseElem) ZeroExpr() string {

	switch s.Value {
	case Bytes:
		return "nil"
	case String:
		return "\"\""
	case Complex64, Complex128:
		return "complex(0,0)"
	case Float32,
		Float64,
		Uint,
		Uint8,
		Uint16,
		Uint32,
		Uint64,
		Byte,
		Int,
		Int8,
		Int16,
		Int32,
		Int64,
		Duration:
		return "0"
	case Bool:
		return "false"

	case Time:
		return "(time.Time{})"
	}

	return ""
}

// IfZeroExpr returns the expression to compare to zero/empty.
func (s *BaseElem) IfZeroExpr() string {
	// Byte slices are special: we treat both nil and empty as
	// zero for encoding purposes.
	if s.Value == Bytes {
		return "len(" + s.Varname() + ") == 0"
	}

	z := s.ZeroExpr()
	if z == "" {
		// Assume this is an identifier from another package,
		// and that it has generated code for MsgIsZero.
		return s.Varname() + ".MsgIsZero()"
	}
	return s.Varname() + " == " + z
}

// Comparable returns whether this elem's type is comparable.
func (s *BaseElem) Comparable() bool {
	switch s.Value {
	case String, Float32, Float64, Complex64, Complex128,
		Uint, Uint8, Uint16, Uint32, Uint64, Byte,
		Int, Int8, Int16, Int32, Int64, Bool, Time:
		return true
	default:
		return false
	}
}

// SortInterface returns a sort.Interface for sorting a slice of this type.
func (s *BaseElem) SortInterface() string {
	sortIntf, ok := sortInterface[s.TypeName()]
	if ok {
		return sortIntf
	}
	return ""
}

func (k Primitive) String() string {
	switch k {
	case String:
		return "String"
	case Bytes:
		return "Bytes"
	case Float32:
		return "Float32"
	case Float64:
		return "Float64"
	case Complex64:
		return "Complex64"
	case Complex128:
		return "Complex128"
	case Uint:
		return "Uint"
	case Uint8:
		return "Uint8"
	case Uint16:
		return "Uint16"
	case Uint32:
		return "Uint32"
	case Uint64:
		return "Uint64"
	case Byte:
		return "Byte"
	case Int:
		return "Int"
	case Int8:
		return "Int8"
	case Int16:
		return "Int16"
	case Int32:
		return "Int32"
	case Int64:
		return "Int64"
	case Bool:
		return "Bool"
	case Intf:
		return "Intf"
	case Time:
		return "time.Time"
	case Duration:
		return "time.Duration"
	case Ext:
		return "Extension"
	case IDENT:
		return "Ident"
	default:
		return "INVALID"
	}
}

// writeStructFields is a trampoline for writeBase for
// all of the fields in a struct
func writeStructFields(s []StructField, name string) {
	for i := range s {
		var path string
		for _, pathelem := range s[i].FieldPath {
			path += "." + pathelem
		}
		s[i].FieldElem.SetVarname(fmt.Sprintf("%s%s.%s", name, path, s[i].FieldName))
	}
}

// SetSortInterface registers sort.Interface types from
// the msgp:sort directive.  It would have been nice to
// register it inside the Elem, but unfortunately that
// only affects the type definition; call sites that
// refer to that type (e.g., map keys) have a different
// Elem that does not inherit (get copied) from the type
// definition in f.Identities.
var sortInterface map[string]string

func SetSortInterface(sorttype string, sortintf string) {
	if sortInterface == nil {
		sortInterface = make(map[string]string)
	}

	sortInterface[sorttype] = sortintf
}
