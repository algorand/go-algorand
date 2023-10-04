package gen

import (
	"fmt"
	"go/ast"
	"io"
	"sort"
	"strings"

	"github.com/algorand/msgp/msgp"
)

func marshal(w io.Writer, topics *Topics) *marshalGen {
	return &marshalGen{
		p:      printer{w: w},
		topics: topics,
	}
}

type marshalGen struct {
	passes
	p      printer
	fuse   []byte
	ctx    *Context
	msgs   []string
	topics *Topics
}

func (m *marshalGen) Method() Method { return Marshal }

func (m *marshalGen) Apply(dirs []string) error {
	return nil
}

func (m *marshalGen) Execute(p Elem) ([]string, error) {
	m.msgs = nil
	if !m.p.ok() {
		return m.msgs, m.p.err
	}
	p = m.applyall(p)
	if p == nil {
		return m.msgs, nil
	}

	// We might change p.Varname in methodReceiver(); make a copy
	// to not affect other code that will use p.
	p = p.Copy()

	m.ctx = &Context{}

	m.p.comment("MarshalMsg implements msgp.Marshaler")

	if IsDangling(p) {
		baseType := p.(*BaseElem).IdentName
		c := p.Varname()
		methodRecv := methodReceiver(p)
		m.p.printf("\nfunc (%s %s) MarshalMsg(b []byte) []byte {", c, methodRecv)
		m.p.printf("\n  return ((*(%s))(%s)).MarshalMsg(b)", baseType, c)
		m.p.printf("\n}")

		m.p.printf("\nfunc (_ %[2]s) CanMarshalMsg(%[1]s interface{}) bool {", c, methodRecv)
		m.p.printf("\n  _, ok := (%s).(%s)", c, methodRecv)
		m.p.printf("\n  return ok")
		m.p.printf("\n}")

		m.topics.Add(methodRecv, "MarshalMsg")
		m.topics.Add(methodRecv, "CanMarshalMsg")

		return m.msgs, m.p.err
	}

	// save the vname before
	// calling methodReceiver so
	// that z.Msgsize() is printed correctly
	c := p.Varname()
	methodRecv := imutMethodReceiver(p)

	m.p.printf("\nfunc (%s %s) MarshalMsg(b []byte) (o []byte) {", c, methodRecv)
	m.p.printf("\no = msgp.Require(b, %s.Msgsize())", c)
	next(m, p)
	m.p.nakedReturn()

	m.p.printf("\nfunc (_ %[2]s) CanMarshalMsg(%[1]s interface{}) bool {", c, methodRecv)
	m.p.printf("\n  _, ok := (%s).(%s)", c, methodRecv)

	// If this is a value receiver, check for a pointer type too
	if methodRecv == p.TypeName() {
		m.p.printf("\n  if !ok {")
		m.p.printf("\n    _, ok = (%s).(*%s)", c, methodRecv)
		m.p.printf("\n  }")
	}

	m.p.printf("\n  return ok")
	m.p.printf("\n}")

	m.topics.Add(methodRecv, "MarshalMsg")
	m.topics.Add(methodRecv, "CanMarshalMsg")

	return m.msgs, m.p.err
}

func (m *marshalGen) rawAppend(typ string, argfmt string, arg interface{}) {
	m.p.printf("\no = msgp.Append%s(o, %s)", typ, fmt.Sprintf(argfmt, arg))
}

func (m *marshalGen) fuseHook() {
	if len(m.fuse) > 0 {
		m.rawbytes(m.fuse)
		m.fuse = m.fuse[:0]
	}
}

func (m *marshalGen) Fuse(b []byte) {
	if len(m.fuse) == 0 {
		m.fuse = b
	} else {
		m.fuse = append(m.fuse, b...)
	}
}

func (m *marshalGen) gStruct(s *Struct) {
	if !m.p.ok() {
		return
	}

	if s.AsTuple {
		m.tuple(s)
	} else {
		m.mapstruct(s)
	}
	return
}

func (m *marshalGen) tuple(s *Struct) {
	data := make([]byte, 0, 5)
	data = msgp.AppendArrayHeader(data, uint32(len(s.Fields)))
	m.p.printf("\n// array header, size %d", len(s.Fields))
	m.Fuse(data)
	if len(s.Fields) == 0 {
		m.fuseHook()
	}
	for i := range s.Fields {
		if !m.p.ok() {
			return
		}
		m.ctx.PushString(s.Fields[i].FieldName)
		next(m, s.Fields[i].FieldElem)
		m.ctx.Pop()
	}
}

func isFieldOmitEmpty(sf StructField, s *Struct) bool {
	tagName := "omitempty"

	// go-codec distinguished between omitempty and omitemptyarray
	e := sf.FieldElem
	_, isArray := e.(*Array)
	if isArray {
		tagName = "omitemptyarray"
	}

	return sf.HasTagPart(tagName) || s.UnderscoreStructHasTagPart(tagName)
}

func (m *marshalGen) mapstruct(s *Struct) {

	// Every struct must have a _struct annotation with a codec: tag.
	// In the common case, the tag would contain omitempty, but it could
	// also be blank, if for some reason omitempty is not desired.  This
	// check guards against developers forgetting to specify omitempty.
	if !s.HasUnderscoreStructTag() {
		m.msgs = append(m.msgs, fmt.Sprintf("Missing _struct annotation on struct %v", s))
		return
	}

	sortedFields := append([]StructField(nil), s.Fields...)
	sort.Sort(byFieldTag(sortedFields))

	oeIdentPrefix := randIdent()

	var data []byte
	nfields := len(sortedFields)
	bm := bmask{
		bitlen:  nfields,
		varname: oeIdentPrefix + "Mask",
	}

	exportedFields := 0
	for _, sf := range sortedFields {
		if !ast.IsExported(sf.FieldName) {
			continue
		}
		exportedFields++
	}

	omitempty := s.AnyHasTagPart("omitempty")
	var fieldNVar string
	needCloseBrace := false
	needBmDecl := true
	if omitempty {

		fieldNVar = oeIdentPrefix + "Len"

		m.p.printf("\n// omitempty: check for empty values")
		m.p.printf("\n%s := uint32(%d)", fieldNVar, exportedFields)
		for i, sf := range sortedFields {
			if !m.p.ok() {
				return
			}

			if !ast.IsExported(sf.FieldName) {
				continue
			}

			fieldOmitEmpty := isFieldOmitEmpty(sf, s)
			if ize := sf.FieldElem.IfZeroExpr(); ize != "" && fieldOmitEmpty {
				if needBmDecl {
					m.p.printf("\n%s", bm.typeDecl())
					needBmDecl = false
				}

				m.p.printf("\nif %s {", ize)
				m.p.printf("\n%s--", fieldNVar)
				m.p.printf("\n%s", bm.setStmt(i))
				m.p.printf("\n}")
			}
		}

		m.p.printf("\n// variable map header, size %s", fieldNVar)
		m.p.varAppendMapHeader("o", fieldNVar, exportedFields)
		if !m.p.ok() {
			return
		}

		// quick check for the case where the entire thing is empty, but only at the top level
		if !strings.Contains(s.Varname(), ".") {
			m.p.printf("\nif %s != 0 {", fieldNVar)
			needCloseBrace = true
		}

	} else {

		// non-omitempty version
		data = make([]byte, 0, 64)
		data = msgp.AppendMapHeader(data, uint32(exportedFields))
		m.p.printf("\n// map header, size %d", exportedFields)
		m.Fuse(data)
		if exportedFields == 0 {
			m.fuseHook()
		}

	}

	for i, sf := range sortedFields {
		if !ast.IsExported(sf.FieldName) {
			continue
		}

		if !m.p.ok() {
			return
		}

		fieldOmitEmpty := isFieldOmitEmpty(sf, s)

		// if field is omitempty, wrap with if statement based on the emptymask
		oeField := fieldOmitEmpty && sf.FieldElem.IfZeroExpr() != ""
		if oeField {
			m.p.printf("\nif %s == 0 { // if not empty", bm.readExpr(i))
		}

		data = msgp.AppendString(nil, sf.FieldTag)

		m.p.printf("\n// string %q", sf.FieldTag)
		m.Fuse(data)
		m.fuseHook()

		m.ctx.PushString(sf.FieldName)
		next(m, sf.FieldElem)
		m.ctx.Pop()

		if oeField {
			m.p.printf("\n}") // close if statement
		}

	}

	if needCloseBrace {
		m.p.printf("\n}")
	}
}

// append raw data
func (m *marshalGen) rawbytes(bts []byte) {
	m.p.print("\no = append(o, ")
	for _, b := range bts {
		m.p.printf("0x%x,", b)
	}
	m.p.print(")")
}

func (m *marshalGen) gMap(s *Map) {
	if !m.p.ok() {
		return
	}
	m.fuseHook()
	vname := s.Varname()
	m.p.printf("\nif %s == nil {", vname)
	m.p.printf("\n  o = msgp.AppendNil(o)")
	m.p.printf("\n} else {")
	m.rawAppend(mapHeader, lenAsUint32, vname)
	m.p.printf("\n}")

	m.p.printf("\n%s_keys := make([]%s, 0, len(%s))", s.Keyidx, s.Key.TypeName(), vname)
	m.p.printf("\nfor %s := range %s {", s.Keyidx, vname)
	m.p.printf("\n%s_keys = append(%s_keys, %s)", s.Keyidx, s.Keyidx, s.Keyidx)
	m.p.closeblock()

	m.p.printf("\nsort.Sort(%s(%s_keys))", s.Key.SortInterface(), s.Keyidx)

	m.p.printf("\nfor _, %s := range %s_keys {", s.Keyidx, s.Keyidx)
	m.p.printf("\n%s := %s[%s]", s.Validx, vname, s.Keyidx)
	m.p.printf("\n_ = %s", s.Validx) // we may not use the value, if it's a struct{}
	m.ctx.PushVar(s.Keyidx)
	next(m, s.Key)
	next(m, s.Value)
	m.ctx.Pop()
	m.p.closeblock()
}

func (m *marshalGen) gSlice(s *Slice) {
	if !m.p.ok() {
		return
	}
	m.fuseHook()
	vname := s.Varname()
	m.p.printf("\nif %s == nil {", vname)
	m.p.printf("\n  o = msgp.AppendNil(o)")
	m.p.printf("\n} else {")
	m.rawAppend(arrayHeader, lenAsUint32, vname)
	m.p.printf("\n}")
	m.p.rangeBlock(m.ctx, s.Index, vname, m, s.Els)
}

func (m *marshalGen) gArray(a *Array) {
	if !m.p.ok() {
		return
	}
	m.fuseHook()
	if be, ok := a.Els.(*BaseElem); ok && be.Value == Byte {
		m.rawAppend("Bytes", "(%s)[:]", a.Varname())
		return
	}

	m.rawAppend(arrayHeader, literalFmt, a.Size)
	m.p.rangeBlock(m.ctx, a.Index, a.Varname(), m, a.Els)
}

func (m *marshalGen) gPtr(p *Ptr) {
	if !m.p.ok() {
		return
	}
	m.fuseHook()
	m.p.printf("\nif %s == nil {\no = msgp.AppendNil(o)\n} else {", p.Varname())
	next(m, p.Value)
	m.p.closeblock()
}

func (m *marshalGen) gBase(b *BaseElem) {
	if !m.p.ok() {
		return
	}
	m.fuseHook()
	vname := b.Varname()

	if b.Convert {
		if b.ShimMode == Cast {
			vname = tobaseConvert(b)
		} else {
			vname = randIdent()
			m.p.printf("\nvar %s %s", vname, b.BaseType())
			m.p.printf("\n%s = %s", vname, tobaseConvert(b))
		}
	}

	switch b.Value {
	case IDENT:
		m.p.printf("\no = %s.MarshalMsg(o)", vname)
	case Intf, Ext:
		m.p.printf("\no = msgp.Append%s(o, %s)", b.BaseName(), vname)
	default:
		m.rawAppend(b.BaseName(), literalFmt, vname)
	}
}
