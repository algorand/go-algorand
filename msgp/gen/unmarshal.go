package gen

import (
	"go/ast"
	"io"
	"strconv"
	"strings"
)

func unmarshal(w io.Writer, topics *Topics) *unmarshalGen {
	return &unmarshalGen{
		p:      printer{w: w},
		topics: topics,
	}
}

type unmarshalGen struct {
	passes
	p        printer
	hasfield bool
	ctx      *Context
	msgs     []string
	topics   *Topics
}

func (u *unmarshalGen) Method() Method { return Unmarshal }

func (u *unmarshalGen) needsField() {
	if u.hasfield {
		return
	}
	u.p.print("\nvar field []byte; _ = field")
	u.hasfield = true
}

func (u *unmarshalGen) Execute(p Elem) ([]string, error) {
	u.msgs = nil
	u.hasfield = false
	if !u.p.ok() {
		return u.msgs, u.p.err
	}
	p = u.applyall(p)
	if p == nil {
		return u.msgs, nil
	}

	// We might change p.Varname in methodReceiver(); make a copy
	// to not affect other code that will use p.
	p = p.Copy()

	u.ctx = &Context{}

	u.p.comment("UnmarshalMsg implements msgp.Unmarshaler")

	if IsDangling(p) {
		baseType := p.(*BaseElem).IdentName
		c := p.Varname()
		methodRecv := methodReceiver(p)
		u.p.printf("\nfunc (%s %s) UnmarshalMsg(bts []byte) ([]byte, error) {", c, methodRecv)
		u.p.printf("\n  return ((*(%s))(%s)).UnmarshalMsg(bts)", baseType, c)
		u.p.printf("\n}")

		u.p.printf("\nfunc (%s %s) UnmarshalMsgWithState(bts []byte, st msgp.UnmarshalState) ([]byte, error) {", c, methodRecv)
		u.p.printf("\n  return ((*(%s))(%s)).UnmarshalMsgWithState(bts, st)", baseType, c)
		u.p.printf("\n}")

		u.p.printf("\nfunc (_ %[2]s) CanUnmarshalMsg(%[1]s interface{}) bool {", c, methodRecv)
		u.p.printf("\n  _, ok := (%s).(%s)", c, methodRecv)
		u.p.printf("\n  return ok")
		u.p.printf("\n}")

		u.topics.Add(methodRecv, "UnmarshalMsg")
		u.topics.Add(methodRecv, "UnmarshalMsgWithState")
		u.topics.Add(methodRecv, "CanUnmarshalMsg")

		return u.msgs, u.p.err
	}

	// save the vname before calling methodReceiver
	c := p.Varname()
	methodRecv := methodReceiver(p)

	u.p.printf("\nfunc (%s %s) UnmarshalMsgWithState(bts []byte, st msgp.UnmarshalState) (o []byte, err error) {", c, methodRecv)
	u.p.printf("\n  if st.Depth == 0 {")
	u.p.printf("\n    err = msgp.ErrMaxDepthExceeded{}")
	u.p.printf("\n    return")
	u.p.printf("\n  }")
	u.p.printf("\n  st.Depth--")
	next(u, p)
	u.p.print("\no = bts")

	// right before the return: attempt to inspect well formed:
	for _, callback := range p.GetCallbacks() {
		if !callback.IsUnmarshallCallback() {
			continue
		}

		u.p.printf("\nif err = %s.%s(); err != nil {", c, callback.GetName())
		u.p.printf("\n  return")
		u.p.printf("\n}")
	}
	u.p.nakedReturn()

	u.p.printf("\nfunc (%s %s) UnmarshalMsg(bts []byte) (o []byte, err error) {", c, methodRecv)
	u.p.printf("\n return %s.UnmarshalMsgWithState(bts, msgp.DefaultUnmarshalState)", c)
	u.p.printf("\n}")

	u.p.printf("\nfunc (_ %[2]s) CanUnmarshalMsg(%[1]s interface{}) bool {", c, methodRecv)
	u.p.printf("\n  _, ok := (%s).(%s)", c, methodRecv)
	u.p.printf("\n  return ok")
	u.p.printf("\n}")

	u.topics.Add(methodRecv, "UnmarshalMsg")
	u.topics.Add(methodRecv, "UnmarshalMsgWithState")
	u.topics.Add(methodRecv, "CanUnmarshalMsg")

	return u.msgs, u.p.err
}

// does assignment to the variable "name" with the type "base"
func (u *unmarshalGen) assignAndCheck(name string, isnil string, base string) {
	if !u.p.ok() {
		return
	}
	u.p.printf("\n%s, %s, bts, err = msgp.Read%sBytes(bts)", name, isnil, base)
	u.p.wrapErrCheck(u.ctx.ArgsStr())
}

func (u *unmarshalGen) gStruct(s *Struct) {
	if !u.p.ok() {
		return
	}
	if s.AsTuple {
		u.tuple(s)
	} else {
		u.mapstruct(s)
	}
	return
}

func (u *unmarshalGen) tuple(s *Struct) {

	// open block
	sz := randIdent()
	u.p.declare(sz, "int")
	u.assignAndCheck(sz, "_", arrayHeader)
	u.p.arrayCheck(strconv.Itoa(len(s.Fields)), sz)
	for i := range s.Fields {
		if !u.p.ok() {
			return
		}
		u.ctx.PushString(s.Fields[i].FieldName)
		next(u, s.Fields[i].FieldElem)
		u.ctx.Pop()
	}
}

func (u *unmarshalGen) mapstruct(s *Struct) {
	u.needsField()
	sz := randIdent()
	isnil := randIdent()
	u.p.declare(sz, "int")
	u.p.declare(isnil, "bool")

	// go-codec compat: decode an array as sequential elements from this struct,
	// in the order they are defined in the Go type (as opposed to canonical
	// order by sorted tag).
	u.p.printf("\n%s, %s, bts, err = msgp.Read%sBytes(bts)", sz, isnil, mapHeader)
	u.p.printf("\nif _, ok := err.(msgp.TypeError); ok {")

	u.assignAndCheck(sz, isnil, arrayHeader)

	u.ctx.PushString("struct-from-array")
	for i := range s.Fields {
		if !ast.IsExported(s.Fields[i].FieldName) {
			continue
		}

		u.p.printf("\nif %s > 0 {", sz)
		u.p.printf("\n%s--", sz)
		u.ctx.PushString(s.Fields[i].FieldName)
		next(u, s.Fields[i].FieldElem)
		u.ctx.Pop()
		u.p.printf("\n}")
	}

	u.p.printf("\nif %s > 0 {", sz)
	u.p.printf("\nerr = msgp.ErrTooManyArrayFields(%s)", sz)
	u.p.wrapErrCheck(u.ctx.ArgsStr())
	u.p.printf("\n}")
	u.ctx.Pop()

	u.p.printf("\n} else {")
	u.p.wrapErrCheck(u.ctx.ArgsStr())

	u.p.printf("\nif %s {", isnil)
	u.p.printf("\n  %s = %s{}", s.Varname(), s.TypeName())
	u.p.printf("\n}")

	u.p.printf("\nfor %s > 0 {", sz)
	u.p.printf("\n%s--; field, bts, err = msgp.ReadMapKeyZC(bts)", sz)
	u.p.wrapErrCheck(u.ctx.ArgsStr())
	u.p.print("\nswitch string(field) {")
	for i := range s.Fields {
		if !ast.IsExported(s.Fields[i].FieldName) {
			continue
		}

		if !u.p.ok() {
			return
		}
		u.p.printf("\ncase \"%s\":", s.Fields[i].FieldTag)
		u.ctx.PushString(s.Fields[i].FieldName)
		next(u, s.Fields[i].FieldElem)
		u.ctx.Pop()
	}
	u.p.print("\ndefault:\nerr = msgp.ErrNoField(string(field))")
	u.p.wrapErrCheck(u.ctx.ArgsStr())
	u.p.print("\n}") // close switch
	u.p.print("\n}") // close for loop
	u.p.print("\n}") // close else statement for array decode
}

func (u *unmarshalGen) gBase(b *BaseElem) {
	if !u.p.ok() {
		return
	}

	refname := b.Varname() // assigned to
	lowered := b.Varname() // passed as argument
	if b.Convert {
		// begin 'tmp' block
		refname = randIdent()
		lowered = b.ToBase() + "(" + lowered + ")"
		u.p.printf("\n{\nvar %s %s", refname, b.BaseType())
	}

	switch b.Value {
	case Bytes:
		if b.common.AllocBound() != "" {
			sz := randIdent()
			u.p.printf("\nvar %s int", sz)
			u.p.printf("\n%s, err = msgp.ReadBytesBytesHeader(bts)", sz)
			u.p.wrapErrCheck(u.ctx.ArgsStr())
			u.p.printf("\nif %s > %s {", sz, b.common.AllocBound())
			u.p.printf("\nerr = msgp.ErrOverflow(uint64(%s), uint64(%s))", sz, b.common.AllocBound())
			u.p.printf("\nreturn")
			u.p.printf("\n}")
		}
		u.p.printf("\n%s, bts, err = msgp.ReadBytesBytes(bts, %s)", refname, lowered)
	case Ext:
		u.p.printf("\nbts, err = msgp.ReadExtensionBytes(bts, %s)", lowered)
	case IDENT:
		u.p.printf("\nbts, err = %s.UnmarshalMsgWithState(bts, st)", lowered)
	case String:
		if b.common.AllocBound() != "" {
			sz := randIdent()
			u.p.printf("\nvar %s int", sz)
			u.p.printf("\n%s, err = msgp.ReadBytesBytesHeader(bts)", sz)
			u.p.wrapErrCheck(u.ctx.ArgsStr())
			u.p.printf("\nif %s > %s {", sz, b.common.AllocBound())
			u.p.printf("\nerr = msgp.ErrOverflow(uint64(%s), uint64(%s))", sz, b.common.AllocBound())
			u.p.printf("\nreturn")
			u.p.printf("\n}")
		}
		u.p.printf("\n%s, bts, err = msgp.ReadStringBytes(bts)", refname)
	default:
		u.p.printf("\n%s, bts, err = msgp.Read%sBytes(bts)", refname, b.BaseName())
	}
	u.p.wrapErrCheck(u.ctx.ArgsStr())

	if b.Convert {
		// close 'tmp' block
		if b.ShimMode == Cast {
			u.p.printf("\n%s = %s(%s)\n", b.Varname(), b.FromBase(), refname)
		} else {
			u.p.printf("\n%s, err = %s(%s)", b.Varname(), b.FromBase(), refname)
			u.p.wrapErrCheck(u.ctx.ArgsStr())
		}
		u.p.printf("}")
	}
}

func (u *unmarshalGen) gArray(a *Array) {
	if !u.p.ok() {
		return
	}

	// special case for [const]byte objects
	// see decode.go for symmetry
	if be, ok := a.Els.(*BaseElem); ok && be.Value == Byte {
		u.p.printf("\nbts, err = msgp.ReadExactBytes(bts, (%s)[:])", a.Varname())
		u.p.wrapErrCheck(u.ctx.ArgsStr())
		return
	}

	sz := randIdent()
	u.p.declare(sz, "int")
	u.assignAndCheck(sz, "_", arrayHeader)
	u.p.arrayCheckBound(a.Size, sz)

	u.ctx.PushVar(a.Index)
	u.p.printf("\nfor %[1]s := 0; %[1]s < %[2]s; %[1]s++ {", a.Index, sz)
	next(u, a.Els)
	u.p.closeblock()
	u.ctx.Pop()
}

func (u *unmarshalGen) gSlice(s *Slice) {
	if !u.p.ok() {
		return
	}
	sz := randIdent()
	isnil := randIdent()
	u.p.declare(sz, "int")
	u.p.declare(isnil, "bool")
	u.assignAndCheck(sz, isnil, arrayHeader)
	resizemsgs := u.p.resizeSlice(sz, isnil, s, u.ctx.ArgsStr())
	u.msgs = append(u.msgs, resizemsgs...)
	childElement := s.Els
	if s.Els.AllocBound() == "" && len(strings.Split(s.AllocBound(), ",")) > 1 {
		childElement = s.Els.Copy()
		childElement.SetAllocBound(s.AllocBound()[strings.Index(s.AllocBound(), ",")+1:])
	}
	u.p.rangeBlock(u.ctx, s.Index, s.Varname(), u, childElement)
}

func (u *unmarshalGen) gMap(m *Map) {
	if !u.p.ok() {
		return
	}
	sz := randIdent()
	isnil := randIdent()
	u.p.declare(sz, "int")
	u.p.declare(isnil, "bool")
	u.assignAndCheck(sz, isnil, mapHeader)

	// allocate or clear map
	resizemsgs := u.p.resizeMap(sz, isnil, m, u.ctx.ArgsStr())
	u.msgs = append(u.msgs, resizemsgs...)

	// loop and get key,value
	u.p.printf("\nfor %s > 0 {", sz)
	u.p.printf("\nvar %s %s; var %s %s; %s--", m.Keyidx, m.Key.TypeName(), m.Validx, m.Value.TypeName(), sz)
	next(u, m.Key)
	u.ctx.PushVar(m.Keyidx)
	next(u, m.Value)
	u.ctx.Pop()
	u.p.mapAssign(m)
	u.p.closeblock()
}

func (u *unmarshalGen) gPtr(p *Ptr) {
	u.p.printf("\nif msgp.IsNil(bts) { bts, err = msgp.ReadNilBytes(bts); if err != nil { return }; %s = nil; } else { ", p.Varname())
	u.p.initPtr(p)
	next(u, p.Value)
	u.p.closeblock()
}
