package gen

import (
	"bytes"
	"fmt"
	"go/ast"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/algorand/msgp/msgp"
)

type maxSizeState uint8

const (
	// need to write "s = ..."
	assignM maxSizeState = iota

	// need to write "s += ..."
	addM

	// can just append "+ ..."
	exprM

	multM
	// the result is multiplied by whatever is preceeding it
)

func maxSizes(w io.Writer, topics *Topics) *maxSizeGen {
	return &maxSizeGen{
		p:      printer{w: w},
		state:  assignM,
		topics: topics,
	}
}

type maxSizeGen struct {
	passes
	p      printer
	state  maxSizeState
	ctx    *Context
	topics *Topics
}

func (s *maxSizeGen) Method() Method { return MaxSize }

func (s *maxSizeGen) Apply(dirs []string) error {
	return nil
}

// this lets us chain together addition
// operations where possible
func (s *maxSizeGen) addConstant(sz string) {
	if !s.p.ok() {
		return
	}

	switch s.state {
	case assignM:
		s.p.print("\ns = " + sz)
		s.state = exprM
		return
	case addM:
		s.p.print("\ns += " + sz)
		s.state = exprM
		return
	case exprM:
		s.p.print(" + " + sz)
		return
	case multM:
		s.p.print(" * ( " + sz + ")")
		s.state = addM
		return
	}

	panic("unknown size state")
}

func (s *maxSizeGen) Execute(p Elem) ([]string, error) {
	if !s.p.ok() {
		return nil, s.p.err
	}
	p = s.applyall(p)
	if p == nil {
		return nil, nil
	}

	// We might change p.Varname in methodReceiver(); make a copy
	// to not affect other code that will use p.
	p = p.Copy()

	s.p.comment("MaxSize returns a maximum valid message size for this message type")

	if IsDangling(p) {
		baseType := p.(*BaseElem).IdentName
		s.p.printf("\nfunc %s int{", getMaxSizeMethod(p.TypeName()))
		s.p.printf("\n  return %s", getMaxSizeMethod(baseType))
		s.p.printf("\n}")
		s.topics.Add(baseType, getMaxSizeMethod(baseType))
		return nil, s.p.err
	}

	s.ctx = &Context{}
	s.ctx.PushString(p.TypeName())

	// receiver := imutMethodReceiver(p)
	s.p.printf("\nfunc  %s (s int) {", getMaxSizeMethod(p.TypeName()))
	s.state = assignM
	next(s, p)
	s.p.nakedReturn()
	s.topics.Add(p.TypeName(), getMaxSizeMethod(p.TypeName()))
	return nil, s.p.err
}

func (s *maxSizeGen) gStruct(st *Struct) {
	if !s.p.ok() {
		return
	}

	nfields := uint32(0)
	for i := range st.Fields {
		if ast.IsExported(st.Fields[i].FieldName) {
			nfields += 1
		}
	}

	if st.AsTuple {
		data := msgp.AppendArrayHeader(nil, nfields)
		s.addConstant(strconv.Itoa(len(data)))
		for i := range st.Fields {
			if !ast.IsExported(st.Fields[i].FieldName) {
				continue
			}

			if !s.p.ok() {
				return
			}
			next(s, st.Fields[i].FieldElem)
		}
	} else {
		data := msgp.AppendMapHeader(nil, nfields)
		s.addConstant(strconv.Itoa(len(data)))
		for i := range st.Fields {
			if !ast.IsExported(st.Fields[i].FieldName) {
				continue
			}

			data = data[:0]
			data = msgp.AppendString(data, st.Fields[i].FieldTag)
			s.addConstant(strconv.Itoa(len(data)))
			next(s, st.Fields[i].FieldElem)
		}
	}
}

func (s *maxSizeGen) gPtr(p *Ptr) {
	s.state = addM // inner must use add
	next(s, p.Value)
	s.state = addM // closing block; reset to add
}

func (s *maxSizeGen) gSlice(sl *Slice) {
	if !s.p.ok() {
		return
	}
	s.state = addM
	s.p.comment("Calculating size of slice: " + sl.Varname())
	if (sl.AllocBound() == "" || sl.AllocBound() == "-") && (sl.MaxTotalBytes() == "" || sl.MaxTotalBytes() == "-") {
		s.p.printf("\npanic(\"Slice %s is unbounded\")", sl.Varname())
		s.state = addM // reset the add to prevent further + expressions from being added to the end the panic statement
		return
	}

	s.addConstant(builtinSize(arrayHeader))

	// use maxtotalbytes if it's available
	if sl.common.MaxTotalBytes() != "" && sl.common.MaxTotalBytes() != "-" {
		s.addConstant(sl.common.MaxTotalBytes())
		return
	}

	topLevelAllocBound := sl.AllocBound()
	childElement := sl.Els
	if sl.Els.AllocBound() == "" && len(strings.Split(sl.AllocBound(), ",")) > 1 {
		splitIndex := strings.Index(sl.AllocBound(), ",")
		childElement = sl.Els.Copy()
		childElement.SetAllocBound(sl.AllocBound()[splitIndex+1:])
		topLevelAllocBound = sl.AllocBound()[:splitIndex]
	}

	if str, err := maxSizeExpr(childElement); err == nil {
		s.addConstant(fmt.Sprintf("((%s) * (%s))", topLevelAllocBound, str))
	} else {
		s.p.printf("\npanic(\"Unable to determine max size: %s\")", err)
	}
	s.state = addM
	return
}

func (s *maxSizeGen) gArray(a *Array) {
	if !s.p.ok() {
		return
	}
	// If this is not the first line where we define s = ... then we need to reset the state
	// to addM so that the comment is printed correctly on a newline
	if s.state != assignM {
		s.state = addM
	}
	s.p.comment("Calculating size of array: " + a.Varname())

	s.addConstant(builtinSize(arrayHeader))

	if str, err := maxSizeExpr(a.Els); err == nil {
		s.addConstant(fmt.Sprintf("((%s) * (%s))", a.Size, str))
	} else {
		s.p.printf("\npanic(\"Unable to determine max size: %s\")", err)

	}
	s.state = addM
	return
}

func (s *maxSizeGen) gMap(m *Map) {
	vn := m.Varname()
	s.state = addM
	s.addConstant(builtinSize(mapHeader))
	topLevelAllocBound := m.AllocBound()
	if topLevelAllocBound != "" && topLevelAllocBound == "-" {
		s.p.printf("\npanic(\"Map %s is unbounded\")", m.Varname())
		s.state = addM // reset the add to prevent further + expressions from being added to the end the panic statement
		return
	}
	splitBounds := strings.Split(m.AllocBound(), ",")
	if len(splitBounds) > 1 {
		topLevelAllocBound = splitBounds[0]
		m.Key.SetAllocBound(splitBounds[1])
		if len(splitBounds) > 2 {
			m.Value.SetAllocBound(splitBounds[2])
		}
	}

	s.p.comment("Adding size of map keys for " + vn)
	s.p.printf("\ns += %s", topLevelAllocBound)
	s.state = multM
	next(s, m.Key)

	s.p.comment("Adding size of map values for " + vn)
	s.p.printf("\ns += %s", topLevelAllocBound)
	s.state = multM
	next(s, m.Value)

	s.state = addM
}

func (s *maxSizeGen) gBase(b *BaseElem) {
	if !s.p.ok() {
		return
	}
	if b.MaxTotalBytes() != "" {
		s.p.comment("Using maxtotalbytes for: " + b.Varname())
		s.state = addM
		s.addConstant(b.MaxTotalBytes())
		s.state = addM
		return
	}
	if b.Convert && b.ShimMode == Convert {
		s.state = addM
		vname := randIdent()
		s.p.printf("\nvar %s %s", vname, b.BaseType())

		// ensure we don't get "unused variable" warnings from outer slice iterations
		s.p.printf("\n_ = %s", b.Varname())

		value, err := baseMaxSizeExpr(b.Value, vname, b.BaseName(), b.TypeName(), b.common.AllocBound())
		if err != nil {
			s.p.printf("\npanic(\"Unable to determine max size: %s\")", err)
			s.state = addM // reset the add to prevent further + expressions from being added to the end the panic statement
			return
		}
		s.p.printf("\ns += %s", value)
		s.state = exprM

	} else {
		vname := b.Varname()
		if b.Convert {
			vname = tobaseConvert(b)
		}
		value, err := baseMaxSizeExpr(b.Value, vname, b.BaseName(), b.TypeName(), b.common.AllocBound())
		if err != nil {
			s.p.printf("\npanic(\"Unable to determine max size: %s\")", err)
			s.state = addM // reset the add to prevent further + expressions from being added to the end the panic statement
			return
		}
		s.addConstant(value)
	}
}

func baseMaxSizeExpr(value Primitive, vname, basename, typename string, allocbound string) (string, error) {
	if typename == "msgp.Raw" {
		return "", fmt.Errorf("MaxSize() not implemented for Raw type")
	}
	switch value {
	case Ext:
		return "", fmt.Errorf("MaxSize() not implemented for Ext type")
	case Intf:
		return "", fmt.Errorf("MaxSize() not implemented for Interfaces")
	case IDENT:
		return getMaxSizeMethod(typename), nil
	case Bytes:
		if allocbound == "" || allocbound == "-" {
			return "", fmt.Errorf("Byteslice type %s is unbounded", vname)
		}
		return "msgp.BytesPrefixSize + " + allocbound, nil
	case String:
		if allocbound == "" || allocbound == "-" {
			return "", fmt.Errorf("String type %s is unbounded", vname)
		}
		return "msgp.StringPrefixSize +  " + allocbound, nil
	default:
		return builtinSize(basename), nil
	}
}

// return a fixed-size expression, if possible.
// only possible for *BaseElem, *Array and Struct.
// returns (expr, err)
func maxSizeExpr(e Elem) (string, error) {
	switch e := e.(type) {
	case *Array:
		if str, err := maxSizeExpr(e.Els); err == nil {
			return fmt.Sprintf("(%s * (%s))", e.Size, str), nil
		} else {
			return "", err
		}
	case *BaseElem:
		if fixedSize(e.Value) {
			return builtinSize(e.BaseName()), nil
		} else if (e.TypeName()) == "msgp.Raw" {
			return "", fmt.Errorf("Raw type is unbounded")
		} else if (e.Value) == String {
			if e.AllocBound() == "" || e.AllocBound() == "-" {
				return "", fmt.Errorf("String type is unbounded for %s", e.Varname())
			}
			return fmt.Sprintf("(msgp.StringPrefixSize + %s)", e.AllocBound()), nil
		} else if (e.Value) == IDENT {
			return fmt.Sprintf("(%s)", getMaxSizeMethod(e.TypeName())), nil
		} else if (e.Value) == Bytes {
			if e.AllocBound() == "" || e.AllocBound() == "-" {
				return "", fmt.Errorf("Inner byteslice type is unbounded")
			}
			return fmt.Sprintf("(msgp.BytesPrefixSize + %s)", e.AllocBound()), nil
		}
	case *Struct:
		return fmt.Sprintf("(%s)", getMaxSizeMethod(e.TypeName())), nil
	case *Slice:
		if e.AllocBound() == "" || e.AllocBound() == "-" {
			return "", fmt.Errorf("Slice %s is unbounded", e.Varname())
		}
		if str, err := maxSizeExpr(e.Els); err == nil {
			return fmt.Sprintf("(%s * (%s))", e.AllocBound(), str), nil
		} else {
			return "", err
		}
	}
	return fmt.Sprintf("%s, %s", e.TypeName(), reflect.TypeOf(e)), nil
}

func getMaxSizeMethod(typeName string) (s string) {
	var pos int
	dotIndex := strings.Index(typeName, ".")
	if dotIndex != -1 {
		pos = dotIndex + 1
	}
	b := []byte(typeName)
	b[pos] = bytes.ToUpper(b)[pos]
	return string(b) + "MaxSize()"
}
