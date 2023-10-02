package gen

import (
	"io"
)

func isZeros(w io.Writer, topics *Topics) *isZeroGen {
	return &isZeroGen{
		p:      printer{w: w},
		topics: topics,
	}
}

type isZeroGen struct {
	passes
	p      printer
	ctx    *Context
	topics *Topics
}

func (s *isZeroGen) Method() Method { return IsZero }

func (s *isZeroGen) Apply(dirs []string) error {
	return nil
}

func (s *isZeroGen) Execute(p Elem) ([]string, error) {
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

	s.ctx = &Context{}
	s.ctx.PushString(p.TypeName())

	s.p.comment("MsgIsZero returns whether this is a zero value")

	if IsDangling(p) {
		baseType := p.(*BaseElem).IdentName
		ptrName := p.Varname()
		receiver := methodReceiver(p)
		s.p.printf("\nfunc (%s %s) MsgIsZero() bool {", ptrName, receiver)
		s.p.printf("\n  return ((*(%s))(%s)).MsgIsZero()", baseType, ptrName)
		s.p.printf("\n}")
		s.topics.Add(receiver, "MsgIsZero")
		return nil, s.p.err
	}

	ptrName := p.Varname()
	receiver := imutMethodReceiver(p)
	s.p.printf("\nfunc (%s %s) MsgIsZero() bool {", ptrName, receiver)
	ize := p.IfZeroExpr()
	if ize == "" {
		ize = "true"
	}
	s.p.printf("\nreturn %s", ize)
	s.p.printf("\n}")

	s.topics.Add(receiver, "MsgIsZero")
	return nil, s.p.err
}
