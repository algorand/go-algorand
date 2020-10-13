package messagetracer

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

type MessageTracer interface {
	Init(cfg config.Local) MessageTracer
	Trace(m []byte)
}

var implFactory func(logging.Logger) MessageTracer

type nopMessageTracer struct {
}

func (gmt *nopMessageTracer) Init(cfg config.Local) MessageTracer {
	return nil
}
func (gmt *nopMessageTracer) Trace(m []byte) {
}

var singletonNopMessageTracer nopMessageTracer

func NewTracer(log logging.Logger) MessageTracer {
	if implFactory != nil {
		return implFactory(log)
	}
	return &singletonNopMessageTracer
}
