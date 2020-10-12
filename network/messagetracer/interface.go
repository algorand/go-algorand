package messagetracer

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

type MessageTracer interface {
	Init(cfg config.Local) MessageTracer
	Trace(m []byte)
}

var implFactory func() MessageTracer

type nopMessageTracer struct {
}

func (gmt *nopMessageTracer) Init(cfg config.Local) MessageTracer {
	return nil
}
func (gmt *nopMessageTracer) Trace(m []byte) {
}

var singletonNopMessageTracer nopMessageTracer

func NewTracer() MessageTracer {
	if implFactory != nil {
		logging.Base().Info("messagetracer using implFactory")
		return implFactory()
	}
	logging.Base().Info("messagetracer disabled")
	return &singletonNopMessageTracer
}
