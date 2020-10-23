package messagetracer

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

type MessageTracer interface {
	Init(cfg config.Local) MessageTracer
	HashTrace(prefix string, data []byte)
}

var implFactory func(logging.Logger) MessageTracer

type nopMessageTracer struct {
}

func (gmt *nopMessageTracer) Init(cfg config.Local) MessageTracer {
	return nil
}
func (gmt *nopMessageTracer) HashTrace(prefix string, data []byte) {
}

var singletonNopMessageTracer nopMessageTracer

func NewTracer(log logging.Logger) MessageTracer {
	if implFactory != nil {
		log.Info("graphtrace factory enabled")
		return implFactory(log)
	}
	log.Info("graphtrace factory DISabled")
	return &singletonNopMessageTracer
}
