package messagetracer

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

// MessageTracer interface for configuring trace client and sending trace messages
type MessageTracer interface {
	// Init configures trace client or returns nil.
	// Caller is expected to check for nil, e.g. `if t != nil {t.HashTrace(...)}`
	Init(cfg config.Local) MessageTracer

	// HashTrace submits a trace message to the statistics server.
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

// NewTracer constructs a new MessageTracer if that has been compiled in with the build tag `msgtrace`
func NewTracer(log logging.Logger) MessageTracer {
	if implFactory != nil {
		log.Info("graphtrace factory enabled")
		return implFactory(log)
	}
	log.Info("graphtrace factory DISabled")
	return &singletonNopMessageTracer
}
