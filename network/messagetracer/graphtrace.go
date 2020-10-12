// +build msgtrace

package messagetracer

import (
	"github.com/algorand/graphtrace/graphtrace"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

var log logging.Logger

type graphtraceMessageTracer struct {
	tracer graphtrace.Client
}

func (gmt *graphtraceMessageTracer) Init(cfg config.Local) MessageTracer {
	var err error
	gmt.tracer, err = graphtrace.NewTcpClient(cfg.NetworkMessageTraceServer)
	if err != nil {
		log.Errorf("unable to create trace client: %v", err)
		return nil
	}
	return gmt
}
func (gmt *graphtraceMessageTracer) Trace(m []byte) {
	gmt.tracer.Trace(m)
}

func NewGraphtraceMessageTracer() MessageTracer {
	return &graphtraceMessageTracer{}
}

func init() {
	log = logging.Base()
	if implFactory != nil {
		panic("at most one MessageTracer impl should be compiled in, dup found at graphtrace.go init()")
	}
	implFactory = NewGraphtraceMessageTracer
}
