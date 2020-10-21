// +build msgtrace

package messagetracer

import (
	"github.com/algorand/graphtrace/graphtrace"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

type graphtraceMessageTracer struct {
	tracer graphtrace.Client
	log    logging.Logger
}

func (gmt *graphtraceMessageTracer) Init(cfg config.Local) MessageTracer {
	if cfg.NetworkMessageTraceServer == "" {
		gmt.log.Info("NetworkMessageTraceServer empty graphtrace disabled")
		return nil
	}
	var err error
	gmt.tracer, err = graphtrace.NewTcpClient(cfg.NetworkMessageTraceServer)
	if err != nil {
		gmt.log.Errorf("unable to create trace client: %v", err)
		return nil
	}
	gmt.log.Infof("tracing network messages to %s", cfg.NetworkMessageTraceServer)
	return gmt
}
func (gmt *graphtraceMessageTracer) Trace(m []byte) {
	gmt.tracer.Trace(m)
}

func NewGraphtraceMessageTracer(log logging.Logger) MessageTracer {
	return &graphtraceMessageTracer{log: log}
}

func init() {
	if implFactory != nil {
		panic("at most one MessageTracer impl should be compiled in, dup found at graphtrace.go init()")
	}
	implFactory = NewGraphtraceMessageTracer
}
