// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.
//
// +build msgtrace

package messagetracer

import (
	"hash/fnv"

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
	gmt.tracer, err = graphtrace.NewTCPClient(cfg.NetworkMessageTraceServer, gmt.log)
	if err != nil {
		gmt.log.Errorf("unable to create trace client: %v", err)
		return nil
	}
	gmt.log.Infof("tracing network messages to %s", cfg.NetworkMessageTraceServer)
	return gmt
}
func (gmt *graphtraceMessageTracer) HashTrace(prefix string, data []byte) {
	hasher := fnv.New64a()
	hasher.Write(data)
	pb := []byte(prefix)
	msg := make([]byte, len(pb)+8)
	copy(msg, pb)
	hash := hasher.Sum(msg[0:len(pb)])
	gmt.tracer.Trace(hash)
}

// NewGraphtraceMessageTracer returns a new MessageTracer that sends data to a graphtrace collector
func NewGraphtraceMessageTracer(log logging.Logger) MessageTracer {
	return &graphtraceMessageTracer{log: log}
}

func init() {
	if implFactory != nil {
		panic("at most one MessageTracer impl should be compiled in, dup found at graphtrace.go init()")
	}
	implFactory = NewGraphtraceMessageTracer
}
