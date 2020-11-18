// Copyright (C) 2019-2020 Algorand, Inc.
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

// Proposal is a prefix for HashTrace()
const Proposal = "prop"
