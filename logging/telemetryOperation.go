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

package logging

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/algorand/go-algorand/logging/telemetryspec"
)

func makeTelemetryOperation(telemetryState *telemetryState, category telemetryspec.Category, identifier telemetryspec.Operation) TelemetryOperation {
	return TelemetryOperation{
		startTime:      time.Now(),
		category:       category,
		identifier:     identifier,
		telemetryState: telemetryState,
		pending:        1, // Indicates we should process Stop() when called
	}
}

// Stop is called to report the completion of an operation started by logger.StartOperation
func (op *TelemetryOperation) Stop(l logger, details interface{}) {
	// If we have already called Stop, or if we're a nil operation, don't do anything
	if !atomic.CompareAndSwapInt32(&op.pending, 1, 0) {
		return
	}

	elapsed := time.Since(op.startTime).Nanoseconds()
	entry := l.WithFields(logrus.Fields{
		"duration": elapsed,
	}).(logger)

	op.telemetryState.logTelemetry(entry, buildMessage(string(op.category), string(op.identifier), "Stop"), details)
}
