// Copyright (C) 2019-2022 Algorand, Inc.
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

package txnsync

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/timers"
)

// Create a logger that hooks the "Metrics" function to signal that we have
// indeed sent some metrics
type metricsLogger struct {
	Logger
	sentLogger *bool
}

func makeMetricsLogger(sentLogger *bool) metricsLogger {
	return metricsLogger{
		sentLogger: sentLogger,
	}
}

func (n metricsLogger) Metrics(category telemetryspec.Category, metrics telemetryspec.MetricDetails, details interface{}) {
	*n.sentLogger = true
}

// TestPrune Test the prune capabilities of the profiler.  We want to simulate
// the conditions to show that the profiler will "remove" elements when needed.
func TestPrune(t *testing.T) {
	partitiontest.PartitionTest(t)

	prof := makeProfiler(2*time.Millisecond, nil, nil, 3*time.Millisecond)
	a := require.New(t)

	a.NotNil(prof)
	a.NotNil(prof.elements)

	prof.profileSum = 2
	prof.profileSpan = 1

	prof.profile = append(prof.profile, 0)

	firstElement := &prof.elements[0]

	(*firstElement).detached = false

	(*firstElement).times = append((*firstElement).times, time.Duration(2), time.Duration(2))
	(*firstElement).total = time.Duration(4)

	a.Equal(len(prof.profile), 1)
	a.Equal(len((*firstElement).times), 2)

	prof.prune()

	a.Equal(len(prof.profile), 0)
	a.Equal(len((*firstElement).times), 1)
	a.Equal((*firstElement).total, time.Duration(2))

}

// TestProfilerStartEndZero Test functionality if the log interval is 0
func TestProfilerStartEndZero(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	prof := makeProfiler(2*time.Millisecond, s.clock, nil, 0*time.Millisecond)
	a := require.New(t)

	a.NotNil(prof)
	a.NotNil(prof.elements)

	firstElement := &prof.elements[0]

	oldLastStart := (*firstElement).lastStart
	oldTotal := (*firstElement).total

	(*firstElement).start()
	time.Sleep(5 * time.Millisecond)
	(*firstElement).end()

	a.Equal(oldLastStart, (*firstElement).lastStart)
	a.Equal(oldTotal, (*firstElement).total)

}

// TestProfilerStartEndEnabled Test profiler functionality if log interval is non-zero.
// This test will assume that a successful start()-end() call
// will produce a non-zero profile sum.
//
// This test forces "detached element" logic to be run.
func TestProfilerStartEndEnabled(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	tmp := false
	// Need to supply logger just in case log profile is called
	nl := makeMetricsLogger(&tmp)
	prof := makeProfiler(2*time.Millisecond, s.clock, nl, 3*time.Millisecond)

	a := require.New(t)

	a.NotNil(prof)
	a.NotNil(prof.elements)

	element := prof.getElement(0)

	// Ensure that we trip the if statement
	element.detached = false

	a.Equal(element.total, time.Duration(0))
	a.Equal(len(element.times), 0)
	a.Equal(len(element.profiler.profile), 0)
	a.Equal(element.profiler.profileSum, time.Duration(0))

	element.start()
	element.end()
	a.NotEqual(element.total, time.Duration(0))
	a.Equal(len(element.times), 1)
	a.Equal(len(element.profiler.profile), 1)
	a.NotEqual(element.profiler.profileSum, time.Duration(0))

}

// TestProfilerStartEndDisabled Test start-end functionality with detached elements.
func TestProfilerStartEndDisabled(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	prof := makeProfiler(2*time.Millisecond, s.clock, nil, 3*time.Millisecond)
	a := require.New(t)

	a.NotNil(prof)
	a.NotNil(prof.elements)

	element := prof.getElement(0)

	// Set to true so we don't trip the if statement for now
	element.detached = true

	a.Equal(element.total, time.Duration(0))
	a.Equal(len(element.times), 0)
	a.Equal(len(element.profiler.profile), 0)

	element.start()
	element.end()
	a.NotEqual(element.total, time.Duration(0))
	a.Equal(len(element.times), 1)
	a.Equal(len(element.profiler.profile), 1)

}

// TestMaybeLogProfile Test that Metrics are only sent when all conditions are met and not
// sent if they are not.
func TestMaybeLogProfile(t *testing.T) {
	partitiontest.PartitionTest(t)

	sentMetrics := false

	var s syncState
	nl := makeMetricsLogger(&sentMetrics)
	s.clock = timers.MakeMonotonicClock(time.Now())
	prof := makeProfiler(2*time.Millisecond, s.clock, nl, 3*time.Millisecond)

	a := require.New(t)

	a.NotNil(prof)
	a.NotNil(prof.elements)

	// --
	prof.logInterval = 0
	prof.maybeLogProfile()
	a.False(sentMetrics)
	prof.logInterval = 1

	// --

	prof.profileSum = 1
	prof.profileSpan = 4
	prof.maybeLogProfile()
	a.False(sentMetrics)

	prof.profileSum = 4
	prof.profileSpan = 4

	// --
	prof.logInterval = 2147483647 // Make this stupidly high to make sure we hit the if statement
	prof.lastProfileLog = prof.clock.Since()
	prof.maybeLogProfile()
	a.False(sentMetrics)

	// The last call to maybeLogProfile should set lastProfileLog to cur time
	prof.logInterval = 1 * time.Nanosecond
	// Sleep some time so we are above 1 ns of duration with a high degree of certainty
	time.Sleep(200 * time.Millisecond)

	prof.maybeLogProfile()
	a.True(sentMetrics)

}

// TestGetElement Tests that getting an element returns it properly
func TestGetElement(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)
	a := require.New(t)

	a.NotNil(prof)
	a.NotNil(prof.elements)

	for i := 0; i < profElementLast; i++ {
		e := prof.getElement(profElements(i))

		a.Equal(e.id, i)
	}

}

// TestMakeProfiler Ensures that makeProfiler() returns a valid profiler.
func TestMakeProfiler(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)
	a := require.New(t)

	a.NotNil(prof)
	a.NotNil(prof.elements)

	a.Equal(prof.profileSpan, 2*time.Millisecond)
	a.Equal(prof.logInterval, 3*time.Millisecond)
	a.Equal(len(prof.elements), profElementLast)

	for i, e := range prof.elements {
		a.Equal(e.id, i)
		a.Equal(e.profiler, prof)

		if i < profFirstDetachedElement {
			a.False(e.detached)
		} else {
			a.True(e.detached)
		}
	}

}
