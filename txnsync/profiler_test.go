package txnsync

import (
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/util/timers"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPrune(t *testing.T) {

	var s syncState
	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)
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

func TestProfilerStartEndEnabled(t *testing.T) {

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)

	// Set logging mechanism in-case maybeLogProfile is called
	prof.profileMetricLogger = profilerMetricLoggerFunc(func(metrics telemetryspec.TransactionSyncProfilingMetrics, l logging.Logger) {
		return
	},
	)

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

func TestProfilerStartEndDisabled(t *testing.T) {

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)
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

func TestMaybeLogProfile(t *testing.T) {

	sentMetrics := false

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)
	prof.profileMetricLogger = profilerMetricLoggerFunc(func(metrics telemetryspec.TransactionSyncProfilingMetrics, l logging.Logger) {
		sentMetrics = true
		return
	},
	)
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

func TestGetElement(t *testing.T) {
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

func TestMakeProfiler(t *testing.T) {
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
