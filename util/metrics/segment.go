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

package metrics

import (
	"sync/atomic"
	"time"
)

// Segment represent a single segment variable.
type Segment struct {
	duration            *Gauge
	totalDuration       *Counter
	counter             *Counter
	concurrentInstances *Gauge
	concurrentCounter   uint32
}

// SegmentInstance is generated once a segments starts.
type SegmentInstance struct {
	segment *Segment
	start   time.Time
	labels  map[string]string
}

// MakeSegment create a new segment with the provided name and description.
func MakeSegment(metric *MetricName) *Segment {
	c := &Segment{
		duration:            MakeGauge(MetricName{Name: metric.Name + "_sec", Description: metric.Description + "(duration)"}),
		totalDuration:       MakeCounter(MetricName{Name: metric.Name + "_sec_total", Description: metric.Description + "(total duration)"}),
		counter:             MakeCounter(MetricName{Name: metric.Name + "_total", Description: metric.Description + "(total count)"}),
		concurrentInstances: MakeGauge(MetricName{Name: metric.Name + "_concurrent", Description: metric.Description + "(concurrent instances)"}),
	}
	return c
}

// EnterSegment is called when a segment is entered.
func (segment *Segment) EnterSegment(labels map[string]string) (*SegmentInstance, error) {
	segment.counter.Inc(labels)
	concurrentCounter := atomic.AddUint32(&segment.concurrentCounter, uint32(1))
	segment.concurrentInstances.Set(float64(concurrentCounter), labels)
	return &SegmentInstance{
		segment: segment,
		start:   time.Now(),
		labels:  labels,
	}, nil
}

// Register registers the counter with the default/specific registry
func (segment *Segment) Register(reg *Registry) {
	segment.duration.Register(reg)
	segment.totalDuration.Register(reg)
	segment.counter.Register(reg)
	segment.concurrentInstances.Register(reg)
}

// Deregister deregisters the counter with the default/specific registry
func (segment *Segment) Deregister(reg *Registry) {
	segment.duration.Deregister(reg)
	segment.totalDuration.Deregister(reg)
	segment.counter.Deregister(reg)
	segment.concurrentInstances.Deregister(reg)
}

// LeaveSegment is expected to be called via a "defer" statement.
func (segInstance *SegmentInstance) LeaveSegment() error {
	if segInstance == nil {
		return nil
	}
	concurrentCounter := atomic.AddUint32(&segInstance.segment.concurrentCounter, ^uint32(0))
	seconds := time.Since(segInstance.start).Seconds()
	segInstance.segment.duration.Set(seconds, segInstance.labels)
	segInstance.segment.totalDuration.Add(seconds, segInstance.labels)
	segInstance.segment.concurrentInstances.Set(float64(concurrentCounter), segInstance.labels)
	return nil
}
