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

package fuzzer

import (
	"encoding/json"
	"fmt"

	"github.com/algorand/go-algorand/protocol"
)

var _ = fmt.Printf

type ScheduleOperation int

const (
	After      ScheduleOperation = iota // 0
	Before     ScheduleOperation = iota // 1
	Between    ScheduleOperation = iota // 2
	NotAfter   ScheduleOperation = iota // 3
	NotBefore  ScheduleOperation = iota // 4
	NotBetween ScheduleOperation = iota // 5
)

type SchedulerFilterSchedule struct {
	FirstTick, SecondTick int
	Operation             ScheduleOperation
	Nodes                 []int // which nodes would be affected
}

type SchedulerFilterConfig struct {
	Filters       []NetworkFilterFactory
	Schedule      []SchedulerFilterSchedule
	ScheduleName  string
	DebugMessages bool
}

type SchedulerFilter struct {
	NetworkFilter
	upstream   UpstreamFilter
	downstream DownstreamFilter
	enabled    bool
	nodeID     int
	filters    []NetworkFilter
	lastTick   int

	NetworkFilterFactory
	factoryConfig *SchedulerFilterConfig
}

func (n *SchedulerFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	nextFilter := n.downstream
	if n.enabled && len(n.filters) > 0 {
		nextFilter = n.filters[0]
	}
	nextFilter.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *SchedulerFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *SchedulerFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	nextFilter := n.upstream
	if n.enabled && len(n.filters) > 0 {
		nextFilter = n.filters[len(n.filters)-1]
	}
	nextFilter.ReceiveMessage(sourceNode, tag, data)
}

func (n *SchedulerFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
	if len(n.filters) > 0 {
		n.filters[len(n.filters)-1].SetDownstreamFilter(f)
	}
}

func (n *SchedulerFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
	if len(n.filters) > 0 {
		n.filters[0].SetUpstreamFilter(f)
	}
}

func (n *SchedulerFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	f := &SchedulerFilter{
		factoryConfig: n.factoryConfig,
		nodeID:        nodeID,
		filters:       make([]NetworkFilter, len(n.factoryConfig.Filters)),
	}
	for i, factory := range n.factoryConfig.Filters {
		f.filters[i] = factory.CreateFilter(nodeID, fuzzer)
	}
	for i := 1; i < len(f.filters); i++ {
		f.filters[i].SetUpstreamFilter(f.filters[i-1])
	}
	for i := 0; i < len(f.filters)-1; i++ {
		f.filters[i].SetDownstreamFilter(f.filters[i+1])
	}
	f.Evaluate(0)
	return f
}

func (n *SchedulerFilter) Tick(newClockTime int) bool {
	deltaTick := newClockTime - n.lastTick
	n.lastTick = newClockTime
	n.Evaluate(newClockTime)
	nextFilter := n.upstream
	if n.enabled && len(n.filters) > 0 {
		nextFilter = n.filters[len(n.filters)-1]
	}
	tickResult := nextFilter.Tick(newClockTime)
	if tickResult {
		return true
	}
	// return true if we're going to change state before the next tick.
	for i := newClockTime + 1; i < newClockTime+deltaTick*2; i++ {
		for _, schedule := range n.factoryConfig.Schedule {
			if enabled := schedule.Evaluate(i, n.nodeID); enabled != n.enabled {
				return true
			}
		}
	}
	return false
}

func MakeScheduleFilterFactory(config *SchedulerFilterConfig) *SchedulerFilter {
	n := &SchedulerFilter{
		factoryConfig: config,
	}
	return n
}

func (n *SchedulerFilter) Evaluate(timepoint int) {
	enabled := false
	for _, schedule := range n.factoryConfig.Schedule {
		if enabled = schedule.Evaluate(timepoint, n.nodeID); enabled {
			break
		}
	}
	if n.enabled != enabled && n.factoryConfig.DebugMessages {
		fmt.Printf("SchedulerFilter(%s) service-%v switch to %v at %v\n", n.factoryConfig.ScheduleName, n.nodeID, enabled, timepoint)
	}
	n.enabled = enabled
}

func (n *SchedulerFilterSchedule) Evaluate(timepoint int, nodeID int) bool {
	// make sure nodeId is in Nodes
	found := false
	for _, node := range n.Nodes {
		if node == nodeID {
			found = true
		}
	}
	if !found {
		return false
	}
	switch n.Operation {
	case After:
		return n.FirstTick < timepoint
	case Before:
		return n.FirstTick > timepoint
	case Between:
		return (n.FirstTick < timepoint) && (n.SecondTick > timepoint)
	case NotAfter:
		return !(n.FirstTick < timepoint)
	case NotBefore:
		return !(n.FirstTick > timepoint)
	case NotBetween:
		return !((n.FirstTick < timepoint) && (n.SecondTick > timepoint))
	default:
		return false
	}
}

// Unmarshall SchedulerFilter
func (n *SchedulerFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type schedulerFilterConfigJSON struct {
		Name         string
		Filters      []interface{}
		Schedule     []SchedulerFilterSchedule
		ScheduleName string
	}

	var jsonConfig schedulerFilterConfigJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "SchedulerFilter" {
		return nil
	}

	filters := []NetworkFilterFactory{}
	// generate a list of concrete filters
	for _, fuzzerFilterData := range jsonConfig.Filters {
		// convert the interface into a byte-stream.
		filterConfig, err := json.Marshal(fuzzerFilterData)
		if err != nil {
			return nil
		}
		var filterFactory NetworkFilterFactory
		for _, regFactory := range registeredFilterFactories {
			filterFactory = regFactory.Unmarshal(filterConfig)
			if filterFactory != nil {
				// we found a filter factory!
				break
			}
		}
		if filterFactory == nil {
			return nil
		}
		filters = append(filters, filterFactory)
	}

	sched := &SchedulerFilterConfig{
		Filters:       filters,
		Schedule:      jsonConfig.Schedule,
		ScheduleName:  jsonConfig.ScheduleName,
		DebugMessages: false,
	}
	return MakeScheduleFilterFactory(sched)
}

// register SchedulerFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &SchedulerFilter{})
}
