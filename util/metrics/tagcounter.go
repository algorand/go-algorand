// Copyright (C) 2019-2024 Algorand, Inc.
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
	"maps"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/algorand/go-deadlock"
)

// NewTagCounterFiltered makes a set of metrics under rootName for tagged counting.
// "{TAG}" in rootName is replaced by the tag, otherwise "_{TAG}" is appended.
// Tags not in allowedTags will be filtered out and ignored.
// unknownTag may be "" or a value that will be counted for tags not in allowedTags.
func NewTagCounterFiltered(rootName, desc string, allowedTags []string, unknownTag string) *TagCounter {
	tc := &TagCounter{Name: rootName, Description: desc, UnknownTag: unknownTag}
	if len(allowedTags) != 0 {
		tc.AllowedTags = make(map[string]bool, len(allowedTags))
		for _, tag := range allowedTags {
			tc.AllowedTags[tag] = true
		}
	}
	DefaultRegistry().Register(tc)
	return tc
}

// NewTagCounter makes a set of metrics under rootName for tagged counting.
// "{TAG}" in rootName is replaced by the tag, otherwise "_{TAG}" is appended.
// Optionally provided declaredTags counters for these names up front (making them easier to discover).
func NewTagCounter(rootName, desc string, declaredTags ...string) *TagCounter {
	tc := &TagCounter{Name: rootName, Description: desc}
	for _, tag := range declaredTags {
		tc.Add(tag, 0)
	}
	DefaultRegistry().Register(tc)
	return tc
}

// TagCounter holds a set of counters
type TagCounter struct {
	Name        string
	Description string

	AllowedTags map[string]bool

	UnknownTag string

	// a read only race-free reference to tags
	tagptr atomic.Value

	tags map[string]*uint64

	storage    [][]uint64
	storagePos int

	tagLock deadlock.Mutex
}

// Add t[tag] += val, fast and multithread safe
func (tc *TagCounter) Add(tag string, val uint64) {
	if (tc.AllowedTags != nil) && (!tc.AllowedTags[tag]) {
		if len(tc.UnknownTag) != 0 {
			tag = tc.UnknownTag
		} else {
			return
		}
	}
	for {
		var tags map[string]*uint64
		tagptr := tc.tagptr.Load()
		if tagptr != nil {
			tags = tagptr.(map[string]*uint64)
		}

		count, ok := tags[tag]
		if ok {
			atomic.AddUint64(count, val)
			return
		}
		tc.tagLock.Lock()
		if _, ok = tc.tags[tag]; !ok {
			// Still need to add a new tag.
			// Make a new map so there's never any race.
			newtags := make(map[string]*uint64, len(tc.tags)+1)
			maps.Copy(newtags, tc.tags)
			var st []uint64
			if len(tc.storage) > 0 {
				st = tc.storage[len(tc.storage)-1]
			}
			if tc.storagePos > (len(st) - 1) {
				st = make([]uint64, 16)
				tc.storagePos = 0
				tc.storage = append(tc.storage, st)
			}
			newtags[tag] = &(st[tc.storagePos])
			tc.storagePos++
			tc.tags = newtags
			tc.tagptr.Store(newtags)
		}
		tc.tagLock.Unlock()
	}
}

// WriteMetric is part of the Metric interface
func (tc *TagCounter) WriteMetric(buf *strings.Builder, parentLabels string) {
	tagptr := tc.tagptr.Load()
	if tagptr == nil {
		// no values, nothing to say.
		return
	}
	isTemplate := strings.Contains(tc.Name, "{TAG}")
	tags := tagptr.(map[string]*uint64)
	for tag, tagcount := range tags {
		if tagcount == nil {
			continue
		}
		var name string
		if isTemplate {
			name = strings.ReplaceAll(tc.Name, "{TAG}", tag)
		} else {
			name = tc.Name + "_" + tag
		}
		buf.WriteString("# HELP ")
		buf.WriteString(name)
		buf.WriteRune(' ')
		buf.WriteString(strings.ReplaceAll(tc.Description, "{TAG}", tag))
		buf.WriteString("\n# TYPE ")
		buf.WriteString(name)
		buf.WriteString(" counter\n")
		buf.WriteString(name)
		if len(parentLabels) > 0 {
			buf.WriteRune('{')
			buf.WriteString(parentLabels)
			buf.WriteRune('}')
		}
		buf.WriteRune(' ')
		count := atomic.LoadUint64(tagcount)
		buf.WriteString(strconv.FormatUint(count, 10))
		buf.WriteRune('\n')
	}
}

// AddMetric is part of the Metric interface
// Copy the values in this TagCounter out into the string-string map.
func (tc *TagCounter) AddMetric(values map[string]float64) {
	tagp := tc.tagptr.Load()
	if tagp == nil {
		return
	}
	isTemplate := strings.Contains(tc.Name, "{TAG}")
	tags := tagp.(map[string]*uint64)
	for tag, tagcount := range tags {
		if tagcount == nil {
			continue
		}
		var name string
		if isTemplate {
			name = strings.ReplaceAll(tc.Name, "{TAG}", tag)
		} else {
			name = tc.Name + "_" + tag
		}
		count := atomic.LoadUint64(tagcount)
		values[sanitizeTelemetryName(name)] = float64(count)
	}
}
