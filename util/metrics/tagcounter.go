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
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/algorand/go-deadlock"
)

// NewTagCounter makes a set of metrics under rootName for tagged counting.
// "{TAG}" in rootName is replaced by the tag, otherwise "_{TAG}" is appended.
func NewTagCounter(rootName, desc string) *TagCounter {
	tc := &TagCounter{Name: rootName, Description: desc}
	DefaultRegistry().Register(tc)
	return tc
}

// TagCounter holds a set of counters
type TagCounter struct {
	Name        string
	Description string

	// a read only race-free reference to tags
	tagptr atomic.Value

	tags map[string]*uint64

	storage    [][]uint64
	storagePos int

	tagLock deadlock.Mutex
}

// Add t[tag] += val, fast and multithread safe
func (tc *TagCounter) Add(tag string, val uint64) {
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
			for k, v := range tc.tags {
				newtags[k] = v
			}
			var st []uint64
			if len(tc.storage) > 0 {
				st = tc.storage[len(tc.storage)-1]
				//fmt.Printf("new tag %v, old block\n", tag)
			}
			if tc.storagePos > (len(st) - 1) {
				//fmt.Printf("new tag %v, new block\n", tag)
				st = make([]uint64, 16)
				tc.storagePos = 0
				tc.storage = append(tc.storage, st)
			}
			newtags[tag] = &(st[tc.storagePos])
			//fmt.Printf("tag %v = %p\n", tag, newtags[tag])
			tc.storagePos++
			tc.tags = newtags
			tc.tagptr.Store(newtags)
		}
		tc.tagLock.Unlock()
	}
}

// WriteMetric is part of the Metric interface
func (tc *TagCounter) WriteMetric(buf *strings.Builder, parentLabels string) {
	// TODO: what to do with "parentLabels"? obsolete part of interface?
	buf.WriteString("# ")
	buf.WriteString(tc.Name)
	buf.WriteString(" ")
	buf.WriteString(tc.Description)
	buf.WriteString("\n")
	isTemplate := strings.Contains(tc.Name, "{TAG}")
	tags := tc.tagptr.Load().(map[string]*uint64)
	for tag, tagcount := range tags {
		if tagcount == nil {
			continue
		}
		if isTemplate {
			name := strings.ReplaceAll(tc.Name, "{TAG}", tag)
			buf.WriteString(name)
			buf.WriteRune(' ')
			buf.WriteString(strconv.FormatUint(*tagcount, 10))
			buf.WriteRune('\n')
		} else {
			buf.WriteString(tc.Name)
			buf.WriteRune('_')
			buf.WriteString(tag)
			buf.WriteRune(' ')
			buf.WriteString(strconv.FormatUint(*tagcount, 10))
			buf.WriteRune('\n')
		}
	}
}

// AddMetric is part of the Metric interface
// Copy the values in this TagCounter out into the string-string map.
func (tc *TagCounter) AddMetric(values map[string]string) {
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
		values[name] = strconv.FormatUint(*tagcount, 10)
	}
}
