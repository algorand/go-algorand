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
	"strings"
)

// MakeStringGauge create a new StringGauge.
func MakeStringGauge() *StringGauge {
	c := &StringGauge{
		values: make(map[string]string),
	}
	c.Register(nil)
	return c
}

// Register registers the StringGauge with the default/specific registry
func (stringGauge *StringGauge) Register(reg *Registry) {
	if reg == nil {
		DefaultRegistry().Register(stringGauge)
	} else {
		reg.Register(stringGauge)
	}
}

// Deregister deregisters the StringGauge with the default/specific registry
func (stringGauge *StringGauge) Deregister(reg *Registry) {
	if reg == nil {
		DefaultRegistry().Deregister(stringGauge)
	} else {
		reg.Deregister(stringGauge)
	}
}

// Set updates a key with a value.
func (stringGauge *StringGauge) Set(key string, value string) {
	stringGauge.values[key] = value
}

// WriteMetric omit string gauges from the metrics report, not sure how they act with prometheus
func (stringGauge *StringGauge) WriteMetric(buf *strings.Builder, parentLabels string) {
}

// AddMetric sets all the key value pairs in the provided map.
func (stringGauge *StringGauge) AddMetric(values map[string]string) {
	for k, v := range stringGauge.values {
		values[k] = v
	}
}
