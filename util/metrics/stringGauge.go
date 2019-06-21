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
