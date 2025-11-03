// Copyright (C) 2019-2025 Algorand, Inc.
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

package cmdutil

import (
	"fmt"
	"slices"
	"strings"
)

// CobraStringValue is similar to spf13.pflag.stringValue but enforces allowed values
type CobraStringValue struct {
	value   string
	allowed []string
	isSet   bool
}

// MakeCobraStringValue creates a string value (satisfying spf13/pflag.Value interface)
// for a limited number of valid options
func MakeCobraStringValue(value string, others []string) *CobraStringValue {
	c := new(CobraStringValue)
	c.value = value
	c.allowed = make([]string, 0, len(others)+1)
	c.allowed = append(c.allowed, value)
	c.allowed = append(c.allowed, others...)
	return c
}

func (c *CobraStringValue) String() string { return c.value }

// Type returns the value type as a string
func (c *CobraStringValue) Type() string { return "string" }

// IsSet returns a boolean flag indicating of the value was changed from defaults
func (c *CobraStringValue) IsSet() bool { return c.isSet }

// Set sets a value and fails if it is not allowed
func (c *CobraStringValue) Set(other string) error {
	if slices.Contains(c.allowed, other) {
		c.value = other
		c.isSet = true
		return nil
	}
	return fmt.Errorf("value %s not allowed", other)
}

// AllowedString returns a comma-separated string of allowed values
func (c *CobraStringValue) AllowedString() string {
	return strings.Join(c.allowed, ", ")
}

// CobraStringSliceValue is similar to spf13.pflag.stringSliceValue but enforces allowed values
type CobraStringSliceValue struct {
	value      []string
	allowed    []string
	allowedMap map[string]int
	isSet      bool
}

// MakeCobraStringSliceValue creates a string slice value (satisfying spf13/pflag.Value interface)
// for a limited number of valid options
func MakeCobraStringSliceValue(value *[]string, others []string) *CobraStringSliceValue {
	c := new(CobraStringSliceValue)
	if value != nil {
		c.value = *value
	}

	// make allowed values by filtering out duplicates and preseve the order
	c.allowedMap = make(map[string]int, len(others)+len(c.value))
	var dups int
	for i, v := range append(c.value, others...) {
		if _, ok := c.allowedMap[v]; !ok {
			c.allowedMap[v] = i - dups
		} else {
			dups++
		}
	}
	c.allowed = make([]string, len(c.allowedMap))
	for v, i := range c.allowedMap {
		c.allowed[i] = v
	}
	return c
}

func (c *CobraStringSliceValue) String() string { return "[" + strings.Join(c.value, ", ") + "]" }

// Type returns the value type as a string
func (c *CobraStringSliceValue) Type() string { return "stringSlice" }

// IsSet returns a boolean flag indicating of the value was changed from defaults
func (c *CobraStringSliceValue) IsSet() bool { return c.isSet }

// Set sets a value and fails if it is not allowed
func (c *CobraStringSliceValue) Set(values string) error {
	others := strings.SplitSeq(values, ",")
	for other := range others {
		other = strings.TrimSpace(other)
		if _, ok := c.allowedMap[other]; ok {
			c.value = append(c.value, other)
			c.isSet = true
		} else {
			return fmt.Errorf("value %s not allowed", other)
		}
	}
	return nil
}

// AllowedString returns a comma-separated string of allowed values
func (c *CobraStringSliceValue) AllowedString() string {
	return strings.Join(c.allowed, ", ")
}

// GetSlice returns a current value as a string slice
func (c *CobraStringSliceValue) GetSlice() []string {
	return c.value
}
