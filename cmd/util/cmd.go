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

package cmdutil

import (
	"fmt"
	"strings"
)

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
func (c *CobraStringValue) Type() string   { return "string" }
func (c *CobraStringValue) IsSet() bool    { return c.isSet }

// Set sets a value and fails if it is not allowed
func (c *CobraStringValue) Set(other string) error {
	for _, s := range c.allowed {
		if other == s {
			c.value = other
			c.isSet = true
			return nil
		}
	}
	return fmt.Errorf("value %s not allowed", other)
}

// AllowedString returns a comma-separated string of allowed values
func (c *CobraStringValue) AllowedString() string {
	return strings.Join(c.allowed, ", ")
}
