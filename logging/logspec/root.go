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

// Package logspec specifies the data format of event log statements.
package logspec

import (
	"encoding/json"
	"errors"
)

// Component is an enum identifying a specific type of Event
// TODO Maybe this should be called ComponentEventType (and change Event to ComponentEvent),
// since these are not actually types of components
//go:generate stringer -type=Component
type Component int

const (
	// Agreement component
	Agreement Component = iota
	// Catchup component
	Catchup
	// Network component
	Network
	// Ledger component
	Ledger
	// Frontend component
	Frontend

	numComponents // keep this last
)

// UnmarshalJSON initializes the Component from a JSON string contained in a byte buffer.
// An error is returned if a valid Component can't be parsed from the buffer.
func (c *Component) UnmarshalJSON(b []byte) error {
	var raw string
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	contextConst, ok := componentFromString(raw)
	if !ok {
		return errors.New("invalid Context field")
	}

	*c = contextConst
	return nil
}

// Event represents data corresponding to an event occurring related to a component
type Event struct {
	// Context contains the component most related to whence log messages originate.
	// It identifies the subtype corresponding to this event.
	Context Component

	// Source uniquely identifies the entity emitting the message within the log file.
	// When one node is executing, this identifier is essentially a constant.
	// During tests simulating multiple nodes, this identifier disambiguates them.
	Source string
}

func componentFromString(s string) (Component, bool) {
	for i := 0; i < int(numComponents); i++ {
		c := Component(i)
		if c.String() == s {
			return c, true
		}
	}
	return 0, false
}
