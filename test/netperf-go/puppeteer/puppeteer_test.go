// Copyright (C) 2019-2020 Algorand, Inc.
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

package main

import (
	"testing"
)

func TestMetricsPrintout(t *testing.T) {
	// this test function was meant for local development test and not as an official unit test.
	t.Skip()
	puppets := []*puppet{
		{
			recipeName: "recipename1.json",
			metrics: map[string]float64{
				"message_count": 10.0,
				"sent_bytes":    30000,
			},
		},
		{
			recipeName: "recipename2_or_maybe_something_else.json",
			metrics: map[string]float64{
				"message_count":  13.0,
				"received_bytes": 200000,
			},
		},
		{
			recipeName: "recipename3.json",
			metrics: map[string]float64{
				"message_count":  50.0,
				"sent_bytes":     30000,
				"received_bytes": 200000,
			},
		},
	}
	printMetrics(puppets)
}
