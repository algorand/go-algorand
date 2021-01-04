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
	"github.com/algorand/go-deadlock"
)

// Counter represent a single counter variable.
type Counter struct {
	// Collects value for special fast-path with no labels through Inc(nil) AddUint64(x, nil)
	// We want to make it on a 64-bit aligned address for ARM compiliers as it's being used by AddUint64
	intValue uint64

	deadlock.Mutex
	name          string
	description   string
	values        []*counterValues
	labels        map[string]int // map each label ( i.e. httpErrorCode ) to an index.
	valuesIndices map[int]int
}

type counterValues struct {
	counter         float64
	labels          map[string]string
	formattedLabels string
}
